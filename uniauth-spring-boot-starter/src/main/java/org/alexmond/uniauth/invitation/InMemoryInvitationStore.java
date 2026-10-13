package org.alexmond.uniauth.invitation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.alexmond.uniauth.approval.ApprovalKey;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * The default {@link InvitationStore}: a map, and nothing else.
 *
 * <p>
 * Supplied so the flow works out of the box and in tests, and <strong>not
 * production-fit</strong>, for the same two reasons {@code InMemoryApprovalStore} is not:
 * invitations are lost on restart, and nothing is shared between instances, so behind a
 * load balancer an invitation exists only on the node that minted it. A console pointed
 * at an in-memory store likewise sees only the invitations created in its own process.
 *
 * <p>
 * Durability is the deployment's choice, so the starter warns about this rather than
 * refusing to start — see {@code InvitationConfiguration}.
 */
public class InMemoryInvitationStore implements InvitationStore {

	private final Map<InvitationToken, Invitation> invitations = new ConcurrentHashMap<>();

	private final Clock clock;

	private final Duration defaultExpiry;

	/** Uses the system UTC clock and a fourteen-day default expiry. */
	public InMemoryInvitationStore() {
		this(Clock.systemUTC(), Duration.ofDays(14));
	}

	/**
	 * Creates a store reading time from the given clock.
	 * @param clock source of the created, used and revoked timestamps; injectable so a
	 * test can assert on expiry boundaries without sleeping
	 * @param defaultExpiry used when {@code create} is given no ttl
	 */
	public InMemoryInvitationStore(Clock clock, Duration defaultExpiry) {
		this.clock = clock;
		this.defaultExpiry = defaultExpiry;
	}

	@Override
	public Invitation create(String subjectRef, Duration ttl, List<String> roles, String createdBy) {
		Assert.hasText(subjectRef, "An invitation must name a subjectRef");
		Assert.isTrue(ttl == null || (!ttl.isZero() && !ttl.isNegative()),
				"An invitation's ttl must be positive, not " + ttl);
		Instant now = this.clock.instant();
		Duration effective = (ttl != null) ? ttl : this.defaultExpiry;
		Invitation invitation = new Invitation(InvitationToken.generate(), subjectRef.trim(), clean(roles), now,
				createdBy, (effective != null) ? now.plus(effective) : null, null, null, null);
		this.invitations.put(invitation.token(), invitation);
		return invitation;
	}

	@Override
	public Optional<Invitation> find(InvitationToken token) {
		return Optional.ofNullable(this.invitations.get(token));
	}

	@Override
	public Invitation redeem(InvitationToken token, ApprovalKey admitted) {
		Instant now = this.clock.instant();
		AtomicReference<Invitation> granted = new AtomicReference<>();
		// compute, not get-then-put: the claim has to be a compare-and-set or two
		// simultaneous logins both take Jane. Success is recorded in `granted` rather
		// than inferred from what compute returns, because an invitation this principal
		// already holds is returned unchanged whether or not they may still use it.
		this.invitations.compute(token, (unused, existing) -> {
			if (existing == null) {
				return null;
			}
			if (existing.revokedAt() != null) {
				// Ahead of the same-principal no-op below, and the order is the whole
				// point. Revocation is the one refusal somebody chose deliberately, and
				// the retry window it has to override can span an outage — which is
				// exactly when it gets used. With the no-op first, revoking inside that
				// window did nothing at all: the next request re-claimed and was let in.
				return existing;
			}
			if (admitted.equals(existing.usedBy())) {
				// Same principal claiming again: a no-op, so a failed listener can be
				// retried instead of stranding the invited person. Expiry does not
				// interfere, because USED outranks EXPIRED in the status precedence.
				granted.set(existing);
				return existing;
			}
			if (existing.status(now) != InvitationStatus.OPEN) {
				return existing;
			}
			Invitation claim = new Invitation(existing.token(), existing.subjectRef(), existing.roles(),
					existing.createdAt(), existing.createdBy(), existing.expiresAt(), now, admitted,
					existing.revokedAt());
			granted.set(claim);
			return claim;
		});
		Invitation claimed = granted.get();
		if (claimed == null) {
			throw new InvitationNotRedeemableException("The invitation is not open to this principal");
		}
		return claimed;
	}

	@Override
	public void revoke(InvitationToken token, String revokedBy) {
		Instant now = this.clock.instant();
		this.invitations.computeIfPresent(token,
				(unused, existing) -> (existing.revokedAt() != null) ? existing
						: new Invitation(existing.token(), existing.subjectRef(), existing.roles(),
								existing.createdAt(), existing.createdBy(), existing.expiresAt(), existing.usedAt(),
								existing.usedBy(), now));
	}

	@Override
	public List<Invitation> list(InvitationStatus... statuses) {
		Instant now = this.clock.instant();
		Set<InvitationStatus> wanted = (statuses.length > 0) ? Set.copyOf(Arrays.asList(statuses))
				: Set.of(InvitationStatus.values());
		return this.invitations.values()
			.stream()
			.filter((invitation) -> wanted.contains(invitation.status(now)))
			.sorted(Comparator.comparing(Invitation::createdAt).reversed())
			.toList();
	}

	/**
	 * Adopts an invitation minted elsewhere. Exists for tests that need a store reading a
	 * different clock over the same contents.
	 * @param invitation the invitation to take in
	 */
	void put(Invitation invitation) {
		this.invitations.put(invitation.token(), invitation);
	}

	/**
	 * Drops null and blank roles and trims the rest.
	 *
	 * <p>
	 * They would otherwise reach {@code ApprovalAuthoritiesFilter}, which prefixes
	 * whatever it is handed: {@code ROLE_null} would be granted and then match nothing,
	 * which reads as a broken application rather than a bad invitation.
	 */
	private static List<String> clean(List<String> roles) {
		if (roles == null) {
			return List.of();
		}
		return roles.stream().filter(StringUtils::hasText).map(String::trim).distinct().toList();
	}

}
