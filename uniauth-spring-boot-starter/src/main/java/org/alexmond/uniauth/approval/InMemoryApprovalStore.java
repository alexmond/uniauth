package org.alexmond.uniauth.approval;

import org.alexmond.uniauth.provider.AuthProviderType;

import java.time.Clock;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The default {@link ApprovalStore}: a map, and nothing else.
 *
 * <p>
 * Good enough for the sample app, for tests, and for a single-instance deployment that
 * can live with re-approving everyone after a restart. It is not good enough for anything
 * else, and the two reasons are worth stating plainly: state is lost on restart, and
 * nothing is shared between instances, so behind a load balancer a user's standing
 * depends on which node they land on.
 */
public class InMemoryApprovalStore implements ApprovalStore {

	private final Map<ApprovalKey, ApprovalRecord> records = new ConcurrentHashMap<>();

	private final Clock clock;

	public InMemoryApprovalStore() {
		this(Clock.systemUTC());
	}

	public InMemoryApprovalStore(Clock clock) {
		this.clock = clock;
	}

	@Override
	public ApprovalStatus statusOf(ApprovalKey key) {
		ApprovalRecord record = this.records.get(key);
		return (record != null) ? record.status() : ApprovalStatus.UNKNOWN;
	}

	@Override
	public ApprovalRecord recordPending(ApprovalKey key, AuthProviderType mechanism) {
		// computeIfAbsent keeps this idempotent: it runs on every request from an
		// unapproved principal, and must never reset a decision already taken.
		return this.records.computeIfAbsent(key, (absent) -> new ApprovalRecord(absent, mechanism,
				ApprovalStatus.PENDING, this.clock.instant(), null, null));
	}

	@Override
	public List<ApprovalRecord> pending() {
		return this.records.values()
			.stream()
			.filter((record) -> record.status() == ApprovalStatus.PENDING)
			.sorted(Comparator.comparing(ApprovalRecord::firstSeen))
			.toList();
	}

	@Override
	public Optional<ApprovalRecord> find(ApprovalKey key) {
		return Optional.ofNullable(this.records.get(key));
	}

	@Override
	public void decide(ApprovalKey key, ApprovalStatus outcome, String approver) {
		if (outcome != ApprovalStatus.APPROVED && outcome != ApprovalStatus.DENIED) {
			throw new IllegalArgumentException("A decision must be APPROVED or DENIED, not " + outcome);
		}
		this.records.computeIfPresent(key, (unused, record) -> record.decide(outcome, approver, this.clock.instant()));
	}

	@Override
	public void remove(ApprovalKey key) {
		this.records.remove(key);
	}

}
