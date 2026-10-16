package org.alexmond.uniauth.approval;

import org.alexmond.uniauth.provider.AuthProviderType;

import java.util.List;
import java.util.Optional;

/**
 * Where approval decisions live.
 *
 * <p>
 * This is an SPI, and deliberately the only stateful thing in UniAuth. The library ships
 * {@link InMemoryApprovalStore} so the flow works out of the box and in tests, but that
 * store forgets everything on restart — which means every approved user goes back to
 * pending. Any real deployment supplies its own implementation backed by whatever
 * database it already has.
 *
 * <p>
 * Keeping persistence behind this interface is what stops the starter from dragging
 * Spring Data, a schema and a migration story onto every application that only wanted a
 * login page.
 *
 * <p>
 * Implementations must be safe for concurrent use.
 */
public interface ApprovalStore {

	/**
	 * Where this principal stands. Returns {@link ApprovalStatus#UNKNOWN} for anyone
	 * never seen before.
	 * @param key the principal being asked about
	 * @return their current standing, never {@code null}
	 */
	ApprovalStatus statusOf(ApprovalKey key);

	/**
	 * Records a first sighting as pending, and does nothing if the principal is already
	 * known. Called on the first authenticated request, so it must be idempotent and
	 * cheap.
	 * @param key the principal being recorded
	 * @param identity who that is in terms a person can judge, captured now because the
	 * queue is read later, by somebody else, when this session may be long gone
	 * @param mechanism which mechanism vouched for them, so a reviewer can tell a
	 * directory account from a stranger with a Google login
	 * @return the record as it now stands — the existing one if already known
	 */
	ApprovalRecord recordPending(ApprovalKey key, PrincipalIdentity identity, AuthProviderType mechanism);

	/**
	 * Every record the store holds whose standing is one of those asked for, oldest
	 * first.
	 *
	 * <p>
	 * <strong>This is the one method that has ever been added to this interface, and
	 * adding it broke every implementation.</strong> It is abstract rather than a
	 * {@code default} because there is nothing honest to default to: the store is the
	 * only thing that can enumerate itself, so a default could return empty — reporting
	 * "nobody has access" to an access-review screen — or throw, which moves a compile
	 * error to a page load. See the migration note in the reference documentation.
	 *
	 * <p>
	 * Why it exists: {@link #pending} answers "who wants in" and by definition excludes
	 * everybody already admitted, and {@link #find} needs a key you already hold — which
	 * for an OIDC login is an opaque subject claim nobody has memorised. So through the
	 * interface alone an application could build a queue but never an access list: no way
	 * to see who can sign in today, what roles they hold, or who was refused, and no way
	 * to pick somebody to revoke. The only route was to query the backing table directly,
	 * which couples the page to one implementation and leaves a non-SQL store unable to
	 * offer the same screen at all (#10).
	 *
	 * <p>
	 * Passing no statuses means every record. {@link ApprovalStatus#UNKNOWN} matches
	 * nothing, ever: it is the absence of a record rather than a value one can be stored
	 * with, so a store must not treat it as a wildcard — an access list asking for the
	 * unknown would otherwise be handed everybody.
	 *
	 * <p>
	 * The ordering is by {@link ApprovalRecord#firstSeen()} ascending, for the whole
	 * interface and not only for the queue, because {@code pending()} is published API
	 * that already promised oldest-first and now reads through here.
	 * @param statuses the standings wanted, or none at all for everything
	 * @return the matching records, oldest first, empty when none match
	 */
	List<ApprovalRecord> list(ApprovalStatus... statuses);

	/**
	 * Everyone currently waiting, oldest first.
	 *
	 * <p>
	 * A {@code default} over {@link #list} since the enumeration landed, so it is no
	 * longer a method an implementation has to write. An implementation that already
	 * overrides it keeps working and keeps winning — that is deliberate, because a store
	 * whose table is indexed for the queue should go on using that index.
	 * @return the pending records, empty when nobody is waiting
	 */
	default List<ApprovalRecord> pending() {
		return list(ApprovalStatus.PENDING);
	}

	/**
	 * One principal's record, whatever their standing.
	 * @param key the principal being looked up
	 * @return their record, or empty if never seen
	 */
	Optional<ApprovalRecord> find(ApprovalKey key);

	/**
	 * Settles a principal's standing.
	 *
	 * <p>
	 * <strong>A key this store has never recorded is left alone.</strong> Implementations
	 * must not create a record here, and the interface says so because it previously did
	 * not: an implementor could not tell which behaviour was required, and the two
	 * answers are not interchangeable to a caller (#35). Creating one would invent a
	 * decision about somebody nobody has ever seen, with no identity and no mechanism to
	 * show whoever reads the queue afterwards — a row an approver cannot make sense of.
	 *
	 * <p>
	 * Which makes pre-approval a recipe rather than a special case: call
	 * {@link #recordPending} with whatever is known about the principal, then decide it.
	 * That is how somebody is admitted before their first login — the documented route
	 * for the first administrator under {@code uniauth.approval.invitations.invite-only}.
	 * @param key who is being decided about; unknown here means nothing happens
	 * @param outcome {@link ApprovalStatus#APPROVED} or {@link ApprovalStatus#DENIED}
	 * @param approver name of whoever decided, for the audit trail
	 * @param roles what the approver granted. An approver looking at "Jane Smith,
	 * verified, via Google" is deciding what she may do, not merely whether she exists —
	 * and a federated principal has no roles of its own, so this is the only place they
	 * can come from
	 */
	void decide(ApprovalKey key, ApprovalStatus outcome, String approver, List<String> roles);

	/**
	 * Forgets a principal entirely, so they read as {@link ApprovalStatus#UNKNOWN} again.
	 *
	 * <p>
	 * This is how access is revoked: the next request re-records them as pending, which
	 * puts a previously approved user back in the waiting room rather than locking them
	 * out with no route back. It also covers tidying up after someone leaves.
	 * @param key the principal to forget; forgetting an unknown one is not an error
	 */
	void remove(ApprovalKey key);

}
