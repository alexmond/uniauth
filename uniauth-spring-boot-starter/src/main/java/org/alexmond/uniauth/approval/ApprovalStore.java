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
	 */
	ApprovalStatus statusOf(ApprovalKey key);

	/**
	 * Records a first sighting as pending, and does nothing if the principal is already
	 * known. Called on the first authenticated request, so it must be idempotent and
	 * cheap.
	 * @return the record as it now stands
	 */
	ApprovalRecord recordPending(ApprovalKey key, AuthProviderType mechanism);

	/** Everyone currently waiting, oldest first. */
	List<ApprovalRecord> pending();

	/** One principal's record, empty if never seen. */
	Optional<ApprovalRecord> find(ApprovalKey key);

	/**
	 * Settles a principal's standing.
	 * @param key who is being decided about
	 * @param outcome {@link ApprovalStatus#APPROVED} or {@link ApprovalStatus#DENIED}
	 * @param approver name of whoever decided, for the audit trail
	 */
	void decide(ApprovalKey key, ApprovalStatus outcome, String approver);

	/**
	 * Forgets a principal entirely, so they read as {@link ApprovalStatus#UNKNOWN} again.
	 *
	 * <p>
	 * This is how access is revoked: the next request re-records them as pending, which
	 * puts a previously approved user back in the waiting room rather than locking them
	 * out with no route back. It also covers tidying up after someone leaves.
	 */
	void remove(ApprovalKey key);

}
