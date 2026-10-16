package org.alexmond.uniauth.examples.web;

import java.util.List;

import org.alexmond.uniauth.approval.ApprovalRecord;

/**
 * One row of the access list — somebody who already has a decision against their name.
 *
 * <p>
 * The queue row and this one are not the same shape, which is why they are not the same
 * record. A waiting row carries a form for making a decision; this one carries the
 * decision that was made: what the approver granted, who they were, and when. Those three
 * are the whole point of an access review, and none of them exist yet while a principal
 * is pending.
 *
 * <p>
 * It composes {@link PendingView} rather than repeating it, because recognising a person
 * is the same problem on both tables: a name, an address, whether the provider stands
 * behind that address, and the subject underneath that approval is really keyed on.
 *
 * @param who the principal, formatted for recognition
 * @param roles what the approver granted, empty when they granted nothing
 * @param decidedBy who decided
 * @param decidedAt when, to the minute
 */
public record AccessView(PendingView who, List<String> roles, String decidedBy, String decidedAt) {

	public static AccessView of(ApprovalRecord record) {
		return new AccessView(PendingView.of(record), record.roles(), record.decidedBy(),
				(record.decidedAt() != null) ? PendingView.stamp(record.decidedAt()) : null);
	}

}
