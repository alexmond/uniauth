package org.alexmond.uniauth.test;

import java.time.Clock;

import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.InMemoryApprovalStore;

/**
 * The shipped default, run against the contract it defines.
 *
 * <p>
 * {@code InMemoryApprovalStore} is not production-fit and says so at startup, but it is
 * still the reference behaviour: a deployment replacing it is expected to behave the same
 * way, so what it does has to be what the contract says.
 */
class InMemoryApprovalStoreContractTest extends ApprovalStoreContract {

	@Override
	protected ApprovalStore createStore(Clock clock) {
		return new InMemoryApprovalStore(clock);
	}

}
