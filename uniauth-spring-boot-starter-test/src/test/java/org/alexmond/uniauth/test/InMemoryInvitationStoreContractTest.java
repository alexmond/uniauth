package org.alexmond.uniauth.test;

import java.time.Clock;
import java.time.Duration;

import org.alexmond.uniauth.invitation.InMemoryInvitationStore;
import org.alexmond.uniauth.invitation.InvitationStore;

/**
 * The shipped default, run against the contract it defines.
 *
 * <p>
 * Two jobs in one file. It proves {@code InMemoryInvitationStore} honours the rules — it
 * is the implementation every consumer meets first, so a divergence here would be the
 * behaviour they learn — and it proves the contract itself is satisfiable by a real store
 * rather than describing a store nobody can write.
 */
class InMemoryInvitationStoreContractTest extends InvitationStoreContract {

	@Override
	protected InvitationStore createStore(Clock clock) {
		return new InMemoryInvitationStore(clock, Duration.ofDays(14));
	}

}
