package org.alexmond.uniauth.autoconfigure;

import java.time.Clock;

import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.InMemoryInvitationStore;
import org.alexmond.uniauth.invitation.InvitationRedemption;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.web.UniAuthInvitationController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires invitations, and only when asked.
 *
 * <p>
 * Imported from {@code ApprovalConfiguration} rather than from the auto-configuration
 * directly, which makes the dependency structural: redemption writes an approval record,
 * so invitations without the gate would have nowhere to put their decision. Setting
 * {@code invitations.enabled} without {@code approval.enabled} therefore wires nothing,
 * in the same way a mechanism with no registration installs no login.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "uniauth.approval.invitations", name = "enabled", havingValue = "true")
class InvitationConfiguration {

	private static final Logger LOGGER = LoggerFactory.getLogger(InvitationConfiguration.class);

	/**
	 * Fails the context on a path that could never work, rather than leaving every
	 * invitation to 404 with nothing anywhere saying why.
	 * @param properties the bound configuration
	 */
	InvitationConfiguration(UniAuthProperties properties) {
		properties.getApproval().getInvitations().validate();
	}

	/**
	 * Forgets everything on restart, so replace it in any deployment that cares.
	 *
	 * <p>
	 * It warns rather than refuses. Durability is the deployment's choice — the same
	 * bargain {@code InMemoryApprovalStore} strikes — but it has to be said out loud,
	 * because the failure is quiet: a console pointed at an in-memory store sees only the
	 * invitations created in its own process, which reads as a broken console rather than
	 * as the limitation it is.
	 * @param properties supplies the default expiry
	 * @return the in-memory store
	 */
	@Bean
	@ConditionalOnMissingBean
	InvitationStore uniAuthInvitationStore(UniAuthProperties properties) {
		LOGGER.warn("UniAuth is using InMemoryInvitationStore: invitations are lost on restart, "
				+ "are not shared between instances, and an admin console pointed at this store sees only "
				+ "the invitations created in its own process. Supply your own InvitationStore bean for anything "
				+ "beyond a demo.");
		return new InMemoryInvitationStore(Clock.systemUTC(),
				properties.getApproval().getInvitations().getDefaultExpiry());
	}

	@Bean
	@ConditionalOnMissingBean
	InvitationRedemption uniAuthInvitationRedemption(InvitationStore invitations, ApprovalStore approvals,
			ApplicationEventPublisher events, UniAuthProperties properties) {
		return new InvitationRedemption(invitations, approvals, events, properties);
	}

	/**
	 * Registered as a bean rather than component-scanned, like every other controller
	 * here, so {@code uniauth.enabled=false} genuinely backs off.
	 * @param store where invitations are looked up
	 * @param properties supplies the chooser and success paths
	 * @return the controller
	 */
	@Bean
	@ConditionalOnMissingBean
	UniAuthInvitationController uniAuthInvitationController(InvitationStore store, UniAuthProperties properties) {
		return new UniAuthInvitationController(store, properties, Clock.systemUTC());
	}

}
