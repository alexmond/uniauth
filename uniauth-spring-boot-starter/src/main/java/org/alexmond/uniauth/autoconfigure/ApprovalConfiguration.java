package org.alexmond.uniauth.autoconfigure;

import java.util.Map;

import org.alexmond.uniauth.approval.ApprovalAuthoritiesFilter;
import org.alexmond.uniauth.approval.ApprovalAuthorizationManager;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.InMemoryApprovalStore;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.InvitationRedemption;
import org.alexmond.uniauth.provider.MechanismResolver;
import org.alexmond.uniauth.web.UniAuthPendingPageController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;

/**
 * Wires the approval gate, and only when asked for.
 *
 * <p>
 * The whole configuration is conditional, which is what lets
 * {@code UniAuthAutoConfiguration} decide between {@code .authenticated()} and the
 * approval manager by looking for the bean: absent means the feature is off, and the
 * chain is exactly what it was before.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "uniauth.approval", name = "enabled", havingValue = "true")
@Import(InvitationConfiguration.class)
class ApprovalConfiguration {

	/**
	 * Serves the waiting page the gate redirects to.
	 *
	 * <p>
	 * Registered as a handler mapping rather than a {@code @Controller} on purpose, and
	 * at an order behind {@code RequestMappingHandlerMapping}, so an application that
	 * already maps the pending page — which is what the absence of this page made them do
	 * (#11) — keeps serving its own and never sees an ambiguous mapping. The order also
	 * sits behind {@code addViewControllers}, whose registry uses 1, so a view controller
	 * of their own wins too.
	 * @param properties the configured pending page, and the view to render on it
	 * @return the mapping
	 */
	@Bean
	@ConditionalOnMissingBean(name = "uniAuthPendingPageMapping")
	SimpleUrlHandlerMapping uniAuthPendingPageMapping(UniAuthProperties properties) {
		UniAuthPendingPageController waitingRoom = new UniAuthPendingPageController();
		waitingRoom.setViewName(properties.getApproval().getPendingView());
		SimpleUrlHandlerMapping mapping = new SimpleUrlHandlerMapping();
		mapping.setOrder(2);
		mapping.setUrlMap(Map.of(properties.getApproval().getPendingPage(), waitingRoom));
		return mapping;
	}

	/**
	 * Forgets everything on restart, so replace it in any deployment that cares. See
	 * {@link InMemoryApprovalStore} for why it is still the default.
	 */
	@Bean
	@ConditionalOnMissingBean
	ApprovalStore uniAuthApprovalStore() {
		return new InMemoryApprovalStore();
	}

	@Bean
	@ConditionalOnMissingBean
	ApprovalAuthorizationManager uniAuthApprovalAuthorizationManager(ApprovalStore store, MechanismResolver resolver,
			UniAuthProperties properties, ObjectProvider<InvitationRedemption> redemption) {
		// Absent unless invitations are on, in which case the gate is exactly what it was
		// before they existed.
		return new ApprovalAuthorizationManager(store, resolver, properties, redemption.getIfAvailable());
	}

	/**
	 * Grants what the approver decided, on the request after the decision.
	 *
	 * <p>
	 * Separate from the authorization manager because they answer different questions:
	 * the manager decides whether to let the request through at all, this decides what
	 * the principal may then do.
	 */
	@Bean
	@ConditionalOnMissingBean
	ApprovalAuthoritiesFilter uniAuthApprovalAuthoritiesFilter(ApprovalStore store, MechanismResolver resolver,
			UniAuthProperties properties) {
		return new ApprovalAuthoritiesFilter(store, resolver, properties);
	}

}
