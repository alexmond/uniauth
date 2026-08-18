package org.alexmond.uniauth.autoconfigure;

import org.alexmond.uniauth.approval.ApprovalAuthoritiesFilter;
import org.alexmond.uniauth.approval.ApprovalAuthorizationManager;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.InMemoryApprovalStore;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.MechanismResolver;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
class ApprovalConfiguration {

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
			UniAuthProperties properties) {
		return new ApprovalAuthorizationManager(store, resolver, properties);
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
