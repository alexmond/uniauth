package org.alexmond.uniauth.autoconfigure;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.RedirectMechanism;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

/**
 * Contributes whichever redirect-based mechanisms are on the classpath.
 *
 * <p>
 * Both are optional dependencies, so each lives behind its own
 * {@code @ConditionalOnClass} in a nested configuration. Spring evaluates that condition
 * from the class file's metadata without loading the class, which is what makes it safe
 * for these configurations to name types that may be absent — and why nothing outside
 * them may.
 *
 * <p>
 * For SAML the saving is more than a jar: OpenSAML is not published to Maven Central, so
 * a mandatory dependency forced every consumer to declare the Shibboleth repository for a
 * mechanism most of them never enable.
 */
@Configuration(proxyBeanMethods = false)
class RedirectMechanismConfiguration {

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnClass(ClientRegistrationRepository.class)
	static class Oauth2 {

		@Bean
		@ConditionalOnMissingBean(name = "uniAuthOauth2Mechanism")
		RedirectMechanism uniAuthOauth2Mechanism(UniAuthProperties properties,
				ObjectProvider<ClientRegistrationRepository> clientRegistrations) {
			return new Oauth2Mechanism(properties, clientRegistrations);
		}

	}

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnClass(RelyingPartyRegistrationRepository.class)
	static class Saml {

		@Bean
		@ConditionalOnMissingBean(name = "uniAuthSamlMechanism")
		RedirectMechanism uniAuthSamlMechanism(UniAuthProperties properties,
				ObjectProvider<RelyingPartyRegistrationRepository> relyingParties) {
			return new SamlMechanism(properties, relyingParties);
		}

	}

}
