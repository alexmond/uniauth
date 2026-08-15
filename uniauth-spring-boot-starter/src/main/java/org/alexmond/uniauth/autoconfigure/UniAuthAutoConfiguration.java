package org.alexmond.uniauth.autoconfigure;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.web.UniAuthLoginController;
import org.alexmond.uniauth.web.UniAuthProvidersController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

/**
 * Wires every enabled mechanism into a <em>single</em> {@link SecurityFilterChain}.
 *
 * <p>
 * This is the heart of the "universal" claim, and the part worth understanding before
 * changing anything here. Rather than one chain per mechanism — which would mean the
 * first matching chain wins and the others never run — there is one chain that has form
 * login, OAuth2 login and SAML login all installed on it. The form-based mechanisms
 * (internal, LDAP) are distinguished not by URL but by the {@code AuthenticationProvider}
 * chain: every provider bean is registered, and Spring Security tries each until one
 * authenticates the submitted credentials.
 *
 * <p>
 * Redirect-based mechanisms keep their own entry-point URLs, which is why the chooser
 * page only needs to render a link per registration.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(SecurityFilterChain.class)
@ConditionalOnProperty(prefix = "uniauth", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(UniAuthProperties.class)
@Import({ InternalAuthConfiguration.class, LdapAuthConfiguration.class, Oauth2AdaptersConfiguration.class })
public class UniAuthAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public AuthProviderRegistry uniAuthProviderRegistry(UniAuthProperties properties,
			ObjectProvider<ClientRegistrationRepository> clientRegistrations,
			ObjectProvider<RelyingPartyRegistrationRepository> relyingParties) {
		return new AuthProviderRegistry(properties, clientRegistrations, relyingParties);
	}

	@Bean
	@ConditionalOnMissingBean
	public UniAuthLoginController uniAuthLoginController(AuthProviderRegistry registry, UniAuthProperties properties) {
		return new UniAuthLoginController(registry, properties);
	}

	@Bean
	@ConditionalOnMissingBean
	public UniAuthProvidersController uniAuthProvidersController(AuthProviderRegistry registry) {
		return new UniAuthProvidersController(registry);
	}

	@Bean
	@ConditionalOnMissingBean(SecurityFilterChain.class)
	public SecurityFilterChain uniAuthSecurityFilterChain(HttpSecurity http, UniAuthProperties properties,
			AuthProviderRegistry registry, ObjectProvider<AuthenticationProvider> authenticationProviders,
			ObjectProvider<ClientRegistrationRepository> clientRegistrations,
			ObjectProvider<RelyingPartyRegistrationRepository> relyingParties) throws Exception {

		List<String> permitted = new ArrayList<>(
				List.of(properties.getLoginPage(), properties.getProvidersEndpoint(), "/error"));
		permitted.addAll(properties.getPublicPaths());

		http.authorizeHttpRequests((requests) -> requests.requestMatchers(permitted.toArray(String[]::new))
			.permitAll()
			.anyRequest()
			.authenticated());

		// Internal and LDAP both land here; order of the provider beans decides who is
		// asked first.
		authenticationProviders.orderedStream().forEach(http::authenticationProvider);

		if (registry.hasFormProvider()) {
			http.formLogin((form) -> form.loginPage(properties.getLoginPage())
				.defaultSuccessUrl(properties.getDefaultSuccessUrl(), true)
				.permitAll());
		}

		if (properties.getOauth2().isEnabled() && clientRegistrations.getIfAvailable() != null) {
			http.oauth2Login((oauth2) -> oauth2.loginPage(properties.getLoginPage())
				.defaultSuccessUrl(properties.getDefaultSuccessUrl(), true));
		}

		if (properties.getSaml().isEnabled() && relyingParties.getIfAvailable() != null) {
			http.saml2Login((saml2) -> saml2.loginPage(properties.getLoginPage())
				.defaultSuccessUrl(properties.getDefaultSuccessUrl(), true));
			http.saml2Logout((withDefaults) -> {
			});
		}

		http.logout((logout) -> logout.logoutSuccessUrl(properties.getLogoutSuccessUrl()).permitAll());

		return http.build();
	}

}
