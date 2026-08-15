package org.alexmond.uniauth.examples.oauth;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * A local OAuth2 / OpenID Connect provider, so the OAUTH2 mechanism can be demonstrated
 * without a Google project or an Entra tenant.
 *
 * <p>
 * The demo is both the authorization server and one of its clients. That is unusual, and
 * the reason it works is the {@link #oauthServerSecurityContextRepository() separate
 * security-context repository} these two chains use. With the default repository both
 * sides would share one session entry, and each would see the other's login: signing in
 * to the app would silently authorize the OAuth flow with no prompt, and signing in at
 * the provider would leave you authenticated to the app as a plain form user. Giving the
 * provider its own session key keeps the two logins genuinely independent — which is what
 * you get in reality, where they are different servers.
 *
 * <p>
 * Chain order matters. Both chains below match narrow paths and run ahead of the
 * starter's catch-all, which is why {@code UniAuthAutoConfiguration} conditions its chain
 * on a bean name rather than backing off whenever any other chain exists.
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

	/** Where the provider sends an unauthenticated user to prove who they are. */
	static final String LOGIN_PAGE = "/oauth-provider/login";

	/**
	 * Session key for the provider's own login, kept apart from the application's. See
	 * the class javadoc — this one line is what makes co-hosting honest.
	 */
	@Bean
	SecurityContextRepository oauthServerSecurityContextRepository() {
		HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository();
		repository.setSpringSecurityContextKey("UNIAUTH_OAUTH_PROVIDER_CONTEXT");
		return repository;
	}

	/**
	 * The provider's protocol endpoints — authorize, token, jwks, userinfo, discovery.
	 * Replaces the chain Spring Boot would auto-configure under this bean name, only to
	 * redirect to the provider's own login page instead of the application's.
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	@ConditionalOnMissingBean(name = "authorizationServerSecurityFilterChain")
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			SecurityContextRepository oauthServerSecurityContextRepository) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();

		http.securityMatcher(authorizationServer.getEndpointsMatcher())
			.with(authorizationServer, (server) -> server.oidc(Customizer.withDefaults()))
			.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated())
			.securityContext((context) -> context.securityContextRepository(oauthServerSecurityContextRepository))
			.csrf((csrf) -> csrf.ignoringRequestMatchers(authorizationServer.getEndpointsMatcher()))
			.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(LOGIN_PAGE)));

		return http.build();
	}

	/**
	 * The provider's login page and form. Authenticates against {@link OAuthUserStore}
	 * and nothing else, so an account at the provider is not an account in the
	 * application.
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	SecurityFilterChain oauthProviderLoginSecurityFilterChain(HttpSecurity http, OAuthUserStore store,
			PasswordEncoder passwordEncoder, SecurityContextRepository oauthServerSecurityContextRepository)
			throws Exception {
		http.securityMatcher("/oauth-provider/**")
			.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll())
			.securityContext((context) -> context.securityContextRepository(oauthServerSecurityContextRepository))
			.authenticationManager(providerAuthenticationManager(store, passwordEncoder))
			.formLogin((form) -> form.loginPage(LOGIN_PAGE)
				.loginProcessingUrl(LOGIN_PAGE)
				// Not alwaysUse: the entry point saved the /oauth2/authorize request that
				// sent the user here, and forcing a fixed target would discard it and
				// strand the flow. "/" is only the fallback for someone who navigated to
				// the provider's login page directly.
				.defaultSuccessUrl("/", false)
				.permitAll());

		return http.build();
	}

	private static AuthenticationManager providerAuthenticationManager(OAuthUserStore store,
			PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider(store.manager());
		provider.setPasswordEncoder(passwordEncoder);
		return new ProviderManager(provider);
	}

}
