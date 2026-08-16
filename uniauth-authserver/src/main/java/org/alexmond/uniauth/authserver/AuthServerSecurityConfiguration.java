package org.alexmond.uniauth.authserver;

import org.alexmond.uniauth.authserver.admin.BearerTokenAuthenticationFilter;
import org.alexmond.uniauth.authserver.token.AccountClaimsTokenCustomizer;
import org.alexmond.uniauth.authserver.user.AccountStore;
import org.alexmond.uniauth.authserver.user.AuthServerProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

/**
 * The provider's chains: its protocol endpoints, its login page, and its admin API.
 *
 * <p>
 * Simpler than the version this replaces. When the provider was co-hosted with one of its
 * clients they shared a session, so each chain needed its own
 * {@code SecurityContextRepository} to stop either seeing the other's login. Separate
 * processes have separate sessions, so that is all gone.
 */
@Configuration(proxyBeanMethods = false)
public class AuthServerSecurityConfiguration {

	static final String LOGIN_PAGE = "/login";

	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	/**
	 * Reports what this provider knows about an account in its ID token — roles, and the
	 * standard profile claims for the scopes granted. Picked up by the authorization
	 * server's token generator by type.
	 */
	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> accountClaimsTokenCustomizer(AccountStore accounts) {
		return new AccountClaimsTokenCustomizer(accounts);
	}

	/** Authorize, token, jwks, userinfo, discovery. */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();

		http.securityMatcher(authorizationServer.getEndpointsMatcher())
			.with(authorizationServer, (server) -> server.oidc(Customizer.withDefaults()))
			.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated())
			.csrf((csrf) -> csrf.ignoringRequestMatchers(authorizationServer.getEndpointsMatcher()))
			.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(LOGIN_PAGE)));

		return http.build();
	}

	/**
	 * The admin API, when enabled: a console managing accounts here. Token-authenticated
	 * and stateless, ahead of the browser chain, because a console has no session and
	 * must never be sent to a login page.
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 5)
	@ConditionalOnProperty(prefix = "authserver.admin-api", name = "enabled", havingValue = "true")
	SecurityFilterChain adminApiSecurityFilterChain(HttpSecurity http, AuthServerProperties properties)
			throws Exception {
		if (!StringUtils.hasText(properties.getAdminApi().getToken())) {
			throw new IllegalStateException("authserver.admin-api.enabled is true but no token is set. "
					+ "This API creates accounts; it will not run without one.");
		}
		http.securityMatcher(properties.getAdminApi().getPath() + "/**")
			.authorizeHttpRequests((requests) -> requests.anyRequest().hasRole("AUTHSERVER_ADMIN_API"))
			.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.csrf(AbstractHttpConfigurer::disable)
			.addFilterBefore(new BearerTokenAuthenticationFilter(properties.getAdminApi().getToken()),
					UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	/** Everything a browser sees: the login form, and nothing else worth reaching. */
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, AccountStore accounts,
			PasswordEncoder passwordEncoder) throws Exception {
		http.authorizeHttpRequests(
				(requests) -> requests.requestMatchers(LOGIN_PAGE, "/css/**", "/error", "/actuator/**")
					.permitAll()
					.anyRequest()
					.authenticated())
			.authenticationManager(accountAuthenticationManager(accounts, passwordEncoder))
			.formLogin((form) -> form.loginPage(LOGIN_PAGE)
				// Not alwaysUse: the entry point saved the authorize request that sent
				// the
				// user here, and a fixed target would discard it and strand the flow.
				.defaultSuccessUrl("/", false)
				.permitAll())
			.logout(Customizer.withDefaults());

		return http.build();
	}

	private static AuthenticationManager accountAuthenticationManager(AccountStore accounts,
			PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider(accounts.manager());
		provider.setPasswordEncoder(passwordEncoder);
		return new ProviderManager(provider);
	}

}
