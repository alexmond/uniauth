package org.alexmond.uniauth.autoconfigure;

import org.alexmond.uniauth.admin.BearerTokenAuthenticationFilter;
import org.alexmond.uniauth.admin.UserAdminController;
import org.alexmond.uniauth.admin.UserStoreAdmin;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * Exposes the user stores to a management console running elsewhere.
 *
 * <p>
 * Its own filter chain, ahead of the application's: the API is authenticated by a token
 * rather than a login, is stateless, and must not be redirected to a sign-in page — a
 * console handed a 302 to HTML has no idea what to do with it.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "uniauth.admin-api", name = "enabled", havingValue = "true")
class AdminApiConfiguration {

	/**
	 * Refuses to start rather than run an account-creating API with no credential.
	 *
	 * <p>
	 * Failing loudly at startup is the point. The alternatives — defaulting to a token,
	 * or quietly leaving the API open — both end with an unprotected write endpoint that
	 * nobody notices until it is used.
	 */
	AdminApiConfiguration(UniAuthProperties properties) {
		if (!StringUtils.hasText(properties.getAdminApi().getToken())) {
			throw new IllegalStateException("uniauth.admin-api.enabled is true but uniauth.admin-api.token is not set. "
					+ "This API creates user accounts; it will not run without a token.");
		}
	}

	@Bean
	@ConditionalOnMissingBean
	UserAdminController uniAuthUserAdminController(List<UserStoreAdmin> stores) {
		return new UserAdminController(stores);
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 10)
	@ConditionalOnMissingBean(name = "uniAuthAdminApiSecurityFilterChain")
	SecurityFilterChain uniAuthAdminApiSecurityFilterChain(HttpSecurity http, UniAuthProperties properties)
			throws Exception {
		String path = properties.getAdminApi().getPath() + "/**";

		http.securityMatcher(path)
			.authorizeHttpRequests((requests) -> requests.anyRequest().hasRole("UNIAUTH_ADMIN_API"))
			// No session: every call carries its own credential, and a console that
			// accumulated sessions would be a needless thing to steal.
			.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			// A token-authenticated caller has no cookie to ride, so CSRF has nothing to
			// protect here.
			.csrf(AbstractHttpConfigurer::disable)
			.addFilterBefore(new BearerTokenAuthenticationFilter(properties.getAdminApi().getToken()),
					UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

}
