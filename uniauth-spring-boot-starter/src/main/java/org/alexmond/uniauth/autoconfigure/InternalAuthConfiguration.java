package org.alexmond.uniauth.autoconfigure;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.List;

/**
 * The internal (in-configuration) user store.
 *
 * <p>
 * Users are declared under {@code uniauth.internal.users}. Passwords go through a
 * delegating encoder, so each one carries its algorithm prefix — {@code {noop}} for plain
 * text in a demo, {@code {bcrypt}} for anything real.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "uniauth.internal", name = "enabled", havingValue = "true")
class InternalAuthConfiguration {

	@Bean
	@ConditionalOnMissingBean
	PasswordEncoder uniAuthPasswordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean(UserDetailsService.class)
	InMemoryUserDetailsManager uniAuthInternalUserDetailsService(UniAuthProperties properties) {
		List<UserDetails> users = properties.getInternal()
			.getUsers()
			.stream()
			.map((configured) -> (UserDetails) User.withUsername(configured.getUsername())
				.password(configured.getPassword())
				.roles(configured.getRoles().toArray(String[]::new))
				.build())
			.toList();
		return new InMemoryUserDetailsManager(users);
	}

	@Bean
	AuthenticationProvider uniAuthInternalAuthenticationProvider(UserDetailsService userDetailsService,
			PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
		provider.setPasswordEncoder(passwordEncoder);
		return provider;
	}

}
