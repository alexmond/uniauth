package org.alexmond.uniauth.autoconfigure;

import org.alexmond.uniauth.config.UniAuthHttpSecurityCustomizer;
import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the chain does with an {@link UniAuthHttpSecurityCustomizer}, and what it does
 * without one.
 */
class UniAuthHttpSecurityCustomizerConfigurationTest {

	/**
	 * The starter's chain needs Spring Security's own {@code HttpSecurity} prototype,
	 * which comes from Boot's security auto-configuration rather than from anything here.
	 */
	private static final Class<?>[] REQUIRED = { SecurityAutoConfiguration.class,
			ServletWebSecurityAutoConfiguration.class, UniAuthAutoConfiguration.class };

	private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(REQUIRED))
		.withPropertyValues("uniauth.enabled=true", "uniauth.internal.enabled=true");

	@Test
	void theChainBuildsWithNoCustomizerAtAll() {
		// The hook is additive. An application that declares none gets exactly the chain
		// it got before the hook existed.
		this.runner.run((context) -> assertThat(context).hasNotFailed()
			.hasSingleBean(SecurityFilterChain.class)
			.doesNotHaveBean(UniAuthHttpSecurityCustomizer.class));
	}

	@Test
	void aCustomizerThatThrowsFailsTheContextRatherThanBeingSwallowed() {
		// It reaches HttpSecurity itself, so a customizer that cannot be applied means
		// the application's own security intent did not take. Starting anyway would
		// serve a chain nobody asked for, and the only sign would be a stack trace
		// nobody reads.
		this.runner.withUserConfiguration(Unapplicable.class).run((context) -> assertThat(context).hasFailed());
	}

	@Configuration(proxyBeanMethods = false)
	static class Unapplicable {

		@Bean
		UniAuthHttpSecurityCustomizer broken() {
			return (http) -> {
				throw new IllegalStateException("cannot be applied");
			};
		}

	}

}
