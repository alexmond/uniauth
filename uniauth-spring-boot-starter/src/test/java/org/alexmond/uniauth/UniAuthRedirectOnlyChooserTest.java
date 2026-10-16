package org.alexmond.uniauth;

import java.util.List;

import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * A {@code UserDetailsService} in the context does not open the password form.
 *
 * <p>
 * The security boundary on #9's detection, and the reason it reads
 * {@code AuthenticationProvider} beans only. Spring Boot contributes a fallback account
 * of its own — {@code user}, with a password generated at startup and printed to the log
 * — and it arrives as precisely this type. That account can genuinely sign in through
 * this chain, because the form-login filter, once installed, resolves through the global
 * {@code AuthenticationManager}. So counting the type would mean an application that
 * installed no mechanism at all getting a password form that admits it: a visibly broken
 * configuration turned into a quietly reachable one.
 *
 * <p>
 * The bean below is the application's own rather than Boot's, which makes the test
 * independent of whether Boot's fallback happens to be present. It is not, here, and the
 * reason is a classpath accident rather than anything in this repository:
 * {@code UserDetailsServiceAutoConfiguration} is {@code @ConditionalOnMissingClass} on
 * {@code ClientRegistrationRepository} — the <em>class</em> — and this starter depends on
 * {@code spring-boot-starter-oauth2-client} at compile scope. Relying on that would make
 * the guarantee somebody else's to keep, and a consumer excluding that dependency would
 * lose it silently. Not reading the type at all is the guarantee.
 *
 * <p>
 * An application whose accounts really are only a {@code UserDetailsService} says so in
 * one line, and {@link UniAuthFormForcedTest} covers both ways.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthRedirectOnlyChooserTest.ApplicationUserDetails.class)
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=false",
		"uniauth.ldap.enabled=false", "spring.security.oauth2.client.registration.google.client-id=demo-id",
		"spring.security.oauth2.client.registration.google.client-secret=demo-secret" })
class UniAuthRedirectOnlyChooserTest {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	AuthProviderRegistry registry;

	@Test
	void thereIsNoFormBecauseNoProviderInTheContextIsTheApplicationSOwn() throws Exception {
		String page = this.mockMvc.perform(get("/login")).andReturn().getResponse().getContentAsString();

		assertThat(this.registry.hasFormProvider()).isFalse();
		assertThat(page).doesNotContain("name=\"password\"");
		assertThat(page).contains("Sign in with Google");
	}

	/** Accounts of the shape Boot's own fallback has, and therefore not counted. */
	@TestConfiguration(proxyBeanMethods = false)
	static class ApplicationUserDetails {

		@Bean
		UserDetailsService applicationUserDetails() {
			return new InMemoryUserDetailsManager(
					List.of(User.withUsername("app-user").password("{noop}letmein").roles("USER").build()));
		}

	}

}
