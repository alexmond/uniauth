package org.alexmond.uniauth;

import java.util.List;

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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * The one line an application says when its accounts are only a
 * {@code UserDetailsService}.
 *
 * <p>
 * Detection cannot read that type — see {@link UniAuthRedirectOnlyChooserTest} for why —
 * so {@code uniauth.form.enabled} is how such an application asks for its form. The route
 * has to actually work, or the boundary that test defends would be a dead end rather than
 * a trade.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthFormForcedTest.ApplicationUserDetails.class)
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=false",
		"uniauth.ldap.enabled=false", "uniauth.form.enabled=true" })
class UniAuthFormForcedTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theFormIsRenderedAndTheApplicationSAccountsAnswerIt() throws Exception {
		assertThat(this.mockMvc.perform(get("/login")).andReturn().getResponse().getContentAsString())
			.contains("name=\"password\"");

		// Spring Security builds the provider around the application's bean, so the
		// accounts work once there is a filter to post to. That is the whole gap: the
		// accounts were never the problem.
		this.mockMvc.perform(formLogin("/login").user("app-user").password("letmein"))
			.andExpect(authenticated().withUsername("app-user"));
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ApplicationUserDetails {

		@Bean
		UserDetailsService applicationUserDetails() {
			return new InMemoryUserDetailsManager(
					List.of(User.withUsername("app-user").password("{noop}letmein").roles("USER").build()));
		}

	}

}
