package org.alexmond.uniauth;

import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An application that declares an {@link AuthenticationEntryPoint} gets it, instead of
 * the redirect to the chooser.
 *
 * <p>
 * This is what an API-first application needs: a JSON client handed a 302 to an HTML page
 * either follows it into nonsense or reports a confusing success. Declaring the bean is
 * the whole opt-in — no filter chain of its own, so every mechanism stays wired.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthEntryPointTest.Unauthorized.class)
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=true",
		"uniauth.internal.users[0].username=alice", "uniauth.internal.users[0].password={noop}s3cret" })
class UniAuthEntryPointTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void aMissingSessionIsUnauthorizedRatherThanARedirect() throws Exception {
		this.mockMvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	void permittedPathsAreStillServed() throws Exception {
		// The entry point only governs what happens when a session is required.
		this.mockMvc.perform(get("/uniauth/providers")).andExpect(status().isOk());
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class Unauthorized {

		@Bean
		AuthenticationEntryPoint unauthorizedEntryPoint() {
			return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
		}

	}

}
