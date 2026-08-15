package org.alexmond.uniauth;

import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end check of the internal store running through the shared filter chain: the
 * chooser page renders, the providers endpoint reports what is enabled, and a real form
 * post authenticates.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "uniauth.internal.enabled=true", "uniauth.internal.users[0].username=alice",
		"uniauth.internal.users[0].password={noop}s3cret", "uniauth.internal.users[0].roles[0]=USER" })
class UniAuthInternalLoginTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void loginPageRendersTheCredentialsForm() throws Exception {
		mockMvc.perform(get("/login"))
			.andExpect(status().isOk())
			.andExpect(content().string(org.hamcrest.Matchers.containsString("name=\"username\"")))
			.andExpect(content().string(org.hamcrest.Matchers.containsString("name=\"password\"")));
	}

	@Test
	void providersEndpointListsTheInternalStore() throws Exception {
		mockMvc.perform(get("/uniauth/providers"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$[0].id").value("internal"))
			.andExpect(jsonPath("$[0].type").value("INTERNAL"))
			.andExpect(jsonPath("$[0].loginUrl").doesNotExist());
	}

	@Test
	void protectedResourceRedirectsAnonymousUsersToTheChooser() throws Exception {
		mockMvc.perform(get("/")).andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/login"));
	}

	@Test
	void configuredCredentialsAuthenticate() throws Exception {
		mockMvc.perform(formLogin("/login").user("alice").password("s3cret"))
			.andExpect(authenticated().withUsername("alice").withRoles("USER"));
	}

	@Test
	void wrongPasswordIsRejected() throws Exception {
		mockMvc.perform(formLogin("/login").user("alice").password("wrong")).andExpect(unauthenticated());
	}

	@Test
	void unknownUserIsRejected() throws Exception {
		mockMvc.perform(formLogin("/login").user("mallory").password("s3cret")).andExpect(unauthenticated());
	}

	@Test
	void logoutReturnsToTheChooser() throws Exception {
		mockMvc
			.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/logout").with(csrf()))
			.andExpect(status().is3xxRedirection());
	}

}
