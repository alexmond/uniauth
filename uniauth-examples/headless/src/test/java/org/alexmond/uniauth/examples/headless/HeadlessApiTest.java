package org.alexmond.uniauth.examples.headless;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * What makes this example different from the web app: no HTML anywhere, and a missing
 * session is a 401 rather than a redirect.
 */
@SpringBootTest
@AutoConfigureMockMvc
class HeadlessApiTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void aMissingSessionIsUnauthorizedRatherThanARedirect() throws Exception {
		// The whole point of the AuthenticationEntryPoint bean. A 302 here would send a
		// fetch() client to an HTML page it cannot use.
		this.mockMvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
	}

	@Test
	void providersAreReadableWithoutASessionSoTheFrontEndCanRenderAChooser() throws Exception {
		this.mockMvc.perform(get("/uniauth/providers"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$[0].id").value("internal"))
			.andExpect(jsonPath("$[1].id").value("ldap"));
	}

	@Test
	void theInternalStoreReportsItselfThroughTheApi() throws Exception {
		HttpSession session = signIn("alice", "s3cret");

		this.mockMvc.perform(get("/api/me").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.name").value("alice"))
			.andExpect(jsonPath("$.mechanism").value("INTERNAL"))
			.andExpect(jsonPath("$.provider").value("internal"))
			.andExpect(jsonPath("$.authorities").value(org.hamcrest.Matchers.hasItem("ROLE_ADMIN")));
	}

	@Test
	void theDirectoryReportsItselfThroughTheSameApi() throws Exception {
		HttpSession session = signIn("bob", "bobspassword");

		this.mockMvc.perform(get("/api/me").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.name").value("bob"))
			.andExpect(jsonPath("$.mechanism").value("LDAP"))
			.andExpect(jsonPath("$.authorities").value(org.hamcrest.Matchers.hasItem("ROLE_DEVELOPERS")));
	}

	private HttpSession signIn(String username, String password) throws Exception {
		return this.mockMvc.perform(formLogin("/login").user(username).password(password))
			.andExpect(authenticated().withUsername(username))
			.andReturn()
			.getRequest()
			.getSession();
	}

}
