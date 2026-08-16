package org.alexmond.uniauth.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The provider as its own service: it publishes discovery, it has its own login and its
 * own accounts, and it lets a console administer them over a token-authenticated API.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = { "authserver.admin-api.enabled=true", "authserver.admin-api.token=test-token" })
class AuthServerTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void itPublishesOpenIdDiscovery() throws Exception {
		this.mockMvc.perform(get("/.well-known/openid-configuration"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.authorization_endpoint").exists())
			.andExpect(jsonPath("$.token_endpoint").exists())
			.andExpect(jsonPath("$.jwks_uri").exists());
	}

	@Test
	void itServesItsOwnLoginPage() throws Exception {
		this.mockMvc.perform(get("/login"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("UniAuth provider")));
	}

	@Test
	void itAuthenticatesItsOwnAccounts() throws Exception {
		this.mockMvc.perform(formLogin("/login").user("olivia").password("oauth-pass"))
			.andExpect(authenticated().withUsername("olivia"));
	}

	@Test
	void itRejectsAnAccountItDoesNotHave() throws Exception {
		// alice is an account at the demo application, not here. Separate services,
		// separate populations — which is the whole reason this is its own process.
		this.mockMvc.perform(formLogin("/login").user("alice").password("s3cret")).andExpect(unauthenticated());
	}

	@Test
	void theAdminApiNeedsItsToken() throws Exception {
		this.mockMvc.perform(get("/admin/api/users")).andExpect(status().isUnauthorized());
		this.mockMvc.perform(get("/admin/api/users").header("Authorization", "Bearer wrong"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void theAdminApiListsAccounts() throws Exception {
		this.mockMvc.perform(get("/admin/api/users").header("Authorization", "Bearer test-token"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$[0].username").value("olivia"));
	}

	@Test
	void anAccountCreatedThroughTheApiCanSignIn() throws Exception {
		this.mockMvc
			.perform(post("/admin/api/users").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"username":"newcomer","password":"pw","roles":["USER"]}"""))
			.andExpect(status().isCreated());

		this.mockMvc.perform(formLogin("/login").user("newcomer").password("pw"))
			.andExpect(authenticated().withUsername("newcomer"));
	}

	@Test
	void aPasswordChangedThroughTheApiTakesEffectAndKeepsTheRoles() throws Exception {
		this.mockMvc
			.perform(post("/admin/api/users").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"username":"rotate","password":"first","roles":["USER","ADMIN"]}"""))
			.andExpect(status().isCreated());

		this.mockMvc
			.perform(put("/admin/api/users/rotate").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"password":"second"}"""))
			.andExpect(status().isOk());

		this.mockMvc.perform(formLogin("/login").user("rotate").password("first")).andExpect(unauthenticated());
		// The roles survive a password reset — the account is rebuilt from itself, not
		// from scratch.
		this.mockMvc.perform(formLogin("/login").user("rotate").password("second"))
			.andExpect(authenticated().withRoles("USER", "ADMIN"));
	}

	@Test
	void rolesCanBeReplacedWithoutKnowingThePassword() throws Exception {
		this.mockMvc
			.perform(post("/admin/api/users").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"username":"promoted","password":"pw","roles":["USER"]}"""))
			.andExpect(status().isCreated());

		this.mockMvc
			.perform(put("/admin/api/users/promoted").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"roles":["USER","ADMIN"]}"""))
			.andExpect(status().isOk());

		this.mockMvc.perform(formLogin("/login").user("promoted").password("pw"))
			.andExpect(authenticated().withRoles("USER", "ADMIN"));
	}

	@Test
	void aDeletedAccountCanNoLongerSignIn() throws Exception {
		this.mockMvc
			.perform(post("/admin/api/users").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"username":"temporary","password":"pw"}"""))
			.andExpect(status().isCreated());
		this.mockMvc.perform(formLogin("/login").user("temporary").password("pw")).andExpect(authenticated());

		this.mockMvc.perform(delete("/admin/api/users/temporary").header("Authorization", "Bearer test-token"))
			.andExpect(status().isOk());

		this.mockMvc.perform(formLogin("/login").user("temporary").password("pw")).andExpect(unauthenticated());
	}

	@Test
	void operationsOnAnAccountThatIsNotThereAreAConflictRatherThanASilentSuccess() throws Exception {
		this.mockMvc.perform(delete("/admin/api/users/ghost").header("Authorization", "Bearer test-token"))
			.andExpect(status().isConflict())
			.andExpect(jsonPath("$.error").exists());
	}

}
