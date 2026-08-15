package org.alexmond.uniauth;

import org.alexmond.uniauth.admin.UserStoreAdmin;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The management API a remote console drives.
 *
 * <p>
 * It creates accounts, so most of what is worth asserting is about who may call it — an
 * unauthenticated caller, a wrong token and a right one, all at the same endpoint.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthAdminApiTest.FakeStore.class)
@TestPropertySource(properties = { "uniauth.admin-api.enabled=true", "uniauth.admin-api.token=test-token",
		"uniauth.internal.enabled=true", "uniauth.internal.users[0].username=alice",
		"uniauth.internal.users[0].password={noop}s3cret" })
class UniAuthAdminApiTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void aCallWithNoTokenIsRefused() throws Exception {
		this.mockMvc.perform(get("/uniauth/admin/stores")).andExpect(status().isUnauthorized());
	}

	@Test
	void aCallWithTheWrongTokenIsRefused() throws Exception {
		this.mockMvc.perform(get("/uniauth/admin/stores").header("Authorization", "Bearer not-the-token"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void anApplicationSessionIsNotEnoughEither() throws Exception {
		// Being signed in as a human is a different thing from being the console. The API
		// takes its token and nothing else.
		this.mockMvc.perform(get("/uniauth/admin/stores").with(
				org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("alice")
					.roles("ADMIN")))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void theRightTokenListsWhateverStoresTheApplicationPublishes() throws Exception {
		this.mockMvc.perform(get("/uniauth/admin/stores").header("Authorization", "Bearer test-token"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$[0].mechanism").value("INTERNAL"))
			.andExpect(jsonPath("$[0].displayName").value("Fake store"))
			.andExpect(jsonPath("$[0].usernames[0]").value("existing"));
	}

	@Test
	void creatingAUserReturnsCreated() throws Exception {
		this.mockMvc
			.perform(post("/uniauth/admin/users").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"mechanism":"INTERNAL","username":"newcomer","password":"pw","roles":["USER"]}"""))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.created").value("newcomer"));
	}

	@Test
	void aNameAlreadyTakenIsAConflictRatherThanAServerError() throws Exception {
		// A console should be able to tell "you asked for something impossible" apart
		// from
		// "the far side broke".
		this.mockMvc
			.perform(post("/uniauth/admin/users").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"mechanism":"INTERNAL","username":"existing","password":"pw"}"""))
			.andExpect(status().isConflict())
			.andExpect(jsonPath("$.error").exists());
	}

	@Test
	void aMechanismWithNoStoreIsNotFound() throws Exception {
		this.mockMvc
			.perform(post("/uniauth/admin/users").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"mechanism":"SAML","username":"nobody","password":"pw"}"""))
			.andExpect(status().isNotFound());
	}

	@Test
	void anIncompleteRequestIsRejected() throws Exception {
		this.mockMvc
			.perform(post("/uniauth/admin/users").header("Authorization", "Bearer test-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"mechanism":"INTERNAL","username":"  "}"""))
			.andExpect(status().isBadRequest());
	}

	/** Stands in for whatever stores a real application publishes. */
	@TestConfiguration(proxyBeanMethods = false)
	static class FakeStore {

		@Bean
		UserStoreAdmin fakeInternalStore() {
			return new UserStoreAdmin() {

				private final List<String> names = new ArrayList<>(List.of("existing"));

				@Override
				public AuthProviderType mechanism() {
					return AuthProviderType.INTERNAL;
				}

				@Override
				public String displayName() {
					return "Fake store";
				}

				@Override
				public String description() {
					return "For the test.";
				}

				@Override
				public List<String> usernames() {
					return List.copyOf(this.names);
				}

				@Override
				public void create(String username, String password, List<String> roles) {
					if (this.names.contains(username)) {
						throw new IllegalArgumentException("already taken: " + username);
					}
					this.names.add(username);
				}
			};
		}

	}

}
