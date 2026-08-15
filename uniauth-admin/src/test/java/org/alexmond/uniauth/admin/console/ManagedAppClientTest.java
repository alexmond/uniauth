package org.alexmond.uniauth.admin.console;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The console's half of the contract, without a managed application running.
 *
 * <p>
 * What matters here is how failures come back: an administrator needs "the far side
 * refused this" and "the far side is not answering" to read differently, because the fix
 * is different.
 */
class ManagedAppClientTest {

	private RestClient.Builder builder;

	private MockRestServiceServer server;

	private ManagedAppClient client;

	private final ManagedApplication.Target target = target();

	@BeforeEach
	void setUp() {
		this.builder = RestClient.builder();
		this.server = MockRestServiceServer.bindTo(this.builder).build();
		this.client = new ManagedAppClient(this.builder.build());
	}

	@Test
	void itAsksTheApplicationWhatItCanAdminister() {
		this.server.expect(requestTo("https://app.test/uniauth/admin/stores"))
			.andExpect(header("Authorization", "Bearer secret-token"))
			.andRespond(withSuccess("""
					[{"mechanism":"INTERNAL","displayName":"Internal store",
					  "description":"in memory","usernames":["alice"]}]
					""", MediaType.APPLICATION_JSON));

		List<java.util.Map<String, Object>> stores = this.client.stores(this.target);

		assertThat(stores).singleElement().satisfies((store) -> {
			assertThat(store.get("mechanism")).isEqualTo("INTERNAL");
			assertThat(store.get("usernames")).isEqualTo(List.of("alice"));
		});
		this.server.verify();
	}

	@Test
	void itSendsTheCredentialAndTheAccountToCreate() {
		this.server.expect(requestTo("https://app.test/uniauth/admin/users"))
			.andExpect(method(org.springframework.http.HttpMethod.POST))
			.andExpect(header("Authorization", "Bearer secret-token"))
			.andExpect(jsonPath("$.username").value("newcomer"))
			.andExpect(jsonPath("$.mechanism").value("LDAP"))
			.andRespond(withStatus(HttpStatus.CREATED));

		Optional<String> failure = this.client.createUser(this.target, "LDAP", "newcomer", "pw", List.of("USER"));

		assertThat(failure).isEmpty();
		this.server.verify();
	}

	@Test
	void aRefusalCarriesTheApplicationsOwnMessage() {
		// Ours would be a guess; the application knows why it said no.
		this.server.expect(requestTo("https://app.test/uniauth/admin/users"))
			.andRespond(withStatus(HttpStatus.CONFLICT).contentType(MediaType.APPLICATION_JSON)
				.body("{\"error\":\"There is already an internal account called alice\"}"));

		Optional<String> failure = this.client.createUser(this.target, "INTERNAL", "alice", "pw", List.of("USER"));

		assertThat(failure).contains("There is already an internal account called alice");
	}

	@Test
	void anUnreachableApplicationSaysSoRatherThanThrowing() {
		this.server.expect(requestTo("https://app.test/uniauth/admin/users")).andRespond((request) -> {
			throw new java.io.IOException("connection refused");
		});

		Optional<String> failure = this.client.createUser(this.target, "INTERNAL", "someone", "pw", List.of("USER"));

		assertThat(failure).isPresent();
		assertThat(failure.get()).contains("not reachable");
	}

	private static ManagedApplication.Target target() {
		ManagedApplication.Target target = new ManagedApplication.Target();
		target.setId("app");
		target.setName("Managed app");
		target.setBaseUrl("https://app.test");
		target.setToken("secret-token");
		return target;
	}

}
