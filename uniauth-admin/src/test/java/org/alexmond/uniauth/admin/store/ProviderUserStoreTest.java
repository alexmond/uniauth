package org.alexmond.uniauth.admin.store;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.alexmond.uniauth.admin.ConsoleProperties;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withResourceNotFound;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The provider store speaks the authserver's admin API, and carries its token on every
 * call.
 */
class ProviderUserStoreTest {

	private MockRestServiceServer server;

	private ProviderUserStore store;

	@BeforeEach
	void setUp() {
		RestClient.Builder builder = RestClient.builder();
		this.server = MockRestServiceServer.bindTo(builder).build();
		ConsoleProperties.Provider config = new ConsoleProperties.Provider();
		config.setBaseUrl("http://provider:8080");
		config.setToken("secret-token");
		this.store = new ProviderUserStore(config, builder.build());
	}

	@Test
	void itListsAccountsWithTheirRoles() {
		this.server.expect(requestTo("http://provider:8080/admin/api/users"))
			.andExpect(method(HttpMethod.GET))
			.andExpect(header("Authorization", "Bearer secret-token"))
			.andRespond(withSuccess("""
					[{"username":"olivia","roles":["ROLE_USER"]}]""", MediaType.APPLICATION_JSON));

		assertThat(this.store.users()).singleElement()
			.satisfies((user) -> assertThat(user.username()).isEqualTo("olivia"));
	}

	@Test
	void itCreatesAnAccount() {
		this.server.expect(requestTo("http://provider:8080/admin/api/users"))
			.andExpect(method(HttpMethod.POST))
			.andExpect(header("Authorization", "Bearer secret-token"))
			.andExpect(content().json("""
					{"username":"newcomer","password":"pw","roles":["USER"]}"""))
			.andRespond(withStatus(org.springframework.http.HttpStatus.CREATED));

		this.store.create("newcomer", "pw", List.of("USER"));
		this.server.verify();
	}

	@Test
	void aPasswordChangeSendsOnlyThePassword() {
		// Not the roles: the provider rebuilds the account from itself, so sending a
		// partial update is what keeps the roles from being silently reset.
		this.server.expect(requestTo("http://provider:8080/admin/api/users/rotate"))
			.andExpect(method(HttpMethod.PUT))
			.andExpect(content().json("""
					{"password":"second"}"""))
			.andRespond(withSuccess());

		this.store.setPassword("rotate", "second");
		this.server.verify();
	}

	@Test
	void itDeletesAnAccount() {
		this.server.expect(requestTo("http://provider:8080/admin/api/users/temporary"))
			.andExpect(method(HttpMethod.DELETE))
			.andRespond(withSuccess());

		this.store.delete("temporary");
		this.server.verify();
	}

	@Test
	void aRefusalCarriesTheProvidersOwnMessage() {
		this.server.expect(requestTo("http://provider:8080/admin/api/users"))
			.andRespond(withStatus(org.springframework.http.HttpStatus.CONFLICT).contentType(MediaType.APPLICATION_JSON)
				.body("""
						{"error":"olivia already exists"}"""));

		assertThatThrownBy(() -> this.store.create("olivia", "pw", List.of("USER"))).isInstanceOf(StoreException.class)
			.hasMessage("olivia already exists");
	}

	@Test
	void anUnreachableProviderSaysSoRatherThanLookingEmpty() {
		this.server.expect(requestTo("http://provider:8080/admin/api/users")).andRespond(withResourceNotFound());

		assertThatThrownBy(() -> this.store.users()).isInstanceOf(StoreException.class);
	}

}
