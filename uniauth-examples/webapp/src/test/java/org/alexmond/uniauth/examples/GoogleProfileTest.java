package org.alexmond.uniauth.examples;

import org.alexmond.uniauth.provider.AuthProvider;
import org.alexmond.uniauth.provider.AuthProviderBrand;
import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Google, from the two lines of configuration the {@code google} profile adds.
 *
 * <p>
 * Credentials here are fake and no call reaches Google: what is worth proving is that
 * supplying an id and a secret is genuinely all it takes — the endpoints, the scopes, the
 * brand and the OIDC capability are all derived, and the chooser offers a button without
 * this application contributing any code. If that ever stops being true, this fails
 * before anyone finds out with a real client id.
 */
@SpringBootTest
@ActiveProfiles({ "test", "google" })
@AutoConfigureMockMvc
@TestPropertySource(properties = { "GOOGLE_CLIENT_ID=test-client-id", "GOOGLE_CLIENT_SECRET=test-client-secret",
		// Its own directory port. The extra profile makes this a SECOND application
		// context, and the embedded UnboundID server binds a fixed port — so sharing
		// 18389 with the other tests fails with "Address already in use" only when the
		// whole suite runs, never when this class runs alone.
		"spring.ldap.embedded.port=18392", "uniauth.ldap.url=ldap://localhost:18392/dc=example,dc=com" })
class GoogleProfileTest {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	AuthProviderRegistry registry;

	@Test
	void theChooserOffersGoogle() {
		assertThat(this.registry.providers()).filteredOn((provider) -> "google".equals(provider.id()))
			.singleElement()
			.satisfies((provider) -> {
				assertThat(provider.type()).isEqualTo(AuthProviderType.OAUTH2);
				assertThat(provider.loginUrl()).isEqualTo("/oauth2/authorization/google");
			});
	}

	@Test
	void googleIsRecognisedAsOpenIdConnectRatherThanPlainOauth2() {
		// The distinction that changes what a client gets back: an OidcUser with claims,
		// not a bare OAuth2User. It is derived from the openid scope, which
		// CommonOAuth2Provider supplies — nothing here declares it.
		AuthProvider google = this.registry.providers()
			.stream()
			.filter((provider) -> "google".equals(provider.id()))
			.findFirst()
			.orElseThrow();

		assertThat(google.oidc()).isTrue();
		assertThat(google.brand()).isEqualTo(AuthProviderBrand.GOOGLE);
	}

	@Test
	void theEntryPointRedirectsToGoogle() throws Exception {
		this.mockMvc.perform(get("/oauth2/authorization/google"))
			.andExpect(status().is3xxRedirection())
			.andExpect(header().string("Location",
					org.hamcrest.Matchers.startsWith("https://accounts.google.com/o/oauth2/v2/auth")));
	}

	@Test
	void theRedirectAsksForTheOpenIdScopeAndCarriesTheClientId() throws Exception {
		String location = this.mockMvc.perform(get("/oauth2/authorization/google"))
			.andReturn()
			.getResponse()
			.getHeader("Location");

		assertThat(location).contains("client_id=test-client-id").contains("scope=openid");
		// The URI Google must have registered, and the single most common reason a real
		// integration fails with redirect_uri_mismatch.
		assertThat(location).contains("redirect_uri=http://localhost/login/oauth2/code/google");
	}

}
