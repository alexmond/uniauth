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
 * GitHub, from the {@code github} profile.
 *
 * <p>
 * Worth its own class because GitHub is the one provider here that is <em>not</em> OpenID
 * Connect. Everything the demo shows about claims, ID tokens and verified addresses comes
 * from OIDC; GitHub has none of it, and the cases below pin the difference so that a
 * change which quietly turns it into "just another OIDC provider" fails rather than
 * misleads.
 */
@SpringBootTest
@ActiveProfiles({ "test", "github" })
@AutoConfigureMockMvc
@TestPropertySource(properties = { "GITHUB_CLIENT_ID=test-client-id", "GITHUB_CLIENT_SECRET=test-client-secret",
		// Its own directory port: the extra profile makes this a second application
		// context, and the embedded server binds a fixed one.
		"spring.ldap.embedded.port=18393", "uniauth.ldap.url=ldap://localhost:18393/dc=example,dc=com" })
class GithubProfileTest {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	AuthProviderRegistry registry;

	@Test
	void theChooserOffersGithub() {
		assertThat(this.registry.providers()).filteredOn((provider) -> "github".equals(provider.id()))
			.singleElement()
			.satisfies((provider) -> {
				assertThat(provider.type()).isEqualTo(AuthProviderType.OAUTH2);
				assertThat(provider.loginUrl()).isEqualTo("/oauth2/authorization/github");
				assertThat(provider.brand()).isEqualTo(AuthProviderBrand.GITHUB);
			});
	}

	@Test
	void githubIsPlainOauth2AndNotOpenIdConnect() {
		// The capability that actually changes what a client gets back: no openid scope
		// means no id_token, so no claims — a bare OAuth2User. Brand is presentation;
		// this is behaviour.
		AuthProvider github = this.registry.providers()
			.stream()
			.filter((provider) -> "github".equals(provider.id()))
			.findFirst()
			.orElseThrow();

		assertThat(github.oidc()).isFalse();
	}

	@Test
	void theRedirectAsksForTheScopeThatMakesAnAddressReachable() throws Exception {
		String location = this.mockMvc.perform(get("/oauth2/authorization/github"))
			.andReturn()
			.getResponse()
			.getHeader("Location");

		// read:user alone signs a user in and leaves the account with no address, which
		// is a login that cannot be approved on anything but a username.
		assertThat(location).contains("scope=read:user%20user:email");
		assertThat(location).contains("client_id=test-client-id");
	}

	@Test
	void theEntryPointRedirectsToGithub() throws Exception {
		this.mockMvc.perform(get("/oauth2/authorization/github"))
			.andExpect(status().is3xxRedirection())
			.andExpect(header().string("Location",
					org.hamcrest.Matchers.startsWith("https://github.com/login/oauth/authorize")));
	}

}
