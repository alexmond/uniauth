package org.alexmond.uniauth;

import org.alexmond.uniauth.provider.AuthProvider;
import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins what Spring Boot actually hands us for two well-known providers, because the
 * differences between them decide how much provider-specific machinery UniAuth needs.
 *
 * <p>
 * Both registrations below declare nothing but a client id and secret. Everything else —
 * endpoints, scopes, display name — is filled in by {@code CommonOAuth2Provider}, matched
 * on the <em>registration id</em>. That is why "google" and "github" work with two lines
 * of configuration while a provider absent from that enum (Microsoft, Apple) needs a full
 * provider block written by hand.
 *
 * <p>
 * The load-bearing assertion is the last one: Google is OpenID Connect and GitHub is not.
 * That distinction, not the brand, is what changes application-visible behaviour.
 */
@SpringBootTest(classes = TestApplication.class)
@TestPropertySource(properties = { "spring.security.oauth2.client.registration.google.client-id=demo-id",
		"spring.security.oauth2.client.registration.google.client-secret=demo-secret",
		"spring.security.oauth2.client.registration.github.client-id=demo-id",
		"spring.security.oauth2.client.registration.github.client-secret=demo-secret" })
class UniAuthOauth2ProvidersTest {

	@Autowired
	AuthProviderRegistry registry;

	@Autowired
	ClientRegistrationRepository clientRegistrations;

	@Test
	void eachRegistrationBecomesItsOwnChooserButton() {
		List<AuthProvider> redirect = this.registry.redirectProviders();

		assertThat(redirect).hasSize(2);
		assertThat(redirect).allMatch((provider) -> provider.type() == AuthProviderType.OAUTH2);
		assertThat(redirect).extracting(AuthProvider::id).containsExactlyInAnyOrder("google", "github");
	}

	@Test
	void wellKnownProvidersCarryTheirOwnBrandNameAndEntryPoint() {
		List<AuthProvider> redirect = this.registry.redirectProviders();

		assertThat(redirect).filteredOn((provider) -> "google".equals(provider.id())).singleElement().satisfies((p) -> {
			assertThat(p.displayName()).isEqualTo("Google");
			assertThat(p.loginUrl()).isEqualTo("/oauth2/authorization/google");
		});
		assertThat(redirect).filteredOn((provider) -> "github".equals(provider.id())).singleElement().satisfies((p) -> {
			assertThat(p.displayName()).isEqualTo("GitHub");
			assertThat(p.loginUrl()).isEqualTo("/oauth2/authorization/github");
		});
	}

	@Test
	void googleIsOpenIdConnectButGithubIsPlainOauth2() {
		ClientRegistration google = this.clientRegistrations.findByRegistrationId("google");
		ClientRegistration github = this.clientRegistrations.findByRegistrationId("github");

		// Google returns an id_token, so the principal arrives as an OidcUser with
		// claims.
		assertThat(google.getScopes()).contains("openid");
		assertThat(google.getProviderDetails().getJwkSetUri()).isNotBlank();
		assertThat(google.getProviderDetails().getIssuerUri()).isEqualTo("https://accounts.google.com");

		// GitHub has no id_token at all: the principal is a plain OAuth2User built from a
		// userinfo call, and there is nothing to support RP-initiated logout with.
		assertThat(github.getScopes()).doesNotContain("openid");
		assertThat(github.getProviderDetails().getJwkSetUri()).isNull();
		assertThat(github.getProviderDetails().getIssuerUri()).isNull();
	}

	@Test
	void githubIdentifiesUsersByNumericIdRatherThanAName() {
		ClientRegistration github = this.clientRegistrations.findByRegistrationId("github");
		ClientRegistration google = this.clientRegistrations.findByRegistrationId("google");

		// Anything rendering "signed in as ..." has to know this differs per provider.
		assertThat(github.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("id");
		assertThat(google.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("sub");
	}

	@Test
	void githubDefaultScopeDoesNotIncludeEmail() {
		ClientRegistration github = this.clientRegistrations.findByRegistrationId("github");

		// read:user alone leaves email null for anyone whose address is private; reaching
		// it
		// needs the user:email scope AND a second call to /user/emails.
		assertThat(github.getScopes()).containsExactly("read:user");
		assertThat(github.getScopes()).doesNotContain("user:email");
	}

}
