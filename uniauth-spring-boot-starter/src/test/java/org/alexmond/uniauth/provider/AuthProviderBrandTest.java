package org.alexmond.uniauth.provider;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Brand detection has to survive registrations named for their role rather than their
 * vendor, which is the common case in an enterprise: nobody calls it "microsoft", they
 * call it "sso" or "corporate".
 */
class AuthProviderBrandTest {

	@Test
	void matchesOnRegistrationIdFirst() {
		assertThat(AuthProviderBrand.detect(registration("google", "https://accounts.google.com/o/oauth2/v2/auth")))
			.isEqualTo(AuthProviderBrand.GOOGLE);
		assertThat(AuthProviderBrand.detect(registration("github", "https://github.com/login/oauth/authorize")))
			.isEqualTo(AuthProviderBrand.GITHUB);
	}

	@Test
	void matchIsCaseInsensitive() {
		assertThat(AuthProviderBrand.detect(registration("GitHub", "https://example.test/authorize")))
			.isEqualTo(AuthProviderBrand.GITHUB);
	}

	@Test
	void fallsBackToTheEndpointHostWhenTheIdSaysNothing() {
		assertThat(AuthProviderBrand
			.detect(registration("corporate-sso", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize")))
			.isEqualTo(AuthProviderBrand.MICROSOFT);
		assertThat(AuthProviderBrand.detect(registration("staff", "https://accounts.google.com/o/oauth2/v2/auth")))
			.isEqualTo(AuthProviderBrand.GOOGLE);
	}

	@Test
	void anythingUnrecognisedIsGeneric() {
		assertThat(AuthProviderBrand.detect(registration("keycloak", "https://sso.internal.test/auth")))
			.isEqualTo(AuthProviderBrand.GENERIC);
		assertThat(AuthProviderBrand.detect(null)).isEqualTo(AuthProviderBrand.GENERIC);
	}

	@Test
	void genericCarriesNoBrandName() {
		assertThat(AuthProviderBrand.GENERIC.displayName()).isEmpty();
		assertThat(AuthProviderBrand.MICROSOFT.displayName()).isEqualTo("Microsoft");
	}

	private static ClientRegistration registration(String registrationId, String authorizationUri) {
		return ClientRegistration.withRegistrationId(registrationId)
			.clientId("client-id")
			.clientSecret("client-secret")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.authorizationUri(authorizationUri)
			.tokenUri("https://example.test/token")
			.build();
	}

}
