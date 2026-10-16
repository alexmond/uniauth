package org.alexmond.uniauth.provider;

import java.util.Arrays;
import java.util.List;

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

	@Test
	void everyBrandThatMandatesACallToActionCarriesItsExactWording() {
		// Not decoration. Google's guidelines list "using 'Google' by itself as button
		// text" among the things explicitly forbidden, and Facebook names the two labels
		// it accepts. Both were rendered as the bare brand name (#8).
		assertThat(AuthProviderBrand.GOOGLE.callToAction()).isEqualTo("Sign in with Google");
		assertThat(AuthProviderBrand.MICROSOFT.callToAction()).isEqualTo("Sign in with Microsoft");
		assertThat(AuthProviderBrand.GITHUB.callToAction()).isEqualTo("Sign in with GitHub");
		assertThat(AuthProviderBrand.FACEBOOK.callToAction()).isEqualTo("Login with Facebook");
	}

	@Test
	void theLabelsReadAlikeAsFarAsTheGuidelinesAllow() {
		// Buttons stacked in one column should not each phrase the same act differently.
		// Identical wording is unreachable — Microsoft's approved set has no "Continue
		// with" and Facebook's has no "Sign in with" — so the test pins the most uniform
		// arrangement that breaks nobody's rules: one phrasing everywhere it is
		// permitted, and exactly one documented exception.
		List<AuthProviderBrand> mandated = Arrays.stream(AuthProviderBrand.values())
			.filter((brand) -> !brand.callToAction().isEmpty())
			.toList();

		assertThat(mandated).isNotEmpty();
		assertThat(mandated).filteredOn((brand) -> !brand.callToAction().startsWith("Sign in with "))
			.containsExactly(AuthProviderBrand.FACEBOOK);
		assertThat(mandated).allSatisfy(
				(brand) -> assertThat(brand.callToAction()).endsWith(" " + brand.displayName()).contains(" with "));
	}

	@Test
	void aBrandWithNoMandateOfItsOwnCarriesNoCallToAction() {
		// Okta is the vendor behind somebody else's IdP, so "Sign in with Okta" would
		// name the wrong organisation to the person reading it. Generic has no brand at
		// all. Both fall back to whatever the registration called itself.
		assertThat(AuthProviderBrand.OKTA.callToAction()).isEmpty();
		assertThat(AuthProviderBrand.GENERIC.callToAction()).isEmpty();
	}

	@Test
	void appleCarriesNoTreatmentBecauseTheSignInItWouldDecorateDoesNotWork() {
		// Apple does mandate one. It is left out because this starter cannot complete an
		// Apple sign-in at all — ClientRegistration takes a static client secret and
		// Apple issues a generated ES256 JWT — so a compliant button would decorate a
		// flow that dead-ends. The treatment lands with the support (#42).
		assertThat(AuthProviderBrand.APPLE.callToAction()).isEmpty();
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
