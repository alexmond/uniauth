package org.alexmond.uniauth.provider;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What a chooser renders for one provider.
 */
class AuthProviderTest {

	@Test
	void aBrandWithMandatedWordingOverridesWhateverTheRegistrationCalledItself() {
		// Boot's CommonOAuth2Provider.GOOGLE sets clientName to "Google", so the display
		// name is the forbidden string. The button must not take it (#8).
		AuthProvider google = new AuthProvider("google", AuthProviderType.OAUTH2, AuthProviderBrand.GOOGLE, "Google",
				"/oauth2/authorization/google", true);

		assertThat(google.buttonLabel()).isEqualTo("Sign in with Google");
		assertThat(google.displayName()).isEqualTo("Google");
	}

	@Test
	void aBrandWithNoMandateKeepsTheNameTheDeploymentChose() {
		// The useful label for a corporate IdP is the employer's name, which arrives as
		// the registration's client name — not the vendor behind it.
		AuthProvider corporate = new AuthProvider("corporate-sso", AuthProviderType.OAUTH2, AuthProviderBrand.OKTA,
				"Acme Corp", "/oauth2/authorization/corporate-sso", true);

		assertThat(corporate.buttonLabel()).isEqualTo("Acme Corp");
	}

	@Test
	void aFormProviderFallsBackToItsOwnName() {
		AuthProvider internal = new AuthProvider("internal", AuthProviderType.INTERNAL, AuthProviderBrand.GENERIC,
				"Username & password", null, false);

		assertThat(internal.buttonLabel()).isEqualTo("Username & password");
		assertThat(internal.isFormBased()).isTrue();
	}

	@Test
	void anAbsentBrandIsNotAnError() {
		// AuthProvider is a record, so nothing stops a caller constructing one with a
		// null brand; a chooser asking for a label should still get one.
		AuthProvider odd = new AuthProvider("odd", AuthProviderType.SAML, null, "Partner IdP",
				"/saml2/authenticate/odd", false);

		assertThat(odd.buttonLabel()).isEqualTo("Partner IdP");
	}

}
