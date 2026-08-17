package org.alexmond.uniauth;

import org.junit.jupiter.api.Test;

import org.alexmond.uniauth.provider.AuthProvider;
import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SAML, configured the way an application configures it — through Spring Boot's own
 * {@code spring.security.saml2.relyingparty.*} binding.
 *
 * <p>
 * This exists because the registry test does not cover it. That one builds an
 * {@code AuthProviderRegistry} directly from a repository it constructs itself, which
 * proves the registry lists whatever it is given and proves nothing about whether an
 * application's configuration ever produces one. The binding is the part that can
 * silently not happen: Boot 4 moved SAML autoconfiguration out of
 * {@code spring-boot-autoconfigure} into its own module, so without that module on the
 * classpath these properties are read by nobody, no repository is created, and SAML
 * disappears from the chooser with nothing logged.
 */
@SpringBootTest(classes = org.alexmond.uniauth.testapp.TestApplication.class)
@TestPropertySource(properties = {
		"spring.security.saml2.relyingparty.registration.testidp.assertingparty.entity-id=https://idp.example.com",
		"spring.security.saml2.relyingparty.registration.testidp.assertingparty.singlesignon.url=https://idp.example.com/sso",
		"spring.security.saml2.relyingparty.registration.testidp.assertingparty.singlesignon.sign-request=false",
		"spring.security.saml2.relyingparty.registration.testidp.assertingparty.verification.credentials[0].certificate-location=classpath:saml/test-idp.crt" })
class UniAuthSamlRegistrationTest {

	@Autowired
	AuthProviderRegistry registry;

	@Autowired(required = false)
	RelyingPartyRegistrationRepository relyingParties;

	@Test
	void bootBindsTheRelyingPartyConfiguration() {
		assertThat(this.relyingParties)
			.as("no RelyingPartyRegistrationRepository — is Boot's SAML " + "autoconfiguration on the classpath?")
			.isNotNull();
	}

	@Test
	void theChooserOffersTheSamlRegistration() {
		assertThat(this.registry.providers()).filteredOn((provider) -> "testidp".equals(provider.id()))
			.singleElement()
			.satisfies((provider) -> {
				assertThat(provider.type()).isEqualTo(AuthProviderType.SAML);
				assertThat(provider.loginUrl()).isEqualTo("/saml2/authenticate/testidp");
				// SAML is redirect-based: it renders a button, not a field on the form.
				assertThat(provider.isFormBased()).isFalse();
			});
	}

	@Test
	void samlIsNotReportedAsOpenIdConnect() {
		AuthProvider saml = this.registry.providers()
			.stream()
			.filter((provider) -> "testidp".equals(provider.id()))
			.findFirst()
			.orElseThrow();

		// oidc() is about id_tokens and claims, which SAML does not have — it carries
		// assertions. A chooser that conflated them would promise the wrong principal
		// type.
		assertThat(saml.oidc()).isFalse();
	}

}
