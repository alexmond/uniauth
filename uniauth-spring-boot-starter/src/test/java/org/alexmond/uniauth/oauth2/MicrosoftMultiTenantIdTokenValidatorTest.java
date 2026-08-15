package org.alexmond.uniauth.oauth2;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The validator loosens exactly one rule, so the tests exist mainly to prove the others
 * still bite. A relaxed issuer check that also stopped checking audience or expiry would
 * be a security hole wearing a feature's clothes.
 *
 * <p>
 * Note what is <em>not</em> covered: no real Entra tenant is involved, so signature
 * verification and the live discovery handshake are untested here.
 */
class MicrosoftMultiTenantIdTokenValidatorTest {

	private static final String TENANT_A = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0";

	private static final String TENANT_B = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0";

	private final MicrosoftMultiTenantIdTokenValidator validator = new MicrosoftMultiTenantIdTokenValidator(
			registration("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"));

	@Test
	void acceptsATokenFromAnyTenantOnTheConfiguredCloud() {
		assertThat(this.validator.validate(idToken(TENANT_A)).hasErrors()).isFalse();
		assertThat(this.validator.validate(idToken(TENANT_B)).hasErrors()).isFalse();
	}

	@Test
	void rejectsAnIssuerThatIsNotATenantOfThatCloud() {
		// "common" is the endpoint you call, never an issuer a token comes back with.
		assertThat(this.validator.validate(idToken("https://login.microsoftonline.com/common/v2.0")).hasErrors())
			.isTrue();
		assertThat(this.validator.validate(idToken("https://accounts.google.com")).hasErrors()).isTrue();
		// A tenant-shaped path on the v1.0 host is still not a v2.0 issuer.
		assertThat(this.validator.validate(idToken("https://sts.windows.net/9188040d-6c67-4c5b-b112-36a304b66dad/"))
			.hasErrors()).isTrue();
	}

	@Test
	void rejectsAnIssuerThatIsNotEvenAUrl() {
		// The literal "{tenantid}" placeholder Entra's discovery document advertises
		// cannot
		// be parsed as a URL. It never appears in a real token — only in metadata — but
		// the
		// read must fail as invalid rather than throw out of the filter chain.
		Jwt unparseable = jwt(TENANT_A).claim("iss", "https://login.microsoftonline.com/{tenantid}/v2.0").build();

		assertThat(this.validator.validate(unparseable).hasErrors()).isTrue();
	}

	@Test
	void rejectsALookalikeHost() {
		// Same tenant-shaped path, attacker-controlled host.
		String lookalike = TENANT_A.replace("login.microsoftonline.com", "login.microsoftonline.com.evil.example");
		assertThat(this.validator.validate(idToken(lookalike)).hasErrors()).isTrue();
	}

	@Test
	void keepsTheAudienceCheck() {
		Jwt wrongAudience = jwt(TENANT_A).audience(List.of("someone-else")).build();

		OAuth2TokenValidatorResult result = this.validator.validate(wrongAudience);

		assertThat(result.hasErrors()).isTrue();
	}

	@Test
	void keepsTheExpiryCheck() {
		Instant issued = Instant.now().minus(20, ChronoUnit.MINUTES);
		Jwt expired = jwt(TENANT_A).issuedAt(issued).expiresAt(issued.plus(5, ChronoUnit.MINUTES)).build();

		assertThat(this.validator.validate(expired).hasErrors()).isTrue();
	}

	@Test
	void keepsTheRequiredClaimCheck() {
		Jwt noSubject = Jwt.withTokenValue("token")
			.header("alg", "RS256")
			.claim("iss", TENANT_A)
			.audience(List.of("client-id"))
			.issuedAt(Instant.now().minusSeconds(30))
			.expiresAt(Instant.now().plusSeconds(600))
			.build();

		assertThat(this.validator.validate(noSubject).hasErrors()).isTrue();
	}

	private static Jwt idToken(String issuer) {
		return jwt(issuer).build();
	}

	private static Jwt.Builder jwt(String issuer) {
		return Jwt.withTokenValue("token")
			.header("alg", "RS256")
			.claim("iss", issuer)
			.subject("subject")
			.audience(List.of("client-id"))
			.issuedAt(Instant.now().minusSeconds(30))
			.expiresAt(Instant.now().plusSeconds(600));
	}

	private static ClientRegistration registration(String authorizationUri) {
		return ClientRegistration.withRegistrationId("microsoft")
			.clientId("client-id")
			.clientSecret("client-secret")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.authorizationUri(authorizationUri)
			.tokenUri("https://login.microsoftonline.com/common/oauth2/v2.0/token")
			.issuerUri("https://login.microsoftonline.com/{tenantid}/v2.0")
			.scope("openid", "profile", "email")
			.build();
	}

}
