package org.alexmond.uniauth.approval;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What an approver is told about the person they are admitting.
 *
 * <p>
 * The queue used to show the approval key and nothing else, which for a Google login is a
 * subject claim — a twenty-one digit number. These cases are the difference between
 * deciding about a person and deciding about a number.
 */
class PrincipalIdentityResolverTest {

	private final PrincipalIdentityResolver resolver = new PrincipalIdentityResolver();

	@Test
	void anOidcLoginBringsItsNameAndAddress() {
		PrincipalIdentity identity = this.resolver.resolve(oidc(Map.of("sub", "106681014797278784721", "name",
				"Alex Mond", "email", "alex@example.com", "email_verified", true)));

		assertThat(identity.displayName()).isEqualTo("Alex Mond");
		assertThat(identity.email()).isEqualTo("alex@example.com");
		assertThat(identity.emailVerified()).isTrue();
	}

	@Test
	void theSubjectIsKeptEvenWhenThereIsANameForIt() {
		// It is what approval is keyed on, so the page can show what is really being
		// admitted rather than only the friendly version of it.
		PrincipalIdentity identity = this.resolver
			.resolve(oidc(Map.of("sub", "106681014797278784721", "name", "Alex Mond")));

		assertThat(identity.subject()).isEqualTo("106681014797278784721");
	}

	@Test
	void anUnverifiedAddressIsReportedAsUnverifiedRatherThanAsAnAddress() {
		// The case that matters most: an address the provider will not stand behind is a
		// claim the user typed. Presenting it like a verified one invites admitting
		// whoever asserted somebody else's address.
		PrincipalIdentity identity = this.resolver
			.resolve(oidc(Map.of("sub", "s", "email", "someone@example.com", "email_verified", false)));

		assertThat(identity.email()).isEqualTo("someone@example.com");
		assertThat(identity.emailVerified()).isFalse();
	}

	@Test
	void aProviderThatSaysNothingAboutVerificationIsNotAssumedToHaveVerified() {
		PrincipalIdentity identity = this.resolver.resolve(oidc(Map.of("sub", "s", "email", "someone@example.com")));

		assertThat(identity.emailVerified()).isNull();
	}

	@Test
	void aProviderThatGivesNoAddressGivesNoAddress() {
		// Rather than an empty string, which would render as a blank cell and read as
		// though something was there.
		PrincipalIdentity identity = this.resolver.resolve(oidc(Map.of("sub", "s")));

		assertThat(identity.email()).isNull();
		assertThat(identity.displayName()).isNull();
	}

	@Test
	void aPlainOauth2LoginFallsBackToTheNamesItDoesHave() {
		// GitHub has no "name" for every account but always has a login.
		DefaultOAuth2User user = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"),
				Map.of("login", "octocat", "id", "1"), "login");

		PrincipalIdentity identity = this.resolver
			.resolve(new UsernamePasswordAuthenticationToken(user, "n/a", user.getAuthorities()));

		assertThat(identity.displayName()).isEqualTo("octocat");
	}

	@Test
	void aSamlAssertionBringsTheAttributesTheIdpReleased() {
		PrincipalIdentity identity = this.resolver.resolve(saml("G-abc-123", Map.of("urn:oid:2.5.4.42", List.of("Sam"),
				"urn:oid:2.5.4.4", List.of("Ortega"), "urn:oid:1.2.840.113549.1.9.1", List.of("sam@example.com"))));

		assertThat(identity.displayName()).isEqualTo("Sam Ortega");
		assertThat(identity.email()).isEqualTo("sam@example.com");
		assertThat(identity.subject()).isEqualTo("G-abc-123");
	}

	@Test
	void aSamlAddressIsNeverReportedAsVerified() {
		// SAML's attribute profile has no equivalent of email_verified, so there is
		// nothing to report. Assuming true is the dangerous direction: it would present
		// an
		// address nobody checked as though the provider stood behind it.
		PrincipalIdentity identity = this.resolver
			.resolve(saml("G-abc-123", Map.of("urn:oid:1.2.840.113549.1.9.1", List.of("sam@example.com"))));

		assertThat(identity.emailVerified()).isNull();
	}

	@Test
	void aSamlIdpThatReleasedNothingLeavesOnlyTheNameId() {
		// Which is the honest outcome, and the reason an IdP needs attribute mappers
		// configured before its users can be judged in an approval queue.
		PrincipalIdentity identity = this.resolver.resolve(saml("G-abc-123", Map.of()));

		assertThat(identity.displayName()).isNull();
		assertThat(identity.email()).isNull();
		assertThat(identity.subject()).isEqualTo("G-abc-123");
	}

	@Test
	void friendlyAttributeNamesAreAcceptedToo() {
		// Identity providers differ over whether they send OID URNs or friendly names.
		PrincipalIdentity identity = this.resolver.resolve(saml("G-abc-123",
				Map.of("displayName", List.of("Sasha Lindqvist"), "mail", List.of("sasha@example.com"))));

		assertThat(identity.displayName()).isEqualTo("Sasha Lindqvist");
		assertThat(identity.email()).isEqualTo("sasha@example.com");
	}

	@Test
	void anInternalAccountIsJustItsName() {
		PrincipalIdentity identity = this.resolver
			.resolve(new UsernamePasswordAuthenticationToken("alice", "n/a", List.of()));

		assertThat(identity.subject()).isEqualTo("alice");
		assertThat(identity.email()).isNull();
	}

	private static UsernamePasswordAuthenticationToken saml(String nameId, Map<String, List<Object>> attributes) {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(nameId, attributes);
		return new UsernamePasswordAuthenticationToken(principal, "n/a", List.of());
	}

	private static UsernamePasswordAuthenticationToken oidc(Map<String, Object> claims) {
		OidcIdToken token = new OidcIdToken("t", Instant.now(), Instant.now().plusSeconds(60), claims);
		DefaultOidcUser user = new DefaultOidcUser(AuthorityUtils.createAuthorityList("ROLE_USER"), token, "sub");
		return new UsernamePasswordAuthenticationToken(user, "n/a", user.getAuthorities());
	}

}
