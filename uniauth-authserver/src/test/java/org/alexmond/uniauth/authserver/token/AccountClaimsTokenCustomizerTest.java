package org.alexmond.uniauth.authserver.token;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.alexmond.uniauth.authserver.user.AccountStore;
import org.alexmond.uniauth.authserver.user.AuthServerProperties;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the provider tells a client about an account.
 */
class AccountClaimsTokenCustomizerTest {

	private final AccountStore accounts = new AccountStore(NoOpPasswordEncoder.getInstance(),
			new AuthServerProperties());

	private final AccountClaimsTokenCustomizer customizer = new AccountClaimsTokenCustomizer(this.accounts);

	private static final Set<String> ALL_SCOPES = Set.of("openid", "profile", "email");

	@Test
	void anIdTokenCarriesTheAccountsRoles() {
		JwtEncodingContext context = idTokenFor("ROLE_ADMIN", "ROLE_USER");

		this.customizer.customize(context);

		List<String> roles = context.getClaims().build().getClaim("roles");
		assertThat(roles).containsExactly("ROLE_ADMIN", "ROLE_USER");
	}

	@Test
	void nonRoleAuthoritiesAreNotReported() {
		// SCOPE_openid and friends are not entitlements at the client, and sending them
		// as roles would let a scope masquerade as one.
		JwtEncodingContext context = idTokenFor("SCOPE_openid", "ROLE_USER");

		this.customizer.customize(context);

		List<String> roles = context.getClaims().build().getClaim("roles");
		assertThat(roles).containsExactly("ROLE_USER");
	}

	@Test
	void anAccessTokenIsLeftAlone() {
		// It is a bearer credential for APIs, and this provider fronts none that
		// authorize
		// by role.
		JwtEncodingContext context = contextFor(OAuth2TokenType.ACCESS_TOKEN.getValue(), "ROLE_ADMIN");

		this.customizer.customize(context);

		assertThat(context.getClaims().build().hasClaim("roles")).isFalse();
	}

	@Test
	void theProfileClaimsComeFromTheAccount() {
		this.accounts.create("olivia", "pw", List.of("USER"),
				new AccountStore.Profile("Olivia Okonkwo", "olivia@example.com", true));
		JwtEncodingContext context = idTokenForAccount("olivia", "ROLE_USER");

		this.customizer.customize(context);

		JwtClaimsSet claims = context.getClaims().build();
		String name = claims.getClaim("name");
		String email = claims.getClaim("email");
		assertThat(name).isEqualTo("Olivia Okonkwo");
		assertThat(email).isEqualTo("olivia@example.com");
		assertThat((Boolean) claims.getClaim("email_verified")).isTrue();
	}

	@Test
	void anUnverifiedAddressIsSentAsUnverifiedRatherThanWithheld() {
		// Withholding it would leave an approver with nothing; sending it unmarked would
		// let them mistake a claim for evidence. Both, honestly labelled.
		this.accounts.create("dana", "pw", List.of("USER"),
				new AccountStore.Profile("Dana Whitlock", "dana@example.com", false));
		JwtEncodingContext context = idTokenForAccount("dana", "ROLE_USER");

		this.customizer.customize(context);

		JwtClaimsSet claims = context.getClaims().build();
		String email = claims.getClaim("email");
		assertThat(email).isEqualTo("dana@example.com");
		assertThat((Boolean) claims.getClaim("email_verified")).isFalse();
	}

	@Test
	void aClientThatDidNotAskForEmailIsNotGivenOne() {
		// The scope is the authorisation. A provider that hands the address over anyway
		// has turned it into decoration.
		this.accounts.create("olivia", "pw", List.of("USER"),
				new AccountStore.Profile("Olivia Okonkwo", "olivia@example.com", true));
		JwtEncodingContext context = contextFor(OidcParameterNames.ID_TOKEN, "olivia", Set.of("openid"), "ROLE_USER");

		this.customizer.customize(context);

		JwtClaimsSet claims = context.getClaims().build();
		assertThat(claims.hasClaim("email")).isFalse();
		assertThat(claims.hasClaim("name")).isFalse();
	}

	@Test
	void anAccountWithNoProfileGetsNoProfileClaims() {
		this.accounts.create("plain", "pw", List.of("USER"));
		JwtEncodingContext context = idTokenForAccount("plain", "ROLE_USER");

		this.customizer.customize(context);

		assertThat(context.getClaims().build().hasClaim("email")).isFalse();
	}

	private JwtEncodingContext idTokenForAccount(String username, String... authorities) {
		return contextFor(OidcParameterNames.ID_TOKEN, username, ALL_SCOPES, authorities);
	}

	private JwtEncodingContext idTokenFor(String... authorities) {
		return contextFor(OidcParameterNames.ID_TOKEN, "someone", ALL_SCOPES, authorities);
	}

	private JwtEncodingContext contextFor(String tokenType, String... authorities) {
		return contextFor(tokenType, "someone", ALL_SCOPES, authorities);
	}

	private JwtEncodingContext contextFor(String tokenType, String username, Set<String> scopes,
			String... authorities) {
		return JwtEncodingContext
			.with(JwsHeader.with(SignatureAlgorithm.RS256),
					JwtClaimsSet.builder()
						.subject(username)
						.issuer("http://provider")
						.issuedAt(Instant.now())
						.expiresAt(Instant.now().plusSeconds(60)))
			.authorizedScopes(scopes)
			.tokenType(new OAuth2TokenType(tokenType))
			.principal(new UsernamePasswordAuthenticationToken(username, "n/a",
					AuthorityUtils.createAuthorityList(authorities)))
			.build();
	}

}
