package org.alexmond.uniauth.authserver.token;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the provider tells a client about entitlement.
 */
class RolesClaimTokenCustomizerTest {

	private final RolesClaimTokenCustomizer customizer = new RolesClaimTokenCustomizer();

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

	private JwtEncodingContext idTokenFor(String... authorities) {
		return contextFor(OidcParameterNames.ID_TOKEN, authorities);
	}

	private JwtEncodingContext contextFor(String tokenType, String... authorities) {
		return JwtEncodingContext
			.with(org.springframework.security.oauth2.jwt.JwsHeader
				.with(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256),
					JwtClaimsSet.builder()
						.subject("someone")
						.issuer("http://provider")
						.issuedAt(java.time.Instant.now())
						.expiresAt(java.time.Instant.now().plusSeconds(60)))
			.tokenType(new OAuth2TokenType(tokenType))
			.principal(new UsernamePasswordAuthenticationToken("someone", "n/a",
					AuthorityUtils.createAuthorityList(authorities)))
			.build();
	}

}
