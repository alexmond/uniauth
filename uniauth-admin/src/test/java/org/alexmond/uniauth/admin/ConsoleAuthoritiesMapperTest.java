package org.alexmond.uniauth.admin;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Whether a provider account is allowed to administer this console.
 */
class ConsoleAuthoritiesMapperTest {

	private final ConsoleAuthoritiesMapper mapper = new ConsoleAuthoritiesMapper();

	@Test
	void aProviderAdministratorBecomesAConsoleAdministrator() {
		var mapped = this.mapper.mapAuthorities(List.of(authority(List.of("ROLE_USER", "ROLE_ADMIN"))));

		assertThat(mapped).extracting(GrantedAuthority::getAuthority).contains("ROLE_ADMIN", "ROLE_USER");
	}

	@Test
	void anOrdinaryProviderAccountDoesNotGetAdmin() {
		// It still signs in — it simply cannot reach anything, which is a permissions
		// decision rather than a failed login.
		var mapped = this.mapper.mapAuthorities(List.of(authority(List.of("ROLE_USER"))));

		assertThat(mapped).extracting(GrantedAuthority::getAuthority).doesNotContain("ROLE_ADMIN");
	}

	@Test
	void anAccountWithNoRolesClaimIsUnchanged() {
		var authority = new OidcUserAuthority(
				new OidcIdToken("t", Instant.now(), Instant.now().plusSeconds(60), Map.of("sub", "someone")));

		var mapped = this.mapper.mapAuthorities(List.of(authority));

		assertThat(mapped).hasSize(1).extracting(GrantedAuthority::getAuthority).containsExactly("OIDC_USER");
	}

	@Test
	void aProviderCannotInventAnAuthorityOfItsOwnChoosing() {
		// Only ROLE_-prefixed values are honoured, so a claim carrying anything else
		// cannot smuggle in an authority this console might check for elsewhere.
		var mapped = this.mapper.mapAuthorities(List.of(authority(List.of("ADMIN", "console:write"))));

		assertThat(mapped).extracting(GrantedAuthority::getAuthority).doesNotContain("ADMIN", "console:write");
	}

	@Test
	void authoritiesTheChainAlreadyGrantedAreKept() {
		var existing = new SimpleGrantedAuthority("SCOPE_openid");

		var mapped = this.mapper.mapAuthorities(List.of(existing, authority(List.of("ROLE_ADMIN"))));

		assertThat(mapped).extracting(GrantedAuthority::getAuthority).contains("SCOPE_openid", "ROLE_ADMIN");
	}

	private static OidcUserAuthority authority(List<String> roles) {
		return new OidcUserAuthority(new OidcIdToken("t", Instant.now(), Instant.now().plusSeconds(60),
				Map.of("sub", "someone", "roles", roles)));
	}

}
