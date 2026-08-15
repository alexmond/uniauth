package org.alexmond.uniauth.admin;

import org.alexmond.uniauth.provider.AuthProviderType;

import java.util.List;

/**
 * Asking the management API to create an account.
 *
 * @param mechanism which store to create it in
 * @param username the account name
 * @param password the initial password, in clear — which is why the API is expected to be
 * on a trusted network and is refused without a token
 * @param roles granted authorities; stores that derive them elsewhere (LDAP, from group
 * membership) ignore this
 */
public record CreateUserRequest(AuthProviderType mechanism, String username, String password, List<String> roles) {

	List<String> rolesOrDefault() {
		return (this.roles == null || this.roles.isEmpty()) ? List.of("USER") : this.roles;
	}

}
