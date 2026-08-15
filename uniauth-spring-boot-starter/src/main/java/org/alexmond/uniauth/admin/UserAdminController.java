package org.alexmond.uniauth.admin;

import org.alexmond.uniauth.provider.AuthProviderType;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The management API: what stores this application has, and a way to add accounts to
 * them.
 *
 * <p>
 * Exposes whatever {@link UserStoreAdmin} beans the application publishes and nothing
 * else, so an application that wants only its directory administrable publishes only that
 * one. With no such beans the API answers with an empty list rather than failing —
 * "nothing is administrable here" is a legitimate answer.
 *
 * <p>
 * Authentication is the token chain in {@code AdminApiConfiguration}, not the
 * application's own login. A console is not a person and has no session.
 */
@RestController
public class UserAdminController {

	private final List<UserStoreAdmin> stores;

	public UserAdminController(List<UserStoreAdmin> stores) {
		this.stores = stores;
	}

	@GetMapping("${uniauth.admin-api.path:/uniauth/admin}/stores")
	public List<UserStoreSummary> stores() {
		return this.stores.stream().map(UserStoreSummary::of).toList();
	}

	@PostMapping("${uniauth.admin-api.path:/uniauth/admin}/users")
	public ResponseEntity<Map<String, String>> create(@RequestBody CreateUserRequest request) {
		if (request.mechanism() == null || isBlank(request.username()) || isBlank(request.password())) {
			return problem(HttpStatus.BAD_REQUEST, "mechanism, username and password are all required");
		}
		Optional<UserStoreAdmin> store = find(request.mechanism());
		if (store.isEmpty()) {
			return problem(HttpStatus.NOT_FOUND, "no store backs " + request.mechanism() + " in this application");
		}
		try {
			store.get().create(request.username().trim(), request.password(), request.rolesOrDefault());
		}
		catch (IllegalArgumentException ex) {
			// The name is taken. A console should show this, not a generic failure.
			return problem(HttpStatus.CONFLICT, ex.getMessage());
		}
		catch (IllegalStateException ex) {
			// The store could not be written to — a directory refusing the entry, say.
			return problem(HttpStatus.BAD_GATEWAY, ex.getMessage());
		}
		return ResponseEntity.status(HttpStatus.CREATED)
			.body(Map.of("created", request.username().trim(), "mechanism", request.mechanism().name()));
	}

	private Optional<UserStoreAdmin> find(AuthProviderType mechanism) {
		return this.stores.stream().filter((store) -> store.mechanism() == mechanism).findFirst();
	}

	private static ResponseEntity<Map<String, String>> problem(HttpStatus status, String message) {
		return ResponseEntity.status(status).body(Map.of("error", message));
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

}
