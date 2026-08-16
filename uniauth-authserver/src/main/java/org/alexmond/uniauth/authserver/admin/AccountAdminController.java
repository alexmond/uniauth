package org.alexmond.uniauth.authserver.admin;

import org.alexmond.uniauth.authserver.user.AccountStore;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Managing this provider's own accounts, for a console running elsewhere.
 *
 * <p>
 * The API belongs here rather than in the applications that trust this provider: these
 * are its accounts, and it is the only thing that can change them. That is the correction
 * this service exists to make — a client library had no business carrying an endpoint
 * that creates users.
 */
@RestController
public class AccountAdminController {

	private final AccountStore accounts;

	public AccountAdminController(AccountStore accounts) {
		this.accounts = accounts;
	}

	@GetMapping("${authserver.admin-api.path:/admin/api}/users")
	public List<AccountStore.Account> users() {
		return this.accounts.accounts();
	}

	@PostMapping("${authserver.admin-api.path:/admin/api}/users")
	public ResponseEntity<Map<String, String>> create(@RequestBody CreateAccount request) {
		if (isBlank(request.username()) || isBlank(request.password())) {
			return problem(HttpStatus.BAD_REQUEST, "username and password are both required");
		}
		return attempt(
				() -> this.accounts.create(request.username().trim(), request.password(), request.rolesOrDefault()),
				HttpStatus.CREATED, Map.of("created", request.username().trim()));
	}

	/**
	 * Password, roles, or both. Each is applied only when present, so a console can offer
	 * the two separately without inventing a value for the one it is not touching.
	 */
	@PutMapping("${authserver.admin-api.path:/admin/api}/users/{username}")
	public ResponseEntity<Map<String, String>> update(@PathVariable String username,
			@RequestBody UpdateAccount request) {
		if (isBlank(request.password()) && request.roles() == null) {
			return problem(HttpStatus.BAD_REQUEST, "send a password, roles, or both");
		}
		return attempt(() -> {
			if (!isBlank(request.password())) {
				this.accounts.updatePassword(username, request.password());
			}
			if (request.roles() != null) {
				this.accounts.updateRoles(username, request.roles());
			}
		}, HttpStatus.OK, Map.of("updated", username));
	}

	@DeleteMapping("${authserver.admin-api.path:/admin/api}/users/{username}")
	public ResponseEntity<Map<String, String>> delete(@PathVariable String username) {
		return attempt(() -> this.accounts.delete(username), HttpStatus.OK, Map.of("deleted", username));
	}

	private static ResponseEntity<Map<String, String>> attempt(Runnable operation, HttpStatus success,
			Map<String, String> body) {
		try {
			operation.run();
		}
		catch (IllegalArgumentException ex) {
			// No such account, or the name is taken. Either way the caller asked for
			// something that cannot be, and the message says which.
			return problem(HttpStatus.CONFLICT, ex.getMessage());
		}
		return ResponseEntity.status(success).body(body);
	}

	private static ResponseEntity<Map<String, String>> problem(HttpStatus status, String message) {
		return ResponseEntity.status(status).body(Map.of("error", String.valueOf(message)));
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	/**
	 * @param username the account name
	 * @param password the initial password, in clear
	 * @param roles authorities to grant; defaults to USER when absent
	 */
	public record CreateAccount(String username, String password, List<String> roles) {

		List<String> rolesOrDefault() {
			return (this.roles == null || this.roles.isEmpty()) ? List.of("USER") : this.roles;
		}
	}

	/**
	 * @param password a new password, or {@code null} to keep the current one
	 * @param roles authorities to set, or {@code null} to leave them alone
	 */
	public record UpdateAccount(String password, List<String> roles) {
	}

}
