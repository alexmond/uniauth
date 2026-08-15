package org.alexmond.uniauth.examples.web;

import org.alexmond.uniauth.examples.admin.UserStoreAdmin;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.List;
import java.util.Map;

/**
 * Creating accounts in whichever store backs a given mechanism.
 *
 * <p>
 * Restricted to {@code ROLE_ADMIN} — as with the approval queue, who may administer users
 * is the application's decision, not the library's.
 */
@Controller
public class AdminUserController {

	private final Map<AuthProviderType, UserStoreAdmin> stores = new LinkedHashMap<>();

	public AdminUserController(List<UserStoreAdmin> stores) {
		// Ordered the way the chooser lists them, so the page reads in the same order as
		// the login screen.
		for (AuthProviderType type : List.of(AuthProviderType.INTERNAL, AuthProviderType.LDAP,
				AuthProviderType.OAUTH2)) {
			stores.stream()
				.filter((store) -> store.mechanism() == type)
				.findFirst()
				.ifPresent((store) -> this.stores.put(type, store));
		}
	}

	@GetMapping("/admin/users")
	@PreAuthorize("hasRole('ADMIN')")
	public String users(Model model) {
		model.addAttribute("stores", this.stores.values());
		return "admin-users";
	}

	@PostMapping("/admin/users")
	@PreAuthorize("hasRole('ADMIN')")
	public String create(@RequestParam String mechanism, @RequestParam String username, @RequestParam String password,
			@RequestParam(required = false) String roles, RedirectAttributes redirect) {
		UserStoreAdmin store = this.stores.get(AuthProviderType.valueOf(mechanism));
		if (store == null) {
			redirect.addFlashAttribute("error", "No store backs " + mechanism);
			return "redirect:/admin/users";
		}
		try {
			store.create(username.trim(), password, parseRoles(roles));
			redirect.addFlashAttribute("created",
					"Created " + username.trim() + " in the " + store.displayName().toLowerCase(Locale.ROOT) + ".");
		}
		catch (IllegalArgumentException | IllegalStateException ex) {
			// Both are "you asked for something this store cannot do", and the message
			// says which — worth showing rather than a generic failure.
			redirect.addFlashAttribute("error", ex.getMessage());
		}
		return "redirect:/admin/users";
	}

	private static List<String> parseRoles(String roles) {
		if (roles == null || roles.isBlank()) {
			return List.of("USER");
		}
		return Arrays.stream(roles.split(",")).map(String::trim).filter((role) -> !role.isEmpty()).toList();
	}

}
