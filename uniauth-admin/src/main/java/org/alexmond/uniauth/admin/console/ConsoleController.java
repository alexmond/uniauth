package org.alexmond.uniauth.admin.console;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.alexmond.uniauth.admin.store.ConsoleUser;
import org.alexmond.uniauth.admin.store.StoreException;
import org.alexmond.uniauth.admin.store.UserStore;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * The console: pick a store, see who is in it, add, edit or remove.
 *
 * <p>
 * Every page needs {@code ROLE_ADMIN} of <em>this</em> console — a separate population
 * from the accounts being administered, which is the point of running it as its own
 * application. An administrator here has no session anywhere else.
 */
@Controller
public class ConsoleController {

	private final List<UserStore> stores;

	public ConsoleController(List<UserStore> stores) {
		this.stores = stores;
	}

	@GetMapping("/")
	@PreAuthorize("hasRole('ADMIN')")
	public String index(Model model) {
		model.addAttribute("stores", this.stores);
		return "stores";
	}

	@GetMapping("/stores/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public String store(@PathVariable String id, Model model, RedirectAttributes redirect) {
		Optional<UserStore> store = find(id);
		if (store.isEmpty()) {
			redirect.addFlashAttribute("error", "No store called " + id);
			return "redirect:/";
		}
		model.addAttribute("store", store.get());
		try {
			model.addAttribute("users", store.get().users());
		}
		catch (StoreException ex) {
			// An unreachable store renders as a message on its own page. An empty table
			// with no explanation reads as "nobody is in this store", which is a
			// different and much more alarming thing than "I could not ask".
			model.addAttribute("users", List.<ConsoleUser>of());
			model.addAttribute("error", ex.getMessage());
		}
		return "store";
	}

	@PostMapping("/stores/{id}/users")
	@PreAuthorize("hasRole('ADMIN')")
	public String create(@PathVariable String id, @RequestParam String username, @RequestParam String password,
			@RequestParam(required = false) String roles, RedirectAttributes redirect) {
		return act(id, redirect, (store) -> {
			store.create(username.trim(), password, parseRoles(roles));
			return "Created " + username.trim() + ".";
		});
	}

	@PostMapping("/stores/{id}/users/{username}/password")
	@PreAuthorize("hasRole('ADMIN')")
	public String changePassword(@PathVariable String id, @PathVariable String username, @RequestParam String password,
			RedirectAttributes redirect) {
		return act(id, redirect, (store) -> {
			store.setPassword(username, password);
			return "Changed the password for " + username + ".";
		});
	}

	@PostMapping("/stores/{id}/users/{username}/roles")
	@PreAuthorize("hasRole('ADMIN')")
	public String changeRoles(@PathVariable String id, @PathVariable String username,
			@RequestParam(required = false) String roles, RedirectAttributes redirect) {
		return act(id, redirect, (store) -> {
			store.setRoles(username, parseRoles(roles));
			return "Updated the roles for " + username + ".";
		});
	}

	@PostMapping("/stores/{id}/users/{username}/delete")
	@PreAuthorize("hasRole('ADMIN')")
	public String delete(@PathVariable String id, @PathVariable String username, RedirectAttributes redirect) {
		return act(id, redirect, (store) -> {
			store.delete(username);
			return "Removed " + username + ".";
		});
	}

	/**
	 * Runs an operation against a store and turns its outcome into a flash message.
	 *
	 * <p>
	 * Every write goes through here so that a refusal from the far side reaches the
	 * screen as a sentence rather than an error page. The stores raise
	 * {@link StoreException} with a message already written for an operator.
	 */
	private String act(String id, RedirectAttributes redirect, Operation operation) {
		Optional<UserStore> store = find(id);
		if (store.isEmpty()) {
			redirect.addFlashAttribute("error", "No store called " + id);
			return "redirect:/";
		}
		try {
			redirect.addFlashAttribute("done", operation.apply(store.get()));
		}
		catch (StoreException ex) {
			redirect.addFlashAttribute("error", ex.getMessage());
		}
		return "redirect:/stores/" + id;
	}

	private Optional<UserStore> find(String id) {
		return this.stores.stream().filter((store) -> store.id().equals(id)).findFirst();
	}

	private static List<String> parseRoles(String roles) {
		if (roles == null || roles.isBlank()) {
			return List.of("USER");
		}
		return Arrays.stream(roles.split(",")).map(String::trim).filter((role) -> !role.isEmpty()).toList();
	}

	@FunctionalInterface
	private interface Operation {

		String apply(UserStore store);

	}

}
