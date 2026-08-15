package org.alexmond.uniauth.admin.console;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The console: pick an application, see what it can administer, add an account.
 *
 * <p>
 * Every page needs {@code ROLE_ADMIN} of <em>this</em> console — a separate population
 * from the users being administered, which is the point of running it as its own
 * application.
 */
@Controller
public class ConsoleController {

	private final ManagedApplication managed;

	private final ManagedAppClient client;

	public ConsoleController(ManagedApplication managed, ManagedAppClient client) {
		this.managed = managed;
		this.client = client;
	}

	@GetMapping("/")
	@PreAuthorize("hasRole('ADMIN')")
	public String targets(Model model) {
		model.addAttribute("targets", this.managed.getTargets());
		return "targets";
	}

	@GetMapping("/apps/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public String stores(@PathVariable String id, Model model, RedirectAttributes redirect) {
		Optional<ManagedApplication.Target> target = find(id);
		if (target.isEmpty()) {
			redirect.addFlashAttribute("error", "No managed application called " + id);
			return "redirect:/";
		}
		model.addAttribute("target", target.get());
		try {
			model.addAttribute("stores", this.client.stores(target.get()));
		}
		catch (RuntimeException ex) {
			// An unreachable application should render as a message on its own page, not
			// a
			// stack trace or an empty screen that looks like "no stores".
			model.addAttribute("stores", List.of());
			model.addAttribute("error", target.get().getName() + " is not answering: " + ex.getMessage());
		}
		return "stores";
	}

	@PostMapping("/apps/{id}/users")
	@PreAuthorize("hasRole('ADMIN')")
	public String create(@PathVariable String id, @RequestParam String mechanism, @RequestParam String username,
			@RequestParam String password, @RequestParam(required = false) String roles, RedirectAttributes redirect) {
		Optional<ManagedApplication.Target> target = find(id);
		if (target.isEmpty()) {
			redirect.addFlashAttribute("error", "No managed application called " + id);
			return "redirect:/";
		}
		Optional<String> failure = this.client.createUser(target.get(), mechanism, username.trim(), password,
				parseRoles(roles));
		if (failure.isPresent()) {
			redirect.addFlashAttribute("error", failure.get());
		}
		else {
			redirect.addFlashAttribute("created", "Created " + username.trim() + " on " + target.get().getName() + ".");
		}
		return "redirect:/apps/" + id;
	}

	private Optional<ManagedApplication.Target> find(String id) {
		return this.managed.getTargets().stream().filter((target) -> target.getId().equals(id)).findFirst();
	}

	private static List<String> parseRoles(String roles) {
		if (roles == null || roles.isBlank()) {
			return List.of("USER");
		}
		return Arrays.stream(roles.split(",")).map(String::trim).filter((role) -> !role.isEmpty()).toList();
	}

}
