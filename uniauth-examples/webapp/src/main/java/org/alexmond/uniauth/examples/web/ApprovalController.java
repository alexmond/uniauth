package org.alexmond.uniauth.examples.web;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStatus;
import java.util.Arrays;
import java.util.List;

import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * The two ends of the approval flow: the room people wait in, and the desk where someone
 * lets them out of it.
 *
 * <p>
 * The waiting page is reachable by unapproved users — the starter permits it
 * automatically — while the queue is not. Restricting the queue is the application's job,
 * not the library's: UniAuth answers "are you approved", and who gets to approve is a
 * decision only the app can make. Here that is {@code ROLE_ADMIN}, enforced with method
 * security.
 */
@Controller
public class ApprovalController {

	private final ApprovalStore store;

	private final UniAuthProperties properties;

	public ApprovalController(ApprovalStore store, UniAuthProperties properties) {
		this.store = store;
		this.properties = properties;
	}

	@GetMapping("/pending")
	public String pending(Authentication authentication, Model model) {
		model.addAttribute("name", (authentication != null) ? authentication.getName() : null);
		return "pending";
	}

	@GetMapping("/approvals")
	@PreAuthorize("hasRole('ADMIN')")
	public String queue(Model model) {
		// One method answers the whole page. Before list() the store could only be
		// asked who was waiting, so the two tables below did not exist and access
		// granted was never access reviewed — nobody could see who had access, what
		// they could do with it, or pick somebody to revoke without already knowing
		// their key by heart (#10).
		model.addAttribute("waiting", this.store.list(ApprovalStatus.PENDING).stream().map(PendingView::of).toList());
		model.addAttribute("admitted", this.store.list(ApprovalStatus.APPROVED).stream().map(AccessView::of).toList());
		model.addAttribute("refused", this.store.list(ApprovalStatus.DENIED).stream().map(AccessView::of).toList());
		return "approvals";
	}

	@PostMapping("/approvals")
	@PreAuthorize("hasRole('ADMIN')")
	public String decide(@RequestParam String provider, @RequestParam String principal, @RequestParam String outcome,
			@RequestParam(required = false) String roles, Authentication approver) {
		ApprovalKey key = new ApprovalKey(provider, principal);
		if ("revoke".equals(outcome)) {
			this.store.remove(key);
		}
		else {
			// What the approver grants, not merely whether they let them in. A federated
			// principal arrives with no ROLE_ of its own, so this is the only place its
			// roles can come from — approve with nothing and it falls back to the
			// configured default rather than admitting somebody who can do nothing.
			this.store.decide(key, ApprovalStatus.valueOf(outcome), approver.getName(), parseRoles(roles));
		}
		return "redirect:/approvals";
	}

	private List<String> parseRoles(String roles) {
		if (roles == null || roles.isBlank()) {
			return this.properties.getApproval().getDefaultRoles();
		}
		return Arrays.stream(roles.split(",")).map(String::trim).filter((role) -> !role.isEmpty()).toList();
	}

}
