package org.alexmond.uniauth.examples.web;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
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

	public ApprovalController(ApprovalStore store) {
		this.store = store;
	}

	@GetMapping("/pending")
	public String pending(Authentication authentication, Model model) {
		model.addAttribute("name", (authentication != null) ? authentication.getName() : null);
		return "pending";
	}

	@GetMapping("/approvals")
	@PreAuthorize("hasRole('ADMIN')")
	public String queue(Model model) {
		model.addAttribute("waiting", this.store.pending().stream().map(PendingView::of).toList());
		return "approvals";
	}

	@PostMapping("/approvals")
	@PreAuthorize("hasRole('ADMIN')")
	public String decide(@RequestParam String provider, @RequestParam String principal, @RequestParam String outcome,
			Authentication approver) {
		ApprovalKey key = new ApprovalKey(provider, principal);
		if ("revoke".equals(outcome)) {
			this.store.remove(key);
		}
		else {
			this.store.decide(key, ApprovalStatus.valueOf(outcome), approver.getName());
		}
		return "redirect:/approvals";
	}

}
