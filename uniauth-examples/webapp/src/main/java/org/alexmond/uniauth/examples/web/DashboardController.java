package org.alexmond.uniauth.examples.web;

import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.examples.session.SessionFacts;
import org.alexmond.uniauth.examples.session.SessionFactsResolver;
import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalRecord;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.provider.MechanismResolver;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Pages that require a session. Reaching either of these while signed out lands you on
 * the starter's provider chooser.
 */
@Controller
public class DashboardController {

	private final AuthProviderRegistry registry;

	private final SessionFactsResolver resolver;

	/**
	 * Optional: the gate is a feature an application turns on, and the dashboard has to
	 * render either way. ObjectProvider rather than a required bean so this example still
	 * starts with {@code uniauth.approval.enabled=false}.
	 */
	private final ObjectProvider<ApprovalStore> approvals;

	private final MechanismResolver mechanisms;

	public DashboardController(AuthProviderRegistry registry, SessionFactsResolver resolver,
			ObjectProvider<ApprovalStore> approvals, MechanismResolver mechanisms) {
		this.registry = registry;
		this.resolver = resolver;
		this.approvals = approvals;
		this.mechanisms = mechanisms;
	}

	@GetMapping("/dashboard")
	public String dashboard(Authentication authentication, Model model) {
		SessionFacts facts = this.resolver.resolve(authentication);
		model.addAttribute("facts", facts);
		model.addAttribute("ports", this.registry.providers());
		model.addAttribute("live", facts.answeredBy());
		// Null when this provider is not behind the gate. The page reports which of the
		// two happened rather than staying silent: "approved by alice" and "no approval
		// needed" are different facts, and a blank space says neither.
		model.addAttribute("approval", approvalFor(authentication));
		return "dashboard";
	}

	/**
	 * Where {@code /session} used to be.
	 *
	 * <p>
	 * It showed the same session under a second heading, so the two pages read as one
	 * page duplicated. Kept as a redirect rather than deleted: it is a URL that has been
	 * linked to, and a 404 for a page whose content moved teaches nobody anything.
	 */
	@GetMapping("/session")
	public String session() {
		return "redirect:/dashboard";
	}

	private ApprovalRecord approvalFor(Authentication authentication) {
		ApprovalStore store = this.approvals.getIfAvailable();
		if (store == null || authentication == null) {
			return null;
		}
		ApprovalKey key = ApprovalKey.of(this.mechanisms.resolve(authentication), authentication);
		if (store.statusOf(key) != ApprovalStatus.APPROVED) {
			return null;
		}
		return store.find(key).orElse(null);
	}

}
