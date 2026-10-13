package org.alexmond.uniauth.web;

import java.time.Clock;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationStatus;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.invitation.InvitationToken;
import org.alexmond.uniauth.invitation.Invitations;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Where an invitation URL lands.
 *
 * <p>
 * It does not claim anything. Redemption lives in {@code ApprovalAuthorizationManager},
 * the one place every request passes exactly once; this endpoint only validates the token
 * and puts it on the session, so the ordinary sign-in follows and the gate does the rest.
 * Four mechanisms would otherwise mean four success handlers.
 *
 * <p>
 * The path is permitted on the starter's chain, because it has to work before anybody has
 * logged in. A token that is not usable goes to the chooser with a {@code ?invite=}
 * reason rather than to a page of its own — #11 happened because the starter redirected
 * somewhere it never served, and the consumer got {@code ERR_TOO_MANY_REDIRECTS}. An
 * {@code outcome-page} property would be that mistake with a new name.
 *
 * <p>
 * Registered as a bean rather than component-scanned, so {@code uniauth.enabled=false}
 * genuinely backs off.
 */
@Controller
public class UniAuthInvitationController {

	private final InvitationStore store;

	private final UniAuthProperties properties;

	private final Clock clock;

	/**
	 * Creates the controller.
	 * @param store where invitations are looked up
	 * @param properties supplies the chooser path, the success path, and the configured
	 * invitation path the confirmation form posts back to
	 * @param clock judges expiry; injectable so a test need not sleep
	 */
	public UniAuthInvitationController(InvitationStore store, UniAuthProperties properties, Clock clock) {
		this.store = store;
		this.properties = properties;
		this.clock = clock;
	}

	/**
	 * Opens an invitation.
	 *
	 * <p>
	 * Everybody gets the same page, and this method changes nothing. The URL is the
	 * credential: whoever holds it gets the record it names, and that is inherent to link
	 * invitations. What the page buys is that a hijack — or a mis-sent link opened by the
	 * wrong colleague — is deliberate rather than accidental, and that only holds if
	 * accepting is an act somebody actually took. A GET cannot be CSRF-protected, so a
	 * GET that stashed would let another site plant its invitation in a visitor's session
	 * and skip this page altogether.
	 *
	 * <p>
	 * An anonymous visitor is told to accept and then sign in; somebody already signed in
	 * is shown which account they would be accepting as. The second is also the recovery
	 * path for a session lost mid-login: the invitation is still unclaimed, so accepting
	 * claims it without a second sign-in.
	 * @param token the token from the path
	 * @param authentication whoever is asking, {@code null} when nobody is
	 * @param request the current request, unchanged by this method
	 * @param model receives what the page renders
	 * @return a redirect for a token that cannot be used, or the acceptance view
	 */
	@GetMapping("${uniauth.approval.invitations.path:/invite/{token}}")
	public String open(@PathVariable String token,
			@CurrentSecurityContext(expression = "authentication") Authentication authentication,
			HttpServletRequest request, Model model) {
		Optional<Invitation> open = usable(token);
		if (open.isEmpty()) {
			return chooser(reasonFor(token));
		}
		// This GET touches nothing. Accepting is a POST, which carries a CSRF token;
		// stashing here would be a state change on a method that cannot be protected, and
		// an attacker's page could fire it with an img tag to plant their invitation in a
		// visitor's session. That visitor would then sign in with their own account and
		// be
		// bound to the record the attacker's invitation names, never seeing this page.
		model.addAttribute("signedInAs", isAuthenticated(authentication) ? authentication.getName() : null);
		model.addAttribute("invitePath", this.properties.getApproval().getInvitations().getPath());
		model.addAttribute("token", open.get().token().value());
		// Deliberately not the subjectRef. The visitor may not be the invited person, and
		// it is the application's own identifier for somebody else.
		return "uniauth/invite";
	}

	/**
	 * Accepts the confirmation.
	 *
	 * <p>
	 * Stashes the token and sends the caller on. The next request passes authorization,
	 * and that is where the claim happens.
	 * @param token the token from the path
	 * @param authentication whoever confirmed, {@code null} when nobody is signed in — in
	 * which case there was nothing to confirm, and they are sent to the chooser to sign
	 * in as the flow intends
	 * @param request the current request, whose session carries the token onwards
	 * @return a redirect
	 */
	@PostMapping("${uniauth.approval.invitations.path:/invite/{token}}")
	public String confirm(@PathVariable String token,
			@CurrentSecurityContext(expression = "authentication") Authentication authentication,
			HttpServletRequest request) {
		Optional<Invitation> open = usable(token);
		if (open.isEmpty()) {
			return chooser(reasonFor(token));
		}
		Invitations.stash(request, open.get().token());
		return isAuthenticated(authentication) ? "redirect:" + this.properties.getDefaultSuccessUrl() : chooser(null);
	}

	/**
	 * The invitation behind a token, if it can still be used.
	 *
	 * <p>
	 * Every rejection collapses to {@link Optional#empty}, including token text that is
	 * blank or absurd. A token arriving from a URL is attacker-controlled and most of
	 * them are typos and scanners, so none of it may become an error page.
	 */
	private Optional<Invitation> usable(String token) {
		if (!StringUtils.hasText(token)) {
			return Optional.empty();
		}
		return this.store.find(InvitationToken.of(token))
			.filter((invitation) -> invitation.status(this.clock.instant()) == InvitationStatus.OPEN);
	}

	/** The reason to show, for a token that could not be used. */
	private String reasonFor(String token) {
		if (!StringUtils.hasText(token)) {
			return "unknown";
		}
		return this.store.find(InvitationToken.of(token))
			.map((invitation) -> invitation.status(this.clock.instant()).name().toLowerCase(java.util.Locale.ROOT))
			.orElse("unknown");
	}

	/**
	 * A redirect to the chooser, which the starter definitely serves.
	 *
	 * <p>
	 * Returned as a view name rather than written with {@code sendRedirect}, so Spring
	 * prepends the servlet context path — an application mounted under one would
	 * otherwise send its visitors outside itself.
	 */
	private String chooser(String reason) {
		String path = this.properties.getLoginPage();
		return (reason != null) ? "redirect:" + path + "?invite=" + reason : "redirect:" + path;
	}

	private static boolean isAuthenticated(Authentication authentication) {
		return authentication != null && authentication.isAuthenticated()
				&& !(authentication instanceof org.springframework.security.authentication.AnonymousAuthenticationToken);
	}

}
