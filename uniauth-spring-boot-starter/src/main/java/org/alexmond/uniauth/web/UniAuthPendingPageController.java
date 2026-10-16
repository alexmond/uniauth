package org.alexmond.uniauth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.ParameterizableViewController;

/**
 * The waiting room a held principal is redirected to.
 *
 * <p>
 * <strong>Not a {@code @Controller}, and that is the whole design of it.</strong> The
 * gate has always redirected to {@code uniauth.approval.pending-page} without the starter
 * serving anything there, so the documented answer was for the application to supply the
 * page — which applications did, mapping {@code /pending} themselves (#11). A
 * {@code @RequestMapping} on the same path would then be an ambiguous mapping and fail
 * their context at startup: a page shipped to help them would break every application
 * that had already worked around its absence.
 *
 * <p>
 * A view controller behind a {@code SimpleUrlHandlerMapping} is ordered after
 * {@code RequestMappingHandlerMapping}, so an application's own mapping simply wins and
 * this is never consulted. Nothing to exclude, nothing to configure — which is why the
 * {@code uniauth-examples/webapp} tree still serves its own richer waiting page with no
 * change at all. {@code UniAuthPendingPageOverriddenTest} is what holds that ordering in
 * place.
 *
 * @see org.springframework.web.servlet.mvc.ParameterizableViewController
 */
public class UniAuthPendingPageController extends ParameterizableViewController {

	/**
	 * The view is set by whoever registers this, from
	 * {@code uniauth.approval.pending-view} — not a constant here, for two reasons.
	 * {@code setViewName} is overridable, so calling it from a constructor would let a
	 * subclass see a half-built object; and the pending <em>page</em> was always
	 * configuration, so the view rendered on it should be too rather than being the one
	 * thing in this flow an application cannot name.
	 */
	@Override
	protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		ModelAndView view = super.handleRequestInternal(request, response);
		// Which account is waiting, not merely that one is. Somebody signed in with the
		// wrong Google account cannot tell from "you are awaiting approval" that they
		// should sign out and come back as somebody else — and that is the one thing they
		// can actually do from here.
		view.addObject("signedInAs", nameOfWhoeverIsWaiting());
		return view;
	}

	/**
	 * The authenticated name, or {@code null} when there is nobody to name.
	 *
	 * <p>
	 * Anonymous is {@code null} rather than {@code "anonymousUser"}: the page is
	 * permitted to everybody, so it can be opened by somebody not signed in at all, and
	 * printing that string at them would be worse than printing nothing.
	 * @return the name, or {@code null}
	 */
	private static String nameOfWhoeverIsWaiting() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()
				|| authentication instanceof AnonymousAuthenticationToken) {
			return null;
		}
		return authentication.getName();
	}

}
