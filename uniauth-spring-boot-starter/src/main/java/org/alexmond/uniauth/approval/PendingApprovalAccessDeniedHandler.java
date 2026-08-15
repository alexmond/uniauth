package org.alexmond.uniauth.approval;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;

import java.io.IOException;

/**
 * Sends a signed-in but unapproved user to the waiting page instead of a bare 403.
 *
 * <p>
 * Only requests flagged by {@link ApprovalAuthorizationManager} are redirected;
 * everything else falls through to Spring's standard handler, so a genuine authorization
 * failure still looks like one.
 */
public class PendingApprovalAccessDeniedHandler implements AccessDeniedHandler {

	private final AccessDeniedHandler delegate = new AccessDeniedHandlerImpl();

	private final String pendingPage;

	public PendingApprovalAccessDeniedHandler(String pendingPage) {
		this.pendingPage = pendingPage;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		if (Boolean.TRUE.equals(request.getAttribute(ApprovalAuthorizationManager.PENDING_ATTRIBUTE))) {
			response.sendRedirect(request.getContextPath() + this.pendingPage);
			return;
		}
		this.delegate.handle(request, response, accessDeniedException);
	}

}
