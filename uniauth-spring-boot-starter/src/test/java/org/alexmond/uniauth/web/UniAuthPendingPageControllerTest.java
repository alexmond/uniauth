package org.alexmond.uniauth.web;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.ModelAndView;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Who the waiting page says is waiting, for each thing the context can hold.
 *
 * <p>
 * The page is permitted to everybody — it has to be, or the gate would keep people out of
 * the page it sends them to — so it is reachable by somebody who is not signed in at all,
 * and by a request whose context was never populated. Those answers are not reachable
 * through the chain in an integration test, because {@code AnonymousAuthenticationFilter}
 * always leaves a token behind, so they are asserted here on the rule itself rather than
 * left to a comment claiming they hold.
 */
class UniAuthPendingPageControllerTest {

	private final UniAuthPendingPageController controller = new UniAuthPendingPageController();

	@AfterEach
	void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void anAuthenticatedPrincipalIsNamed() throws Exception {
		SecurityContextHolder.getContext()
			.setAuthentication(UsernamePasswordAuthenticationToken.authenticated("held", null, List.of()));

		assertThat(render().getModel()).containsEntry("signedInAs", "held");
	}

	@Test
	void anonymousIsNobodyRatherThanTheWordAnonymousUser() {
		// Printing "anonymousUser" at somebody would be worse than printing nothing, and
		// the page branches on null to offer the sign-in wording instead.
		SecurityContextHolder.getContext()
			.setAuthentication(new AnonymousAuthenticationToken("key", "anonymousUser",
					List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));

		assertThat(nameOnThePage()).isNull();
	}

	@Test
	void anEmptyContextIsNobody() {
		assertThat(nameOnThePage()).isNull();
	}

	@Test
	void anUnauthenticatedTokenIsNobody() {
		// An unauthenticated token is a credentials attempt, not a principal. It names a
		// username that nothing has checked, which must not be echoed back as the
		// account being held.
		SecurityContextHolder.getContext()
			.setAuthentication(new UsernamePasswordAuthenticationToken("whoever-typed-this", "guess"));

		assertThat(nameOnThePage()).isNull();
	}

	private Object nameOnThePage() {
		try {
			return render().getModel().get("signedInAs");
		}
		catch (Exception failed) {
			throw new AssertionError(failed);
		}
	}

	private ModelAndView render() throws Exception {
		ModelAndView view = this.controller.handleRequest(new MockHttpServletRequest("GET", "/pending"),
				new MockHttpServletResponse());
		assertThat(view).isNotNull();
		return view;
	}

}
