package org.alexmond.uniauth;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.alexmond.uniauth.config.UniAuthHttpSecurityCustomizer;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The application's reach into {@code HttpSecurity} itself.
 *
 * <p>
 * {@link org.alexmond.uniauth.config.UniAuthAuthorizationCustomizer} answers "who may do
 * what". Nothing answered CSRF, headers, CORS or session management, so an application
 * with its own API had one option: declare its own chain, and lose every mechanism the
 * starter wires. That was #12, found when enabling the starter turned a working
 * {@code POST /api/feedback} into a 403 with nothing failing at startup and nothing
 * logged.
 *
 * <p>
 * This file is also where the single-page recipe is proved rather than asserted in prose,
 * because the obvious version of it does not work: Spring's default
 * {@link XorCsrfTokenRequestAttributeHandler} masks the token it renders, so a front end
 * that echoes the raw cookie value back is refused.
 * {@link ApplicationConcerns.SpaHandler} is the delegating handler that reconciles the
 * two, and {@link #aFrontEndThatHoldsNoFormCanTakeATokenFromACookieAndSignOut()} is the
 * proof that the documented recipe is the working one.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthHttpSecurityCustomizerTest.ApplicationConcerns.class)
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=true",
		"uniauth.internal.users[0].username=jane", "uniauth.internal.users[0].password={noop}s3cret",
		"uniauth.public-paths=/api/**" })
class UniAuthHttpSecurityCustomizerTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void aCustomizerCanLetTheApplicationsOwnApiAcceptAPostWithNoToken() throws Exception {
		this.mockMvc.perform(post("/api/feedback")).andExpect(status().isOk());
	}

	@Test
	void csrfStaysOnEverywhereTheCustomizerDidNotExempt() throws Exception {
		// The hook is not a way to switch protection off wholesale. /logout is the
		// starter's own state-changing POST and still demands a token.
		this.mockMvc.perform(post("/logout")).andExpect(status().isForbidden());
	}

	@Test
	void aFrontEndThatHoldsNoFormCanTakeATokenFromACookieAndSignOut() throws Exception {
		// The whole recipe, and the case #32 raised: the token travels in a cookie the
		// script can read and comes back in a header, because there is no server-rendered
		// form to carry it. Signing out is a POST like any other, so without this a
		// sign-out button on a static page is a guaranteed 403.
		MvcResult primed = this.mockMvc.perform(get("/login")).andExpect(cookie().exists("XSRF-TOKEN")).andReturn();
		Cookie token = primed.getResponse().getCookie("XSRF-TOKEN");

		this.mockMvc.perform(post("/logout").cookie(token).header("X-XSRF-TOKEN", token.getValue()))
			.andExpect(status().is3xxRedirection());
	}

	@Test
	void everyCustomizerRunsInOrder() {
		assertThat(ApplicationConcerns.applied).containsExactly("csrf", "headers");
	}

	@TestConfiguration
	static class ApplicationConcerns {

		static final List<String> applied = new ArrayList<>();

		@Bean
		@Order(1)
		UniAuthHttpSecurityCustomizer csrfForTheApi() {
			return (http) -> {
				applied.add("csrf");
				http.csrf((csrf) -> csrf.ignoringRequestMatchers("/api/**")
					.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
					.csrfTokenRequestHandler(new SpaHandler()));
			};
		}

		@Bean
		@Order(2)
		UniAuthHttpSecurityCustomizer headers() {
			return (http) -> applied.add("headers");
		}

		/**
		 * Renders a masked token for the server-rendered pages and accepts a raw one from
		 * a header.
		 *
		 * <p>
		 * Both halves are needed because this library serves a login form <em>and</em>
		 * the application serves a front end. Masking defends the rendered value against
		 * BREACH, so it is worth keeping for the form; but the value in the cookie is the
		 * raw token, so a script echoing it back must be read by the plain handler.
		 * Spring's reference documentation carries this same pattern for exactly this
		 * reason.
		 */
		static final class SpaHandler implements CsrfTokenRequestHandler {

			private final CsrfTokenRequestHandler plain = new CsrfTokenRequestAttributeHandler();

			private final CsrfTokenRequestHandler masked = new XorCsrfTokenRequestAttributeHandler();

			@Override
			public void handle(HttpServletRequest request, HttpServletResponse response,
					Supplier<CsrfToken> csrfToken) {
				this.masked.handle(request, response, csrfToken);
				// Resolved eagerly: the repository only writes the cookie once somebody
				// asks for the token, and a front end that is handed no page has nobody
				// to ask on its behalf.
				csrfToken.get();
			}

			@Override
			public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
				String fromHeader = request.getHeader(csrfToken.getHeaderName());
				return StringUtils.hasText(fromHeader) ? this.plain.resolveCsrfTokenValue(request, csrfToken)
						: this.masked.resolveCsrfTokenValue(request, csrfToken);
			}

		}

	}

}
