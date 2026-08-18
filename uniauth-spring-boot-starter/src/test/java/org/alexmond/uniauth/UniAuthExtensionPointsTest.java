package org.alexmond.uniauth;

import org.junit.jupiter.api.Test;

import org.alexmond.uniauth.config.UniAuthAuthorizationCustomizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Contributing to the chain without owning it, and letting a program in.
 *
 * <p>
 * Both exist because the single chain offered exactly one authorization shape and no way
 * for a non-browser to authenticate — and the only escapes were replacing the chain,
 * which costs every mechanism, or adding a second one, which separates an application's
 * rules from the mechanisms that satisfy them.
 */
@SpringBootTest(
		classes = { org.alexmond.uniauth.testapp.TestApplication.class, UniAuthExtensionPointsTest.Rules.class })
@AutoConfigureMockMvc
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=true",
		"uniauth.internal.users[0].username=alice", "uniauth.internal.users[0].password={noop}s3cret",
		"uniauth.internal.users[0].roles[0]=ADMIN", "uniauth.http-basic.enabled=true",
		"uniauth.http-basic.paths[0]=/api/**" })
class UniAuthExtensionPointsTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void anApplicationSRuleIsApplied() throws Exception {
		// /status is not in uniauth.public-paths — it is open because the customizer said
		// so, on UniAuth's own chain rather than a second one.
		this.mockMvc.perform(get("/status")).andExpect(status().isNotFound());
	}

	@Test
	void theCatchAllStillApplies() throws Exception {
		// A customizer adds rules; it does not replace the default. Anything it did not
		// mention still needs a session.
		this.mockMvc.perform(get("/something-else")).andExpect(status().is3xxRedirection());
	}

	@Test
	void aProgramGetsABasicChallenge() throws Exception {
		this.mockMvc.perform(get("/api/thing").accept(MediaType.APPLICATION_JSON))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, org.hamcrest.Matchers.startsWith("Basic")));
	}

	@Test
	void aBrowserStillGetsTheChooser() throws Exception {
		// The detail worth getting right: installed naively, Basic gives an
		// unauthenticated browser a native credential dialog instead of the login page,
		// which defeats the point of offering OAuth.
		this.mockMvc.perform(get("/api/thing").accept(MediaType.TEXT_HTML)).andExpect(redirectedUrl("/login"));
	}

	@Test
	void basicIsNotChallengedOutsideItsPaths() throws Exception {
		// paths scopes the challenge, so a page a human visits never prompts.
		this.mockMvc.perform(get("/somewhere").accept(MediaType.APPLICATION_JSON))
			.andExpect(status().is3xxRedirection());
	}

	@Test
	void credentialsPresentedOverBasicAuthenticate() throws Exception {
		this.mockMvc.perform(get("/api/thing").header(HttpHeaders.AUTHORIZATION, "Basic YWxpY2U6czNjcmV0"))
			.andExpect(status().isNotFound());
	}

	@TestConfiguration
	static class Rules {

		@Bean
		UniAuthAuthorizationCustomizer openTheStatusPage() {
			// A rule the chain could not previously express: keyed on something other
			// than "permitted" or "authenticated".
			return (rules) -> rules.requestMatchers("/status").permitAll();
		}

	}

}
