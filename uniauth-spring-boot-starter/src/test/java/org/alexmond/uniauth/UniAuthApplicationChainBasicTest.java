package org.alexmond.uniauth;

import org.alexmond.uniauth.config.UniAuthBasicEntryPoint;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An application's own chain can reuse the starter's Basic decision instead of copying
 * it.
 *
 * <p>
 * Declaring a second, more specific chain is ordinary Spring Security and the starter
 * says so — but the rule that keeps the browser's native dialog shut lived in private
 * statics, so an application that followed that advice had to write its own
 * {@code .httpBasic(...)} and could not reach it. What it reached for instead was a bare
 * {@code BasicAuthenticationEntryPoint}, and the dialog came back on every
 * expired-session XHR. Nothing reported it: the starter's chain was still installed and
 * still correct, for the paths the application had not claimed.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthApplicationChainBasicTest.ApiChain.class)
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=true",
		"uniauth.internal.users[0].username=alice", "uniauth.internal.users[0].password={noop}s3cret" })
class UniAuthApplicationChainBasicTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void aBrowserXhrOnTheApplicationSChainGetsABare401() throws Exception {
		// The whole point of #14: this assertion passes on the starter's own chain and
		// used to fail here, for the paths an API-first front end actually calls.
		this.mockMvc
			.perform(get("/api/thing").accept(MediaType.ALL)
				.header("Sec-Fetch-Mode", "cors")
				.header("Sec-Fetch-Site", "same-origin"))
			.andExpect(status().isUnauthorized())
			.andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));
	}

	@Test
	void aProgramOnTheApplicationSChainIsStillChallenged() throws Exception {
		// The loss the unconditional-401 workaround accepts, kept instead: a client that
		// waits for the challenge before sending credentials still gets one.
		this.mockMvc.perform(get("/api/thing").accept(MediaType.APPLICATION_JSON))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, org.hamcrest.Matchers.startsWith("Basic")));
	}

	@Test
	void credentialsPresentedToTheApplicationSChainAuthenticate() throws Exception {
		this.mockMvc.perform(get("/api/thing").header(HttpHeaders.AUTHORIZATION, "Basic YWxpY2U6czNjcmV0"))
			.andExpect(status().isNotFound());
	}

	@Test
	void theStarterSOwnChainStillGovernsEverythingElse() throws Exception {
		// A second chain costs the application nothing it did not claim.
		this.mockMvc.perform(get("/").accept(MediaType.TEXT_HTML)).andExpect(redirectedUrl("/login"));
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ApiChain {

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE + 10)
		SecurityFilterChain apiChain(HttpSecurity http, UniAuthBasicEntryPoint entryPoint) throws Exception {
			return http.securityMatcher("/api/**")
				.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated())
				.httpBasic((basic) -> basic.authenticationEntryPoint(entryPoint))
				.build();
		}

	}

}
