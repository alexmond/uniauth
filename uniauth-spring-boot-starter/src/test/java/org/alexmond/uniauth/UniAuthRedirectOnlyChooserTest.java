package org.alexmond.uniauth;

import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * A chooser offering only redirect providers still shows no password box.
 *
 * <p>
 * The guard on #9's detection. It looks at {@code AuthenticationProvider} and
 * {@code UserDetailsService} beans — things the application owns — rather than at
 * anything that could conceivably authenticate a password, and the difference is not
 * hypothetical. Spring Boot contributes a fallback account of its own, {@code user} with
 * a password generated at startup and printed to the log, and that account can genuinely
 * sign in through this chain. A detector reasoning from capability alone would put a form
 * on every redirect-only login page and admit it there.
 *
 * <p>
 * It cannot reach a UniAuth application as things stand, and the reason is worth writing
 * down because it is not a property of UniAuth's own code:
 * {@code UserDetailsServiceAutoConfiguration}'s condition is
 * {@code @ConditionalOnMissingClass} on {@code ClientRegistrationRepository} and
 * {@code RelyingPartyRegistrationRepository} — the <em>classes</em>, not beans — and this
 * starter depends on {@code spring-boot-starter-oauth2-client} at compile scope. So the
 * first of those is on every consumer's classpath and the condition never matches. Make
 * that dependency optional, as SAML's already is, and Boot's generated user appears in
 * any application that takes neither: this test is what will say so.
 *
 * <p>
 * Nothing asserted the form's absence before this, so the regression had nothing standing
 * in its way.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=false",
		"uniauth.ldap.enabled=false", "spring.security.oauth2.client.registration.google.client-id=demo-id",
		"spring.security.oauth2.client.registration.google.client-secret=demo-secret" })
class UniAuthRedirectOnlyChooserTest {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	AuthProviderRegistry registry;

	@Test
	void thereIsNoFormBecauseNothingTheApplicationOwnsCanAnswerOne() throws Exception {
		String page = this.mockMvc.perform(get("/login")).andReturn().getResponse().getContentAsString();

		assertThat(this.registry.hasFormProvider()).isFalse();
		assertThat(page).doesNotContain("name=\"password\"");
		assertThat(page).contains("Sign in with Google");
	}

}
