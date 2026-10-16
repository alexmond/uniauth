package org.alexmond.uniauth;

import java.util.List;

import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * The application's own accounts, and nothing else at all.
 *
 * <p>
 * Worth its own context rather than a second case next door, because the thing being
 * checked only appears when the registry can name no providers whatever: it is
 * {@code isEmpty()} that prints "no authentication provider is enabled", and it reads the
 * named ones. An application whose accounts are its own is not among them, so the page
 * would otherwise carry a working password form underneath a notice saying there was
 * nothing to sign in with.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthApplicationAccountsTest.OwnAccounts.class)
@TestPropertySource(
		properties = { "uniauth.enabled=true", "uniauth.internal.enabled=false", "uniauth.ldap.enabled=false" })
class UniAuthApplicationAccountsOnlyTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theFormStandsAloneAndThePageDoesNotSayNothingIsConfigured() throws Exception {
		String page = this.mockMvc.perform(get("/login")).andReturn().getResponse().getContentAsString();

		assertThat(page).contains("name=\"username\"");
		assertThat(page).doesNotContain("No authentication provider is enabled");
	}

	@Test
	void andItStillAuthenticates() throws Exception {
		this.mockMvc.perform(SecurityMockMvcRequestBuilders.formLogin("/login").user("app-admin").password("letmein"))
			.andExpect(authenticated().withUsername("app-admin").withAuthorities(List.of(ROLE)));
	}

	private static final org.springframework.security.core.authority.SimpleGrantedAuthority ROLE = new org.springframework.security.core.authority.SimpleGrantedAuthority(
			"ROLE_ADMIN");

}
