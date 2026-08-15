package org.alexmond.uniauth;

import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * LDAP bind authentication against an embedded UnboundID directory, alongside the
 * internal store.
 *
 * <p>
 * Running both form-based mechanisms at once is the case that matters: it proves the
 * {@code AuthenticationProvider} chain really does fall through from one to the other,
 * which is what lets a deployment keep local break-glass accounts next to a directory.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "spring.ldap.embedded.base-dn=dc=example,dc=com",
		"spring.ldap.embedded.ldif=classpath:test-directory.ldif", "spring.ldap.embedded.port=13389",

		"uniauth.ldap.enabled=true", "uniauth.ldap.url=ldap://localhost:13389/dc=example,dc=com",
		"uniauth.ldap.user-dn-patterns[0]=uid={0},ou=people", "uniauth.ldap.group-search-base=ou=groups",

		"uniauth.internal.enabled=true", "uniauth.internal.users[0].username=breakglass",
		"uniauth.internal.users[0].password={noop}local-only" })
class UniAuthLdapLoginTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void directoryUserAuthenticatesAndPicksUpGroupAuthorities() throws Exception {
		mockMvc.perform(formLogin("/login").user("bob").password("bobspassword"))
			.andExpect(authenticated().withUsername("bob").withRoles("DEVELOPERS"));
	}

	@Test
	void wrongDirectoryPasswordIsRejected() throws Exception {
		mockMvc.perform(formLogin("/login").user("bob").password("nope")).andExpect(unauthenticated());
	}

	@Test
	void internalUserStillAuthenticatesWhileLdapIsActive() throws Exception {
		mockMvc.perform(formLogin("/login").user("breakglass").password("local-only"))
			.andExpect(authenticated().withUsername("breakglass"));
	}

	@Test
	void bothFormProvidersAreReported() throws Exception {
		mockMvc.perform(get("/uniauth/providers"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$[0].type").value("INTERNAL"))
			.andExpect(jsonPath("$[1].type").value("LDAP"))
			.andExpect(jsonPath("$[1].displayName").value("Directory account"));
	}

}
