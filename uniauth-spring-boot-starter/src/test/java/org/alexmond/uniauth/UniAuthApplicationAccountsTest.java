package org.alexmond.uniauth;

import java.util.List;

import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An application that brings its own accounts still gets a password form.
 *
 * <p>
 * The registry used to answer "can a username and password be entered here?" from
 * configuration alone — {@code uniauth.internal.enabled} or {@code uniauth.ldap.enabled}
 * — and never from whether the application had registered a provider that would happily
 * authenticate one. So an application holding its credentials somewhere else got a login
 * page with the redirect buttons and no form, and because the same answer gates
 * {@code http.formLogin}, there was no filter to post to either: the form was not broken,
 * it did not exist (#9).
 *
 * <p>
 * Declaring accounts a second time under {@code uniauth.internal.users} was the only way
 * through, which means declaring them twice — and switching the internal store on with
 * nothing in it reads as a lie in the configuration, since the reason it is set has
 * nothing to do with internal accounts.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthApplicationAccountsTest.OwnAccounts.class)
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=false",
		"uniauth.ldap.enabled=false", "spring.security.oauth2.client.registration.google.client-id=demo-id",
		"spring.security.oauth2.client.registration.google.client-secret=demo-secret" })
class UniAuthApplicationAccountsTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theFormIsRenderedBecauseSomethingInTheContextCanAnswerIt() throws Exception {
		String page = this.mockMvc.perform(get("/login"))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();

		assertThat(page).contains("name=\"username\"").contains("name=\"password\"");
		// And the redirect button is still there: this is the side-by-side case the
		// issue was reported from — a local administrator and Google on one page.
		assertThat(page).contains("Sign in with Google");
	}

	@Test
	void andPostingToItAuthenticatesAgainstTheApplicationSOwnProvider() throws Exception {
		// The half that a rendered form alone would not fix. hasFormProvider() also
		// gates http.formLogin, so without this there is no filter listening on the
		// login path and the form posts into nothing.
		this.mockMvc.perform(formLogin("/login").user("app-admin").password("letmein"))
			.andExpect(authenticated().withUsername("app-admin").withAuthorities(List.of(ROLE_ADMIN)));
	}

	private static final SimpleGrantedAuthority ROLE_ADMIN = new SimpleGrantedAuthority("ROLE_ADMIN");

	/**
	 * An application's own accounts: one provider, no {@code UserDetailsService}, nothing
	 * declared under {@code uniauth.*}.
	 */
	@TestConfiguration(proxyBeanMethods = false)
	static class OwnAccounts {

		@Bean
		AuthenticationProvider applicationAccounts() {
			return new AuthenticationProvider() {

				@Override
				public Authentication authenticate(Authentication authentication) throws AuthenticationException {
					if (!"app-admin".equals(authentication.getName())
							|| !"letmein".equals(authentication.getCredentials())) {
						return null;
					}
					return UsernamePasswordAuthenticationToken.authenticated(authentication.getName(), null,
							List.of(ROLE_ADMIN));
				}

				@Override
				public boolean supports(Class<?> authentication) {
					return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
				}

			};
		}

	}

}
