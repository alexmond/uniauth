package org.alexmond.uniauth.oauth2;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Covers the decorator's logic without touching GitHub: the delegate is a stub and the
 * second call is served by a mock server, so both halves of the merge are exercised
 * offline.
 */
class GithubEmailOAuth2UserServiceTest {

	private static final String EMAILS_URI = "https://api.github.com/user/emails";

	private RestClient.Builder builder;

	private MockRestServiceServer server;

	@BeforeEach
	void setUp() {
		this.builder = RestClient.builder();
		this.server = MockRestServiceServer.bindTo(this.builder).build();
	}

	@Test
	void addsThePrimaryVerifiedAddressWhenUserinfoHasNone() {
		this.server.expect(requestTo(EMAILS_URI))
			.andExpect(header("Authorization", "Bearer token-value"))
			.andRespond(withSuccess("""
					[
					  {"email":"secondary@example.com","primary":false,"verified":true},
					  {"email":"unverified@example.com","primary":true,"verified":false},
					  {"email":"bob@example.com","primary":true,"verified":true}
					]
					""", MediaType.APPLICATION_JSON));

		OAuth2User user = service(githubUser(null)).loadUser(request("github"));

		assertThat(user.<String>getAttribute("email")).isEqualTo("bob@example.com");
		// The rest of the principal survives the rebuild.
		assertThat(user.getName()).isEqualTo("4242");
		assertThat(user.<String>getAttribute("login")).isEqualTo("bob");
		this.server.verify();
	}

	@Test
	void marksTheFetchedAddressAsVerified() {
		// It is taken only from an entry GitHub calls primary AND verified, so saying so
		// is reporting a fact. Leaving it unsaid would make a checked address
		// indistinguishable from one nobody stands behind — which is the distinction an
		// approver is deciding on.
		this.server.expect(requestTo(EMAILS_URI)).andRespond(withSuccess("""
				[{"email":"bob@example.com","primary":true,"verified":true}]
				""", MediaType.APPLICATION_JSON));

		OAuth2User user = service(githubUser(null)).loadUser(request("github"));

		assertThat(user.<Boolean>getAttribute("email_verified")).isTrue();
	}

	@Test
	void leavesAnExistingEmailAlone() {
		OAuth2User user = service(githubUser("public@example.com")).loadUser(request("github"));

		assertThat(user.<String>getAttribute("email")).isEqualTo("public@example.com");
		// No second call was made — a public address is already the answer.
		this.server.verify();
	}

	@Test
	void ignoresProvidersThatAreNotGithub() {
		OAuth2User user = service(githubUser(null)).loadUser(request("google"));

		assertThat(user.<String>getAttribute("email")).isNull();
		this.server.verify();
	}

	@Test
	void signInStillSucceedsWhenTheEmailLookupFails() {
		// What a missing user:email scope looks like from here.
		this.server.expect(requestTo(EMAILS_URI)).andRespond(withServerError());

		OAuth2User user = service(githubUser(null)).loadUser(request("github"));

		assertThat(user).isNotNull();
		assertThat(user.<String>getAttribute("email")).isNull();
	}

	private GithubEmailOAuth2UserService service(OAuth2User delegateResult) {
		OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = (request) -> delegateResult;
		return new GithubEmailOAuth2UserService(delegate, this.builder.build(), EMAILS_URI);
	}

	private static OAuth2User githubUser(String email) {
		Map<String, Object> attributes = new LinkedHashMap<>();
		attributes.put("id", "4242");
		attributes.put("login", "bob");
		if (email != null) {
			attributes.put("email", email);
		}
		return new DefaultOAuth2User(AuthorityUtils.createAuthorityList("OAUTH2_USER"), attributes, "id");
	}

	private static OAuth2UserRequest request(String registrationId) {
		OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token-value",
				Instant.now(), Instant.now().plusSeconds(600));
		return new OAuth2UserRequest(registration(registrationId), token);
	}

	private static ClientRegistration registration(String registrationId) {
		return ClientRegistration.withRegistrationId(registrationId)
			.clientId("client-id")
			.clientSecret("client-secret")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.authorizationUri("https://example.test/authorize")
			.tokenUri("https://example.test/token")
			.userInfoUri("https://example.test/user")
			.userNameAttributeName("id")
			.build();
	}

}
