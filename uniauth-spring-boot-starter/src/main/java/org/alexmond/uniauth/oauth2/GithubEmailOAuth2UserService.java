package org.alexmond.uniauth.oauth2;

import org.alexmond.uniauth.provider.AuthProviderBrand;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestClient;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Fills in the email address GitHub leaves out.
 *
 * <p>
 * GitHub's {@code /user} response carries {@code email} only when the account has a
 * public address, and private is the default — so most GitHub logins arrive with no email
 * at all. The addresses live behind a second endpoint, {@code /user/emails}, which
 * Spring's default user service has no reason to call. This decorator makes that call and
 * merges the primary verified address into the principal's attributes.
 *
 * <p>
 * It is deliberately conservative: anything that is not GitHub passes straight through,
 * an email already present is left alone, and a failed lookup returns the original user
 * rather than breaking the sign-in. A missing {@code user:email} scope shows up as
 * exactly that failure, so the login still succeeds — just without an address.
 */
public class GithubEmailOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private static final ParameterizedTypeReference<List<Map<String, Object>>> EMAIL_LIST = new ParameterizedTypeReference<>() {
	};

	private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate;

	private final RestClient restClient;

	private final String emailsUri;

	/**
	 * Wraps a user service with the address lookup.
	 * @param delegate the user service that loads the principal first; this one only adds
	 * an address to what it returns
	 * @param restClient client for the second call
	 * @param emailsUri the endpoint listing addresses, from
	 * {@code uniauth.oauth2.github.emails-uri}
	 */
	public GithubEmailOAuth2UserService(OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate,
			RestClient restClient, String emailsUri) {
		this.delegate = delegate;
		this.restClient = restClient;
		this.emailsUri = emailsUri;
	}

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) {
		OAuth2User user = this.delegate.loadUser(userRequest);
		if (AuthProviderBrand.detect(userRequest.getClientRegistration()) != AuthProviderBrand.GITHUB) {
			return user;
		}
		// Asked for even when /user already returned one. That field is the PUBLIC
		// PROFILE email — whatever the account chose to display — and GitHub says nothing
		// about whether it still belongs to them; it is frequently an old address. The
		// primary verified address is the account's actual identity, so it wins when both
		// exist. Preferring the public one is how this shipped showing the wrong address
		// with no badge to hint that it was unchecked.
		String email = primaryVerifiedEmail(userRequest);
		if (email == null) {
			// Nothing verified to be had — no user:email scope, or no verified address on
			// the account. Whatever /user gave stays, unmarked, because unmarked is the
			// truth about it.
			return user;
		}
		Map<String, Object> attributes = new LinkedHashMap<>(user.getAttributes());
		attributes.put("email", email);
		// Say so. The address is taken only from an entry GitHub marks primary AND
		// verified, so this is a fact rather than an assumption — and without it a
		// consumer cannot tell a checked address from one nobody stands behind, which is
		// exactly the distinction an approval decision turns on.
		attributes.put("email_verified", true);
		String nameAttribute = userRequest.getClientRegistration()
			.getProviderDetails()
			.getUserInfoEndpoint()
			.getUserNameAttributeName();
		return new DefaultOAuth2User(user.getAuthorities(), attributes, nameAttribute);
	}

	private String primaryVerifiedEmail(OAuth2UserRequest userRequest) {
		try {
			List<Map<String, Object>> emails = this.restClient.get()
				.uri(this.emailsUri)
				.accept(MediaType.APPLICATION_JSON)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + userRequest.getAccessToken().getTokenValue())
				.retrieve()
				.body(EMAIL_LIST);
			if (emails == null) {
				return null;
			}
			return emails.stream()
				.filter((entry) -> Boolean.TRUE.equals(entry.get("primary")))
				.filter((entry) -> Boolean.TRUE.equals(entry.get("verified")))
				.map((entry) -> (String) entry.get("email"))
				.findFirst()
				.orElse(null);
		}
		catch (RuntimeException ex) {
			// Almost always a missing user:email scope. Signing in without an address
			// beats
			// failing the login outright.
			return null;
		}
	}

}
