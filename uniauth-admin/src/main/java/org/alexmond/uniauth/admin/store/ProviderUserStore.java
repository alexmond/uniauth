package org.alexmond.uniauth.admin.store;

import java.util.List;
import java.util.Map;

import org.alexmond.uniauth.admin.ConsoleProperties;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

/**
 * The OAuth2/OIDC provider's accounts, over its token-authenticated admin API.
 *
 * <p>
 * The provider owns this population and this console does not mirror it — every page load
 * asks. A cache here would be a second source of truth for accounts that another operator
 * can change out from under it.
 */
public class ProviderUserStore implements UserStore {

	private static final ParameterizedTypeReference<List<Map<String, Object>>> USER_LIST = new ParameterizedTypeReference<>() {
	};

	private final ConsoleProperties.Provider config;

	private final RestClient restClient;

	public ProviderUserStore(ConsoleProperties.Provider config, RestClient restClient) {
		this.config = config;
		this.restClient = restClient;
	}

	@Override
	public String id() {
		return "provider";
	}

	@Override
	public String name() {
		return this.config.getName();
	}

	@Override
	public String location() {
		return this.config.getBaseUrl();
	}

	@Override
	public String description() {
		return "Accounts held by the identity provider. A user signing in through the provider "
				+ "button on an application proves themselves against this population.";
	}

	@Override
	public boolean supportsRoles() {
		return true;
	}

	@Override
	public List<ConsoleUser> users() {
		List<Map<String, Object>> body = call(() -> this.restClient.get()
			.uri(usersUri())
			.header(HttpHeaders.AUTHORIZATION, bearer())
			.accept(MediaType.APPLICATION_JSON)
			.retrieve()
			.body(USER_LIST));
		if (body == null) {
			return List.of();
		}
		return body.stream().map(ProviderUserStore::toUser).toList();
	}

	@Override
	public void create(String username, String password, List<String> roles) {
		call(() -> this.restClient.post()
			.uri(usersUri())
			.header(HttpHeaders.AUTHORIZATION, bearer())
			.contentType(MediaType.APPLICATION_JSON)
			.body(Map.of("username", username, "password", password, "roles", roles))
			.retrieve()
			.toBodilessEntity());
	}

	@Override
	public void setPassword(String username, String password) {
		update(username, Map.of("password", password));
	}

	@Override
	public void setRoles(String username, List<String> roles) {
		update(username, Map.of("roles", roles));
	}

	private void update(String username, Map<String, Object> body) {
		call(() -> this.restClient.put()
			.uri(usersUri() + "/" + username)
			.header(HttpHeaders.AUTHORIZATION, bearer())
			.contentType(MediaType.APPLICATION_JSON)
			.body(body)
			.retrieve()
			.toBodilessEntity());
	}

	@Override
	public void delete(String username) {
		call(() -> this.restClient.delete()
			.uri(usersUri() + "/" + username)
			.header(HttpHeaders.AUTHORIZATION, bearer())
			.retrieve()
			.toBodilessEntity());
	}

	@SuppressWarnings("unchecked")
	private static ConsoleUser toUser(Map<String, Object> entry) {
		Object roles = entry.get("roles");
		List<String> asList = (roles instanceof List) ? (List<String>) roles : List.of();
		return new ConsoleUser(String.valueOf(entry.get("username")), asList);
	}

	private String usersUri() {
		return this.config.getBaseUrl() + this.config.getPath() + "/users";
	}

	private String bearer() {
		return "Bearer " + this.config.getToken();
	}

	private <T> T call(java.util.function.Supplier<T> request) {
		try {
			return request.get();
		}
		catch (RestClientResponseException ex) {
			// The provider answered and said no — 409 for a name already taken, 401 for a
			// stale token. Its own message beats anything this console could invent.
			throw new StoreException(messageFrom(ex), ex);
		}
		catch (RuntimeException ex) {
			throw new StoreException(this.config.getName() + " is not answering (" + this.config.getBaseUrl() + ")",
					ex);
		}
	}

	private static String messageFrom(RestClientResponseException ex) {
		String body = ex.getResponseBodyAsString();
		int start = body.indexOf("\"error\":\"");
		if (start >= 0) {
			int from = start + "\"error\":\"".length();
			int end = body.indexOf('"', from);
			if (end > from) {
				return body.substring(from, end);
			}
		}
		return "The provider refused this: " + ex.getStatusText();
	}

}
