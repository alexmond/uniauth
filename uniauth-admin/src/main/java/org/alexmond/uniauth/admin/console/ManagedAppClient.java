package org.alexmond.uniauth.admin.console;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.List;
import java.util.Map;

/**
 * Talks to a managed application's admin API.
 *
 * <p>
 * Failures are turned into messages a console can show rather than exceptions that become
 * a stack trace on screen. The distinction that matters to an administrator is "the far
 * side refused this" versus "the far side is not answering", and both are common enough
 * to be worth naming.
 */
@Component
public class ManagedAppClient {

	private static final ParameterizedTypeReference<List<Map<String, Object>>> STORE_LIST = new ParameterizedTypeReference<>() {
	};

	private final RestClient restClient;

	public ManagedAppClient() {
		// Built directly rather than injected: a RestClient.Builder bean is not always
		// auto-configured, and this client needs nothing from one — no base URL, no
		// shared
		// interceptors. Each call carries its own target and token.
		this(RestClient.create());
	}

	/** For tests, which bind a MockRestServiceServer to the client. */
	ManagedAppClient(RestClient restClient) {
		this.restClient = restClient;
	}

	/** What the managed application says it can administer. */
	public List<Map<String, Object>> stores(ManagedApplication.Target target) {
		return this.restClient.get()
			.uri(target.getBaseUrl() + target.getPath() + "/stores")
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + target.getToken())
			.accept(MediaType.APPLICATION_JSON)
			.retrieve()
			.body(STORE_LIST);
	}

	/**
	 * Creates a user on the far side.
	 * @return an error message, or empty when it worked
	 */
	public java.util.Optional<String> createUser(ManagedApplication.Target target, String mechanism, String username,
			String password, List<String> roles) {
		try {
			this.restClient.post()
				.uri(target.getBaseUrl() + target.getPath() + "/users")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + target.getToken())
				.contentType(MediaType.APPLICATION_JSON)
				.body(Map.of("mechanism", mechanism, "username", username, "password", password, "roles", roles))
				.retrieve()
				.toBodilessEntity();
			return java.util.Optional.empty();
		}
		catch (RestClientResponseException ex) {
			// The application answered and said no — 409 for a name already taken, 502
			// when
			// a directory refused the entry. Its message is more useful than ours.
			return java.util.Optional.of(messageFrom(ex));
		}
		catch (RuntimeException ex) {
			return java.util.Optional.of(target.getName() + " is not reachable: " + ex.getMessage());
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
		return ex.getStatusText();
	}

}
