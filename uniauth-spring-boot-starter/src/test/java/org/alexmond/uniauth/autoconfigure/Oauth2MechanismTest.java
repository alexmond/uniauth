package org.alexmond.uniauth.autoconfigure;

import java.util.List;
import java.util.stream.Stream;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProvider;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Turning Boot's client registrations into chooser entries lives here rather than in the
 * registry, so that nothing outside this package names an OAuth2 type — which is what
 * lets the dependency be optional. These are the enumeration cases that used to sit in
 * {@code AuthProviderRegistryTest}.
 */
class Oauth2MechanismTest {

	@Test
	void registrationsBecomeRedirectProviders() {
		Oauth2Mechanism mechanism = mechanism(new UniAuthProperties(), clientRegistration("google", "Google"));

		assertThat(mechanism.providers()).singleElement().satisfies((provider) -> {
			assertThat(provider.id()).isEqualTo("google");
			assertThat(provider.type()).isEqualTo(AuthProviderType.OAUTH2);
			assertThat(provider.displayName()).isEqualTo("Google");
			assertThat(provider.loginUrl()).isEqualTo("/oauth2/authorization/google");
			assertThat(provider.isFormBased()).isFalse();
		});
	}

	@Test
	void disablingOauth2HidesItsRegistrationsEvenWhenARepositoryExists() {
		// The repository comes from Boot's own binding, so the only way to say "not this
		// one" is the uniauth flag — the registrations are there either way.
		UniAuthProperties properties = new UniAuthProperties();
		properties.getOauth2().setEnabled(false);

		Oauth2Mechanism mechanism = mechanism(properties, clientRegistration("google", "Google"));

		assertThat(mechanism.providers()).isEmpty();
	}

	@Test
	void fallsBackToTheRegistrationIdWhenAClientHasNoName() {
		// Boot defaults clientName to the registration id, so an unnamed provider would
		// otherwise render as a lowercase key on the button.
		Oauth2Mechanism mechanism = mechanism(new UniAuthProperties(), clientRegistration("keycloak", "keycloak"));

		assertThat(mechanism.providers()).singleElement().extracting(AuthProvider::displayName).isEqualTo("Keycloak");
	}

	@Test
	void listsNothingWithoutARepository() {
		Oauth2Mechanism mechanism = new Oauth2Mechanism(new UniAuthProperties(), provider(null));

		assertThat(mechanism.providers()).isEmpty();
	}

	private static Oauth2Mechanism mechanism(UniAuthProperties properties, ClientRegistration... registrations) {
		ClientRegistrationRepository repository = new InMemoryClientRegistrationRepository(List.of(registrations));
		return new Oauth2Mechanism(properties, provider(repository));
	}

	private static ClientRegistration clientRegistration(String id, String name) {
		return ClientRegistration.withRegistrationId(id)
			.clientId("client-id")
			.clientSecret("client-secret")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.authorizationUri("https://idp.example.com/auth")
			.tokenUri("https://idp.example.com/token")
			.clientName(name)
			.build();
	}

	/** Minimal {@link ObjectProvider} standing in for the container's lookup. */
	private static <T> ObjectProvider<T> provider(T instance) {
		return new ObjectProvider<>() {
			@Override
			public T getObject() {
				return instance;
			}

			@Override
			public T getObject(Object... args) {
				return instance;
			}

			@Override
			public T getIfAvailable() {
				return instance;
			}

			@Override
			public T getIfUnique() {
				return instance;
			}

			@Override
			public Stream<T> stream() {
				return (instance != null) ? Stream.of(instance) : Stream.empty();
			}
		};
	}

}
