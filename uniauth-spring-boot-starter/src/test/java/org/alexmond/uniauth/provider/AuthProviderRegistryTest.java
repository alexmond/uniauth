package org.alexmond.uniauth.provider;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The registry is what the chooser page and the providers endpoint both read, so its
 * behaviour is worth pinning down independently of any application context.
 */
class AuthProviderRegistryTest {

	@Test
	void listsNothingWhenNoMechanismIsEnabled() {
		AuthProviderRegistry registry = registry(new UniAuthProperties(), null, null);

		assertThat(registry.isEmpty()).isTrue();
		assertThat(registry.hasFormProvider()).isFalse();
		assertThat(registry.providers()).isEmpty();
	}

	@Test
	void internalAndLdapBothShareTheForm() {
		UniAuthProperties properties = new UniAuthProperties();
		properties.getInternal().setEnabled(true);
		properties.getLdap().setEnabled(true);

		AuthProviderRegistry registry = registry(properties, null, null);

		assertThat(registry.hasFormProvider()).isTrue();
		assertThat(registry.formProviders()).extracting(AuthProvider::type)
			.containsExactly(AuthProviderType.INTERNAL, AuthProviderType.LDAP);
		assertThat(registry.formProviders()).allMatch(AuthProvider::isFormBased);
		assertThat(registry.redirectProviders()).isEmpty();
	}

	@Test
	void oauth2RegistrationsBecomeRedirectProviders() {
		UniAuthProperties properties = new UniAuthProperties();
		ClientRegistrationRepository clients = new InMemoryClientRegistrationRepository(
				clientRegistration("google", "Google"));

		AuthProviderRegistry registry = registry(properties, clients, null);

		assertThat(registry.redirectProviders()).singleElement().satisfies((provider) -> {
			assertThat(provider.id()).isEqualTo("google");
			assertThat(provider.type()).isEqualTo(AuthProviderType.OAUTH2);
			assertThat(provider.displayName()).isEqualTo("Google");
			assertThat(provider.loginUrl()).isEqualTo("/oauth2/authorization/google");
			assertThat(provider.isFormBased()).isFalse();
		});
	}

	@Test
	void disablingOauth2HidesItsRegistrationsEvenWhenARepositoryExists() {
		UniAuthProperties properties = new UniAuthProperties();
		properties.getOauth2().setEnabled(false);
		ClientRegistrationRepository clients = new InMemoryClientRegistrationRepository(
				clientRegistration("google", "Google"));

		AuthProviderRegistry registry = registry(properties, clients, null);

		assertThat(registry.redirectProviders()).isEmpty();
	}

	@Test
	void formProvidersAreListedBeforeRedirectProviders() {
		UniAuthProperties properties = new UniAuthProperties();
		properties.getInternal().setEnabled(true);
		ClientRegistrationRepository clients = new InMemoryClientRegistrationRepository(
				clientRegistration("google", "Google"));

		AuthProviderRegistry registry = registry(properties, clients, null);

		assertThat(registry.providers()).extracting(AuthProvider::type)
			.containsExactly(AuthProviderType.INTERNAL, AuthProviderType.OAUTH2);
	}

	@Test
	void fallsBackToTheRegistrationIdWhenAClientHasNoName() {
		ClientRegistration noName = ClientRegistration.withRegistrationId("keycloak")
			.clientId("id")
			.clientSecret("secret")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.authorizationUri("https://idp.example.com/auth")
			.tokenUri("https://idp.example.com/token")
			.clientName(null)
			.build();

		AuthProviderRegistry registry = registry(new UniAuthProperties(),
				new InMemoryClientRegistrationRepository(noName), null);

		assertThat(registry.redirectProviders()).singleElement()
			.extracting(AuthProvider::displayName)
			.isEqualTo("Keycloak");
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

	private static AuthProviderRegistry registry(UniAuthProperties properties, ClientRegistrationRepository clients,
			RelyingPartyRegistrationRepository relyingParties) {
		return new AuthProviderRegistry(properties, provider(clients), provider(relyingParties));
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
			public java.util.stream.Stream<T> stream() {
				return (instance != null) ? List.of(instance).stream() : java.util.stream.Stream.empty();
			}
		};
	}

}
