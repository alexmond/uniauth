package org.alexmond.uniauth.provider;

import java.util.List;
import java.util.stream.Stream;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The registry is what the chooser page and the providers endpoint both read, so its
 * behaviour is worth pinning down independently of any application context.
 *
 * <p>
 * It aggregates and orders; enumerating an OAuth2 or SAML repository belongs to the
 * mechanism that owns those types, and is covered there. That split is what allows both
 * jars to be optional — nothing in this class, or this test, names a type from either.
 */
class AuthProviderRegistryTest {

	@Test
	void listsNothingWhenNoMechanismIsEnabled() {
		AuthProviderRegistry registry = registryWith(new UniAuthProperties());

		assertThat(registry.isEmpty()).isTrue();
		assertThat(registry.hasFormProvider()).isFalse();
		assertThat(registry.providers()).isEmpty();
	}

	@Test
	void internalAndLdapBothShareTheForm() {
		UniAuthProperties properties = new UniAuthProperties();
		properties.getInternal().setEnabled(true);
		properties.getLdap().setEnabled(true);

		AuthProviderRegistry registry = registryWith(properties);

		assertThat(registry.hasFormProvider()).isTrue();
		assertThat(registry.formProviders()).extracting(AuthProvider::type)
			.containsExactly(AuthProviderType.INTERNAL, AuthProviderType.LDAP);
		assertThat(registry.formProviders()).allMatch(AuthProvider::isFormBased);
		assertThat(registry.redirectProviders()).isEmpty();
	}

	@Test
	void formProvidersAreListedBeforeRedirectProviders() {
		// The chooser renders the shared form first and buttons after it, so the order
		// the
		// registry returns is part of its contract rather than an accident.
		UniAuthProperties properties = new UniAuthProperties();
		properties.getInternal().setEnabled(true);

		AuthProviderRegistry registry = registryWith(properties, List.of(redirectProvider("google")));

		assertThat(registry.providers()).extracting(AuthProvider::type)
			.containsExactly(AuthProviderType.INTERNAL, AuthProviderType.OAUTH2);
	}

	@Test
	void providersFromEveryMechanismAreGathered() {
		// Two mechanisms contribute independently; the registry is the only thing that
		// sees both.
		AuthProviderRegistry registry = registryWith(new UniAuthProperties(), List.of(redirectProvider("google")),
				List.of(redirectProvider("okta")));

		assertThat(registry.redirectProviders()).extracting(AuthProvider::id).containsExactly("google", "okta");
	}

	private static AuthProvider redirectProvider(String id) {
		return new AuthProvider(id, AuthProviderType.OAUTH2, AuthProviderBrand.GENERIC, id,
				"/oauth2/authorization/" + id, false);
	}

	@SafeVarargs
	private static AuthProviderRegistry registryWith(UniAuthProperties properties, List<AuthProvider>... perMechanism) {
		List<RedirectMechanism> mechanisms = Stream.of(perMechanism).map(AuthProviderRegistryTest::mechanism).toList();
		return new AuthProviderRegistry(properties, provider(mechanisms));
	}

	private static RedirectMechanism mechanism(List<AuthProvider> providers) {
		return new RedirectMechanism() {
			@Override
			public List<AuthProvider> providers() {
				return providers;
			}

			@Override
			public void install(HttpSecurity http, String loginPage, String defaultSuccessUrl) {
			}
		};
	}

	/** Minimal {@link ObjectProvider} standing in for the container's lookup. */
	private static <T> ObjectProvider<T> provider(List<T> instances) {
		return new ObjectProvider<>() {
			@Override
			public T getObject() {
				return instances.get(0);
			}

			@Override
			public T getObject(Object... args) {
				return instances.get(0);
			}

			@Override
			public T getIfAvailable() {
				return instances.isEmpty() ? null : instances.get(0);
			}

			@Override
			public T getIfUnique() {
				return (instances.size() == 1) ? instances.get(0) : null;
			}

			@Override
			public Stream<T> stream() {
				return instances.stream();
			}

			@Override
			public Stream<T> orderedStream() {
				return instances.stream();
			}
		};
	}

}
