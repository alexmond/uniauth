package org.alexmond.uniauth.admin.store;

import java.util.ArrayList;
import java.util.List;

import org.alexmond.uniauth.admin.ConsoleProperties;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.web.client.RestClient;

/**
 * Builds whichever stores are configured.
 *
 * <p>
 * A store that is switched off contributes no bean, so the console lists exactly what it
 * can actually reach. Rendering a store that was never configured, and letting it fail on
 * the first click, is how this console shipped its last bug.
 */
@Configuration(proxyBeanMethods = false)
public class StoreConfiguration {

	@Bean
	List<UserStore> userStores(ConsoleProperties properties) {
		List<UserStore> stores = new ArrayList<>();
		if (properties.getProvider().isEnabled()) {
			// Built directly rather than injected: this client needs nothing from a
			// shared builder — no base URL, no interceptors — and a RestClient.Builder
			// bean is not always auto-configured.
			stores.add(new ProviderUserStore(properties.getProvider(), RestClient.create()));
		}
		if (properties.getDirectory().isEnabled()) {
			stores.add(new DirectoryUserStore(properties.getDirectory(), ldapTemplate(properties.getDirectory())));
		}
		return stores;
	}

	private static LdapTemplate ldapTemplate(ConsoleProperties.Directory directory) {
		LdapContextSource contextSource = new LdapContextSource();
		contextSource.setUrl(urlWithoutBase(directory.getUrl()));
		contextSource.setBase(baseOf(directory.getUrl()));
		contextSource.setUserDn(directory.getManagerDn());
		contextSource.setPassword(directory.getManagerPassword());
		contextSource.afterPropertiesSet();
		return new LdapTemplate(contextSource);
	}

	/**
	 * Splits {@code ldap://host:389/dc=example,dc=com} into server and base.
	 *
	 * <p>
	 * The applications configure LDAP as one URL carrying the base DN, and the console
	 * takes the same string so both can be set from one value. {@code LdapContextSource}
	 * wants them apart.
	 */
	private static String urlWithoutBase(String url) {
		int slash = url.indexOf('/', "ldap://".length());
		return (slash < 0) ? url : url.substring(0, slash);
	}

	private static String baseOf(String url) {
		int slash = url.indexOf('/', "ldap://".length());
		return (slash < 0) ? "" : url.substring(slash + 1);
	}

}
