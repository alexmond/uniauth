package org.alexmond.uniauth.admin;

import jakarta.annotation.PostConstruct;
import lombok.Data;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

/**
 * What this console administers.
 *
 * <p>
 * Two stores, each optional, each configured as a flat block rather than as entries in a
 * list. That is deliberate and it is a bug fix: a list bound from environment variables
 * <em>replaces</em> the one in {@code application.yaml} instead of merging with it, so
 * supplying one field from a Secret used to blank every sibling field silently. Flat
 * blocks bind field by field and cannot lose their neighbours.
 */
@Data
@ConfigurationProperties(prefix = "console")
public class ConsoleProperties {

	private Provider provider = new Provider();

	private Directory directory = new Directory();

	@PostConstruct
	void validate() {
		if (this.provider.isEnabled()) {
			require(this.provider.getBaseUrl(), "console.provider.base-url");
			require(this.provider.getToken(), "console.provider.token");
		}
		if (this.directory.isEnabled()) {
			require(this.directory.getUrl(), "console.directory.url");
			// Writing to a directory is not anonymous anywhere that matters, and the
			// failure without it is a runtime "insufficient access" on the first create
			// rather than anything pointing here.
			require(this.directory.getManagerDn(), "console.directory.manager-dn");
			require(this.directory.getManagerPassword(), "console.directory.manager-password");
		}
	}

	private static void require(String value, String property) {
		if (!StringUtils.hasText(value)) {
			throw new IllegalStateException(property + " is not set, and the store it belongs to is enabled. "
					+ "Set it, or disable that store.");
		}
	}

	/** The OAuth2/OIDC provider, administered over its admin API. */
	@Data
	public static class Provider {

		private boolean enabled = true;

		private String name = "UniAuth provider";

		/** Base URL of the provider, as this console can reach it. */
		private String baseUrl;

		/**
		 * The provider's {@code authserver.admin-api.token}. It creates accounts on the
		 * far side, so inject it from the environment rather than committing it.
		 */
		private String token;

		/** Must match the provider's {@code authserver.admin-api.path}. */
		private String path = "/admin/api";

	}

	/** The LDAP directory, administered over LDAP. */
	@Data
	public static class Directory {

		private boolean enabled = true;

		private String name = "Directory";

		/** Including the base DN, e.g. {@code ldap://openldap:389/dc=example,dc=com}. */
		private String url;

		/** Bind account with write access. */
		private String managerDn;

		private String managerPassword;

		/** Where person entries live, relative to the base DN. */
		private String userBase = "ou=people";

		/** The naming attribute for a person entry. */
		private String userAttribute = "uid";

		/** Shown beside an entry so its full DN is visible; not used for binding. */
		private String baseDn = "";

	}

}
