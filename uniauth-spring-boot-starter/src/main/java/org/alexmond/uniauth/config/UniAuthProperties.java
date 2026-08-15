package org.alexmond.uniauth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration surface for UniAuth.
 * <p>
 * Each mechanism is enabled independently — several may be active at once, and the login
 * page lets the user choose between them. OAuth2 and SAML deliberately do <em>not</em>
 * re-declare registration properties here: they reuse Spring Boot's own
 * {@code spring.security.oauth2.client.registration.*} and
 * {@code spring.security.saml2.relyingparty.*} binding, and UniAuth consumes the
 * resulting repositories.
 */
@Data
@ConfigurationProperties(prefix = "uniauth")
public class UniAuthProperties {

	/**
	 * Master switch. When false, UniAuth backs off entirely and Boot's default security
	 * applies.
	 */
	private boolean enabled = true;

	/** Path of the provider-chooser login page served by this starter. */
	private String loginPage = "/login";

	/** Where to send a user after a successful authentication. */
	private String defaultSuccessUrl = "/";

	/** Where to send a user after logout. */
	private String logoutSuccessUrl = "/login?logout";

	/** Path of the JSON endpoint listing the enabled providers. */
	private String providersEndpoint = "/uniauth/providers";

	/**
	 * Extra ant-style paths served without authentication, on top of the login page, the
	 * providers endpoint and {@code /error}. Static assets and public pages go here — it
	 * lets an application open up routes without replacing the whole filter chain.
	 */
	private List<String> publicPaths = new ArrayList<>();

	private Internal internal = new Internal();

	private Ldap ldap = new Ldap();

	private Oauth2 oauth2 = new Oauth2();

	private Saml saml = new Saml();

	/**
	 * Local user store — credentials declared in configuration. Intended for demos and
	 * small apps.
	 */
	@Data
	public static class Internal {

		/**
		 * Off unless explicitly turned on — this mechanism needs configuration to work.
		 */
		private boolean enabled;

		/**
		 * Label shown above the username/password form when it is the internal store
		 * answering.
		 */
		private String displayName = "Username & password";

		private List<User> users = new ArrayList<>();

		@Data
		public static class User {

			private String username;

			/**
			 * Encoded password. A delegating encoder is used, so prefix the algorithm —
			 * {@code {noop}secret} for plain text, {@code {bcrypt}$2a$...} for bcrypt.
			 */
			private String password;

			private List<String> roles = new ArrayList<>(List.of("USER"));

		}

	}

	/**
	 * LDAP bind authentication. Shares the username/password form with the internal
	 * store.
	 */
	@Data
	public static class Ldap {

		/**
		 * Off unless explicitly turned on — this mechanism needs configuration to work.
		 */
		private boolean enabled;

		private String displayName = "Directory account";

		/**
		 * Full provider URL, e.g.
		 * {@code ldap://directory.example.com:389/dc=example,dc=com}.
		 */
		private String url;

		/**
		 * DN patterns used to bind the user, {@code {0}} being the submitted username.
		 */
		private List<String> userDnPatterns = new ArrayList<>(List.of("uid={0},ou=people"));

		/** Base DN for group lookups, relative to the URL's base. */
		private String groupSearchBase = "ou=groups";

		private String groupSearchFilter = "(member={0})";

		/** Bind DN used for searches. Leave empty for an anonymous bind. */
		private String managerDn;

		private String managerPassword;

	}

	/**
	 * OAuth2 / OIDC. Active only when a {@code ClientRegistrationRepository} is present —
	 * configure registrations under {@code spring.security.oauth2.client.registration.*}.
	 */
	@Data
	public static class Oauth2 {

		private boolean enabled = true;

	}

	/**
	 * SAML 2.0. Active only when a {@code RelyingPartyRegistrationRepository} is present
	 * — configure relying parties under {@code spring.security.saml2.relyingparty.*}.
	 */
	@Data
	public static class Saml {

		private boolean enabled = true;

	}

}
