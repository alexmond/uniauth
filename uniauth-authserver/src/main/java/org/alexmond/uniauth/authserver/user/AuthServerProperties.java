package org.alexmond.uniauth.authserver.user;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * The provider's own configuration: the accounts it starts with, and the credential its
 * admin API accepts.
 */
@Data
@ConfigurationProperties(prefix = "authserver")
public class AuthServerProperties {

	/** Accounts seeded at startup, so the provider is usable on a fresh boot. */
	private List<SeedUser> users = new ArrayList<>();

	private AdminApi adminApi = new AdminApi();

	@Data
	public static class SeedUser {

		private String username;

		/** In clear; encoded on the way into the store. */
		private String password;

		private List<String> roles = new ArrayList<>(List.of("USER"));

		/**
		 * The {@code name} claim. A provider that knows only usernames is not much of
		 * one.
		 */
		private String name;

		/** The {@code email} claim. */
		private String email;

		/**
		 * Whether this provider stands behind the address, as the {@code email_verified}
		 * claim. Defaults to false, which is the honest default: an address nobody
		 * checked is a claim, and a relying party deciding on one is trusting whoever
		 * typed it.
		 */
		private boolean emailVerified;

	}

	@Data
	public static class AdminApi {

		private boolean enabled;

		/**
		 * Shared secret a console presents as {@code Authorization: Bearer <token>}.
		 * Required whenever the API is on — it creates accounts, so there is no safe
		 * default.
		 */
		private String token;

		private String path = "/admin/api";

	}

}
