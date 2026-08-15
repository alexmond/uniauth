package org.alexmond.uniauth.admin.console;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * The applications this console administers.
 *
 * <p>
 * Each is a separate running application reached over its admin API. The console holds no
 * user store of its own — it cannot, because the interesting stores live inside those
 * applications' memory, which is exactly why the API exists.
 */
@Data
@ConfigurationProperties(prefix = "uniauth-admin")
public class ManagedApplication {

	private List<Target> targets = new ArrayList<>();

	@Data
	public static class Target {

		/** Short identifier used in URLs. */
		private String id;

		/** Name shown in the console. */
		private String name;

		/** Base URL of the managed application, as this console can reach it. */
		private String baseUrl;

		/**
		 * The application's {@code uniauth.admin-api.token}. Inject it from the
		 * environment rather than committing it — it creates accounts on the far side.
		 */
		private String token;

		/** Must match the managed application's {@code uniauth.admin-api.path}. */
		private String path = "/uniauth/admin";

	}

}
