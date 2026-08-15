package org.alexmond.uniauth.admin.console;

import lombok.Data;
import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

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
@ConfigurationProperties(prefix = "console")
public class ManagedApplication {

	private List<Target> targets = new ArrayList<>();

	/**
	 * Rejects a half-configured target at startup instead of letting it fail on the first
	 * request.
	 *
	 * <p>
	 * The failure mode this guards against is specific and easy to hit: a list bound from
	 * environment variables <em>replaces</em> the one in {@code application.yaml} rather
	 * than merging with it, so supplying only a token from a Secret silently blanks the
	 * id and name. Every field of every entry has to come from the same place.
	 */
	@PostConstruct
	void validate() {
		for (int i = 0; i < this.targets.size(); i++) {
			Target target = this.targets.get(i);
			require(target.getId(), i, "id");
			require(target.getName(), i, "name");
			require(target.getBaseUrl(), i, "base-url");
			require(target.getToken(), i, "token");
		}
	}

	private static void require(String value, int index, String field) {
		if (!StringUtils.hasText(value)) {
			throw new IllegalStateException("console.targets[" + index + "]." + field + " is not set. "
					+ "When any part of a target comes from the environment, every part must: a list bound "
					+ "from environment variables replaces the one in application.yaml rather than merging.");
		}
	}

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
