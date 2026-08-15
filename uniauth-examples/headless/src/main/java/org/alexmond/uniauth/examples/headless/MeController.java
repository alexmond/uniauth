package org.alexmond.uniauth.examples.headless;

import org.alexmond.uniauth.provider.MechanismResolver;
import org.alexmond.uniauth.provider.ResolvedMechanism;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * The session, as JSON. What a front end asks for after the redirect brings the user
 * back.
 *
 * <p>
 * {@link MechanismResolver} comes from the starter, so a headless application gets the
 * same "which provider answered" answer the server-rendered one puts on its dashboard,
 * without having to work it out from token classes itself.
 */
@RestController
public class MeController {

	private final MechanismResolver resolver;

	public MeController(MechanismResolver resolver) {
		this.resolver = resolver;
	}

	@GetMapping("/api/me")
	public Me me(Authentication authentication) {
		ResolvedMechanism mechanism = this.resolver.resolve(authentication);
		List<String> authorities = authentication.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.toList();
		return new Me(authentication.getName(), mechanism.type().name(), mechanism.provider(), authorities);
	}

	/**
	 * @param name the authenticated principal
	 * @param mechanism which of the four answered
	 * @param provider the registration id, or the mechanism name for form-based sign-ins
	 * @param authorities granted authorities
	 */
	public record Me(String name, String mechanism, String provider, List<String> authorities) {
	}

}
