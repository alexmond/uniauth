package org.alexmond.uniauth.admin;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Authenticates a management console by a shared token.
 *
 * <p>
 * Deliberately small. This is service-to-service: there is no user, no session and
 * nothing to redirect to, so the whole contract is one header and a 401 when it is wrong.
 *
 * <p>
 * The comparison is constant-time. A plain {@code equals} leaks the token a character at
 * a time to anyone who can measure the response, which for a credential that creates
 * accounts is not a risk worth taking to save one line.
 */
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

	private static final String PREFIX = "Bearer ";

	private final byte[] expected;

	public BearerTokenAuthenticationFilter(String token) {
		this.expected = token.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header == null || !header.startsWith(PREFIX)) {
			unauthorized(response, "a bearer token is required");
			return;
		}
		byte[] presented = header.substring(PREFIX.length()).trim().getBytes(StandardCharsets.UTF_8);
		if (!MessageDigest.isEqual(this.expected, presented)) {
			unauthorized(response, "that token was not accepted");
			return;
		}
		// A console is not a person; the authority is what the API authorizes on.
		SecurityContextHolder.getContext()
			.setAuthentication(new UsernamePasswordAuthenticationToken("uniauth-admin-api", null,
					AuthorityUtils.createAuthorityList("ROLE_UNIAUTH_ADMIN_API")));
		try {
			chain.doFilter(request, response);
		}
		finally {
			SecurityContextHolder.clearContext();
		}
	}

	private static void unauthorized(HttpServletResponse response, String message) throws IOException {
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.getWriter().write("{\"error\":\"" + message + "\"}");
	}

}
