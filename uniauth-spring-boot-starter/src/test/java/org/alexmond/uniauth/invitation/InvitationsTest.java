package org.alexmond.uniauth.invitation;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Carrying the token across the provider round trip.
 */
class InvitationsTest {

	@Test
	void whatGoesOnTheSessionSurvivesASerializingSessionStore() {
		// spring-session-data-redis and spring-session-jdbc both default to JDK
		// serialization, and so do Tomcat's session persistence and replication. A
		// session attribute that cannot be serialized throws when the session is saved —
		// which here would land on the POST that accepts the invitation, the only flow
		// this feature has, in exactly the multi-instance deployment the docs point at.
		MockHttpServletRequest request = new MockHttpServletRequest();
		Invitations.stash(request, InvitationToken.generate());

		Object stored = request.getSession().getAttribute(Invitations.SESSION_ATTRIBUTE);

		assertThatNoException().isThrownBy(() -> {
			try (ObjectOutputStream out = new ObjectOutputStream(new ByteArrayOutputStream())) {
				out.writeObject(stored);
			}
		});
	}

	@Test
	void theTokenComesBackOutAsItWentIn() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		InvitationToken token = InvitationToken.generate();

		Invitations.stash(request, token);

		assertThat(Invitations.pending(request)).isEqualTo(token);
	}

	@Test
	void readingDoesNotCreateASession() {
		// Called on every authorized request. Creating a session for each would turn a
		// stateless API call into a stateful one.
		MockHttpServletRequest request = new MockHttpServletRequest();

		assertThat(Invitations.pending(request)).isNull();
		assertThat(request.getSession(false)).isNull();
	}

	@Test
	void clearingWithoutASessionIsNotAnError() {
		Invitations.clear(new MockHttpServletRequest());
	}

	@Test
	void aSessionCarryingSomethingUnexpectedReadsAsCarryingNothing() {
		// Defensive: a rolling upgrade can hand this code a session written by a previous
		// version. A ClassCastException on every request would be a worse answer than
		// "no invitation", which simply sends the person through the ordinary gate.
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.getSession().setAttribute(Invitations.SESSION_ATTRIBUTE, 42);

		assertThat(Invitations.pending(request)).isNull();
	}

}
