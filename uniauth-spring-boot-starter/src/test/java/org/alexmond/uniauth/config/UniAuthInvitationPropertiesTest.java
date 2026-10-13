package org.alexmond.uniauth.config;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * The invitation properties, and the one of them that can be set to something that never
 * works.
 */
class UniAuthInvitationPropertiesTest {

	@Test
	void invitationsAreOffByDefaultLikeEveryOtherMechanismHere() {
		UniAuthProperties.Approval.Invitations invitations = new UniAuthProperties().getApproval().getInvitations();

		assertThat(invitations.isEnabled()).isFalse();
		assertThat(invitations.isInviteOnly()).isFalse();
		assertThat(invitations.getPath()).isEqualTo("/invite/{token}");
		assertThat(invitations.getDefaultExpiry()).isEqualTo(Duration.ofDays(14));
	}

	@Test
	void aPathWithoutTheTokenPlaceholderIsRejectedAtStartup() {
		// Review Focus 1. Without this the controller maps a literal path, every
		// invitation 404s, and nothing anywhere says why.
		UniAuthProperties.Approval.Invitations invitations = new UniAuthProperties.Approval.Invitations();
		invitations.setPath("/invite");

		assertThatIllegalStateException().isThrownBy(invitations::validate)
			.withMessageContaining("{token}")
			.withMessageContaining("/invite");
	}

	@Test
	void aPathNotStartingWithASlashIsRejectedAtStartup() {
		UniAuthProperties.Approval.Invitations invitations = new UniAuthProperties.Approval.Invitations();
		invitations.setPath("invite/{token}");

		assertThatIllegalStateException().isThrownBy(invitations::validate);
	}

	@Test
	void aCustomPathIsAccepted() {
		UniAuthProperties.Approval.Invitations invitations = new UniAuthProperties.Approval.Invitations();
		invitations.setPath("/welcome/{token}");

		invitations.validate();

		assertThat(invitations.getPath()).isEqualTo("/welcome/{token}");
	}

	@Test
	void theDurationBindsInBootSShorthand() {
		// "14d" rather than "PT336H", because nobody writes an invitation expiry in ISO
		// 8601.
		UniAuthProperties bound = new Binder(new MapConfigurationPropertySource(java.util.Map.of(
				"uniauth.approval.invitations.enabled", "true", "uniauth.approval.invitations.default-expiry", "3d",
				"uniauth.approval.invitations.invite-only", "true")))
			.bind("uniauth", UniAuthProperties.class)
			.get();

		assertThat(bound.getApproval().getInvitations().getDefaultExpiry()).isEqualTo(Duration.ofDays(3));
		assertThat(bound.getApproval().getInvitations().isInviteOnly()).isTrue();
	}

}
