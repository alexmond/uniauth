package org.alexmond.uniauth.autoconfigure;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.InMemoryApprovalStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationRedemption;
import org.alexmond.uniauth.invitation.InvitationStatus;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.invitation.InvitationToken;
import org.alexmond.uniauth.web.UniAuthInvitationController;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What gets wired, and what gets said about it.
 */
@ExtendWith(OutputCaptureExtension.class)
class InvitationConfigurationTest {

	/**
	 * The starter's chain needs Spring Security's own {@code HttpSecurity} prototype,
	 * which comes from Boot's security auto-configuration rather than from anything here.
	 * A runner carrying only this starter fails on a missing {@code HttpSecurity}, which
	 * looks like a fault in the configuration under test and is not one.
	 */
	private static final Class<?>[] REQUIRED = { SecurityAutoConfiguration.class,
			ServletWebSecurityAutoConfiguration.class, UniAuthAutoConfiguration.class };

	private final WebApplicationContextRunner runner = runner("uniauth.enabled=true", "uniauth.approval.enabled=true");

	private static WebApplicationContextRunner runner(String... properties) {
		return new WebApplicationContextRunner().withConfiguration(AutoConfigurations.of(REQUIRED))
			.withPropertyValues(properties);
	}

	@Test
	void nothingIsWiredUntilInvitationsAreAskedFor() {
		this.runner.run((context) -> assertThat(context).hasNotFailed()
			.doesNotHaveBean(InvitationStore.class)
			.doesNotHaveBean(InvitationRedemption.class)
			.doesNotHaveBean(UniAuthInvitationController.class));
	}

	@Test
	void invitationsNeedTheApprovalGateBecauseRedemptionWritesAnApprovalRecord() {
		// Structural rather than documented: InvitationConfiguration is imported from
		// ApprovalConfiguration, so switching invitations on alone wires nothing.
		runner("uniauth.enabled=true", "uniauth.approval.invitations.enabled=true")
			.run((context) -> assertThat(context).hasNotFailed().doesNotHaveBean(InvitationStore.class));
	}

	@Test
	void andSaysSoRatherThanWiringNothingInSilence(CapturedOutput output) {
		// Otherwise it is the same experience the path validation exists to prevent,
		// reached by another route: every invitation 404s and nothing anywhere says why.
		runner("uniauth.enabled=true", "uniauth.approval.invitations.enabled=true")
			.run((context) -> assertThat(context).hasNotFailed());

		assertThat(output).contains("uniauth.approval.enabled");
	}

	@Test
	void askingForInvitationsWiresTheStoreTheCollaboratorAndTheEndpoint() {
		this.runner.withPropertyValues("uniauth.approval.invitations.enabled=true")
			.run((context) -> assertThat(context).hasSingleBean(InvitationStore.class)
				.hasSingleBean(InvitationRedemption.class)
				.hasSingleBean(UniAuthInvitationController.class));
	}

	@Test
	void theDefaultStoreSaysItForgetsEverything(CapturedOutput output) {
		// Durability is the deployment's choice, so this warns rather than refuses — the
		// bargain InMemoryApprovalStore already strikes. But it has to be said: a console
		// pointed at an in-memory store sees only the invitations created in its own
		// process, and that reads as a broken console.
		this.runner.withPropertyValues("uniauth.approval.invitations.enabled=true")
			.run((context) -> assertThat(context).hasNotFailed());

		assertThat(output).contains("InMemoryInvitationStore").contains("lost on restart");
	}

	@Test
	void anApplicationSOwnStoreIsUsedAndNothingIsWarnedAbout(CapturedOutput output) {
		this.runner.withPropertyValues("uniauth.approval.invitations.enabled=true")
			.withUserConfiguration(DurableStore.class)
			.run((context) -> assertThat(context).getBean(InvitationStore.class)
				.isInstanceOf(DurableStore.PretendDatabase.class));

		assertThat(output).doesNotContain("lost on restart");
	}

	@Test
	void aPathWithoutTheTokenPlaceholderFailsTheContextRatherThan404IngForever() {
		// Review Focus 1, at the layer where a person actually hits it.
		this.runner
			.withPropertyValues("uniauth.approval.invitations.enabled=true",
					"uniauth.approval.invitations.path=/invite")
			.run((context) -> assertThat(context).hasFailed().getFailure().rootCause().hasMessageContaining("{token}"));
	}

	@Test
	void defaultPathResolvesWhenNothingIsConfigured() {
		// The mapping's default value contains braces of its own. If Spring's placeholder
		// parser miscounts them the context fails here, loudly, rather than in somebody's
		// deployment.
		this.runner.withPropertyValues("uniauth.approval.invitations.enabled=true")
			.run((context) -> assertThat(context).hasNotFailed().hasSingleBean(UniAuthInvitationController.class));
	}

	@Configuration(proxyBeanMethods = false)
	static class DurableStore {

		@Bean
		InvitationStore applicationsOwnStore() {
			return new PretendDatabase();
		}

		@Bean
		ApprovalStore applicationsOwnApprovals() {
			return new InMemoryApprovalStore();
		}

		/**
		 * Stands in for a database-backed store. Deliberately not a subclass of ours: the
		 * assertion is that the starter backed off, and a subclass would satisfy an
		 * {@code instanceof} against the very class it is meant to have replaced.
		 */
		static class PretendDatabase implements InvitationStore {

			@Override
			public Invitation create(String subjectRef, Duration ttl, List<String> roles, String createdBy) {
				throw new UnsupportedOperationException();
			}

			@Override
			public Optional<Invitation> find(InvitationToken token) {
				return Optional.empty();
			}

			@Override
			public Invitation redeem(InvitationToken token, ApprovalKey admitted) {
				throw new UnsupportedOperationException();
			}

			@Override
			public void revoke(InvitationToken token, String revokedBy) {
			}

			@Override
			public List<Invitation> list(InvitationStatus... statuses) {
				return List.of();
			}

		}

	}

}
