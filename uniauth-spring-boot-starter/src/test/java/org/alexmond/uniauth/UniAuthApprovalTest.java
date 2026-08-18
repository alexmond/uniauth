package org.alexmond.uniauth;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalRecord;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.PrincipalIdentity;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The approval gate, driven through the real filter chain.
 *
 * <p>
 * LDAP is gated here and the internal store is not, which is the default split and also
 * the most useful thing to test: it proves the gate discriminates by mechanism rather
 * than stopping everyone.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.approval.enabled=true",
		"uniauth.approval.require-for=LDAP", "uniauth.approval.pending-page=/pending",

		"spring.ldap.embedded.base-dn=dc=example,dc=com", "spring.ldap.embedded.ldif=classpath:test-directory.ldif",
		"spring.ldap.embedded.port=13390",

		"uniauth.ldap.enabled=true", "uniauth.ldap.url=ldap://localhost:13390/dc=example,dc=com",
		"uniauth.ldap.user-dn-patterns[0]=uid={0},ou=people", "uniauth.ldap.group-search-base=ou=groups",

		"uniauth.internal.enabled=true", "uniauth.internal.users[0].username=alice",
		"uniauth.internal.users[0].password={noop}s3cret" })
class UniAuthApprovalTest {

	private static final ApprovalKey BOB = new ApprovalKey("ldap", "bob");

	@Autowired
	MockMvc mockMvc;

	@Autowired
	ApprovalStore store;

	/**
	 * The store is a singleton shared by every test in this context, so a decision taken
	 * in one method would otherwise be visible in the next.
	 */
	@BeforeEach
	void forgetPreviousDecisions() {
		this.store.remove(BOB);
		this.store.remove(new ApprovalKey("internal", "alice"));
	}

	@Test
	void revokingSendsAnApprovedPrincipalBackToTheWaitingRoom() throws Exception {
		HttpSession session = signIn("bob", "bobspassword");
		this.store.recordPending(BOB, PrincipalIdentity.ofName("bob"), AuthProviderType.LDAP);
		this.store.decide(BOB, ApprovalStatus.APPROVED, "admin", java.util.List.of("USER"));
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());

		this.store.remove(BOB);

		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(redirectedUrl("/pending"));
		assertThat(this.store.statusOf(BOB)).isEqualTo(ApprovalStatus.PENDING);
	}

	@Test
	void aGatedPrincipalAuthenticatesButIsHeldAtThePendingPage() throws Exception {
		HttpSession session = signIn("bob", "bobspassword");

		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(redirectedUrl("/pending"));
	}

	@Test
	void theFirstRequestRecordsThePrincipalAsPending() throws Exception {
		HttpSession session = signIn("bob", "bobspassword");
		this.mockMvc.perform(get("/").session((MockHttpSession) session));

		assertThat(this.store.statusOf(BOB)).isEqualTo(ApprovalStatus.PENDING);
		assertThat(this.store.pending()).extracting(ApprovalRecord::key).contains(BOB);
		assertThat(this.store.find(BOB)).get().satisfies((record) -> {
			assertThat(record.mechanism()).isEqualTo(AuthProviderType.LDAP);
			assertThat(record.firstSeen()).isNotNull();
			assertThat(record.decidedAt()).isNull();
		});
	}

	@Test
	void thePendingPageItselfStaysReachable() throws Exception {
		HttpSession session = signIn("bob", "bobspassword");

		// Without this the redirect would loop: the gate would keep out the very page it
		// sends people to.
		this.mockMvc.perform(get("/pending").session((MockHttpSession) session)).andExpect(status().isNotFound());
	}

	@Test
	void approvingLetsThePrincipalThrough() throws Exception {
		HttpSession session = signIn("bob", "bobspassword");
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(redirectedUrl("/pending"));

		this.store.decide(BOB, ApprovalStatus.APPROVED, "admin", java.util.List.of("USER"));

		// Same session, no re-authentication needed.
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());
		assertThat(this.store.pending()).extracting(ApprovalRecord::key).doesNotContain(BOB);
	}

	@Test
	void denyingIsAPlainRefusalRatherThanAnInvitationToWait() throws Exception {
		HttpSession session = signIn("bob", "bobspassword");
		this.mockMvc.perform(get("/").session((MockHttpSession) session));

		this.store.decide(BOB, ApprovalStatus.DENIED, "admin", java.util.List.of("USER"));

		// 403, not a redirect — telling someone already refused to keep waiting is a lie.
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isForbidden());
	}

	@Test
	void anUngatedMechanismIsUnaffected() throws Exception {
		HttpSession session = signIn("alice", "s3cret");

		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());
		assertThat(this.store.statusOf(new ApprovalKey("internal", "alice"))).isEqualTo(ApprovalStatus.UNKNOWN);
	}

	@Test
	void anonymousRequestsStillGoToTheChooser() throws Exception {
		this.mockMvc.perform(get("/")).andExpect(redirectedUrl("/login"));
	}

	private HttpSession signIn(String username, String password) throws Exception {
		return this.mockMvc.perform(formLogin("/login").user(username).password(password))
			.andExpect(authenticated().withUsername(username))
			.andReturn()
			.getRequest()
			.getSession();
	}

	@Test
	void theRolesAnApproverGrantedReachThePrincipal() throws Exception {
		// The gap this closes: approval used to be a boolean, so a principal cleared the
		// gate and was then refused by every hasRole() rule in the application. Driven
		// through a real request so the filter that grants them actually runs — a mock
		// authentication would bypass it and prove nothing.
		HttpSession session = signIn("bob", "bobspassword");
		this.store.recordPending(BOB, PrincipalIdentity.ofName("bob"), AuthProviderType.LDAP);
		this.store.decide(BOB, ApprovalStatus.APPROVED, "admin", java.util.List.of("ADMIN"));

		MvcResult result = this.mockMvc.perform(get("/").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andReturn();

		assertThat(authoritiesFrom(result)).contains("ROLE_ADMIN");
	}

	@Test
	void theMechanismSurvivesTheRolesBeingAdded() throws Exception {
		// The authentication is rebuilt to carry the new authorities, and its concrete
		// type is how MechanismResolver knows which provider answered. Flattening it
		// would silently break the approval key on the next request.
		HttpSession session = signIn("bob", "bobspassword");
		this.store.recordPending(BOB, PrincipalIdentity.ofName("bob"), AuthProviderType.LDAP);
		this.store.decide(BOB, ApprovalStatus.APPROVED, "admin", java.util.List.of("ADMIN"));

		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());

		// Still approved, not re-pended — which only holds if the key still resolves.
		assertThat(this.store.statusOf(BOB)).isEqualTo(ApprovalStatus.APPROVED);
	}

	private static java.util.List<String> authoritiesFrom(MvcResult result) {
		org.springframework.security.core.context.SecurityContext context = (org.springframework.security.core.context.SecurityContext) result
			.getRequest()
			.getSession()
			.getAttribute("SPRING_SECURITY_CONTEXT");
		return context.getAuthentication()
			.getAuthorities()
			.stream()
			.map(org.springframework.security.core.GrantedAuthority::getAuthority)
			.toList();
	}

	@Test
	void aPendingRecordCarriesNoRoles() {
		this.store.recordPending(BOB, PrincipalIdentity.ofName("bob"), AuthProviderType.LDAP);

		assertThat(this.store.find(BOB)).get().extracting(ApprovalRecord::roles).isEqualTo(java.util.List.of());
	}

}
