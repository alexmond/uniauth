package org.alexmond.uniauth;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The waiting page's template is configuration, not a constant.
 *
 * <p>
 * Dropping a {@code templates/uniauth/pending.html} of your own ahead of the starter jar
 * works and is the same re-skin path the chooser takes, but it is the only route if the
 * view name is hard-coded — and it forces an application into the starter's own template
 * path to use a page it already has somewhere else. Naming it is the smaller ask, and the
 * pending <em>page</em> was configurable from the start, so its view should be too.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=true",
		"uniauth.internal.users[0].username=held", "uniauth.internal.users[0].password={noop}pw",
		"uniauth.approval.enabled=true", "uniauth.approval.require-for=INTERNAL",
		"uniauth.approval.pending-view=waiting-room-of-our-own" })
class UniAuthPendingViewTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theConfiguredViewIsRenderedAndStillGetsTheModel() throws Exception {
		HttpSession session = this.mockMvc.perform(formLogin("/login").user("held").password("pw"))
			.andReturn()
			.getRequest()
			.getSession();

		String page = this.mockMvc.perform(get("/pending").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();

		assertThat(page).contains("Our own waiting room for");
		// The model has to survive the swap, or a replacement view can say less than the
		// one it replaced and nobody finds out until somebody is actually held.
		assertThat(page).contains("held");
		assertThat(page).doesNotContain("Waiting for approval");
	}

}
