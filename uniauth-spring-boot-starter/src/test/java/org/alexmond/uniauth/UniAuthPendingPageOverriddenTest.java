package org.alexmond.uniauth;

import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An application that already serves the pending page keeps serving its own.
 *
 * <p>
 * This is the compatibility half of #11, and the reason the starter's page is a view
 * controller rather than a {@code @Controller}. The page was missing for long enough that
 * the documented answer was to supply it, so applications did — including this
 * repository's own {@code uniauth-examples/webapp}. A {@code @RequestMapping} on the same
 * path would be an ambiguous mapping and fail their context at startup: a page shipped to
 * help them would break everybody who had already worked around its absence.
 *
 * <p>
 * Two assertions, because either alone would pass for the wrong reason. The context
 * starting proves there is no ambiguous mapping; the body proves which handler won.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthPendingPageOverriddenTest.OwnWaitingRoom.class)
@TestPropertySource(
		properties = { "uniauth.enabled=true", "uniauth.internal.enabled=true", "uniauth.approval.enabled=true" })
class UniAuthPendingPageOverriddenTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theApplicationSOwnMappingWinsAndTheContextStillStarts() throws Exception {
		String page = this.mockMvc.perform(get("/pending"))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();

		assertThat(page).isEqualTo("the application's own waiting room");
		assertThat(page).doesNotContain("Waiting for approval");
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class OwnWaitingRoom {

		@RestController
		static class PendingPage {

			@GetMapping("/pending")
			String waiting() {
				return "the application's own waiting room";
			}

		}

	}

}
