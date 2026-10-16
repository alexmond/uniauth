package org.alexmond.uniauth;

import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * What the chooser actually renders for a branded provider.
 *
 * <p>
 * Brand guidelines are conditions attached to using the service, not styling preferences,
 * and the default template rendered every provider identically as its bare brand name —
 * which is the one thing Google's guidelines name as forbidden (#8). Every consumer that
 * enabled a Google registration inherited that, so the assertions below are about
 * compliance rather than appearance.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(
		properties = { "uniauth.enabled=true", "spring.security.oauth2.client.registration.google.client-id=demo-id",
				"spring.security.oauth2.client.registration.google.client-secret=demo-secret",
				"spring.security.oauth2.client.registration.github.client-id=demo-id",
				"spring.security.oauth2.client.registration.github.client-secret=demo-secret" })
class UniAuthBrandButtonTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theGoogleButtonCarriesTheRequiredCallToActionAndNotTheBareBrandName() throws Exception {
		String page = chooser();

		assertThat(page).contains("Sign in with Google");
		// The forbidden rendering: the anchor's whole content being the single word.
		assertThat(page).doesNotContain(">Google<");
	}

	@Test
	void theGoogleButtonCarriesTheFullColourGAndNotAMonochromeOne() throws Exception {
		String page = chooser();

		// The four brand colours of the standard G. A monochrome mark, or a recoloured
		// one, is explicitly disallowed — so the presence of all four is the check.
		assertThat(page).contains("#ea4335").contains("#4285f4").contains("#fbbc05").contains("#34a853");
		// And it must not be swept up by the theme-switching rule that serves the
		// official black and white variants of the other marks.
		assertThat(page).doesNotContain("provider__mark provider__mark--mono\"><svg viewBox=\"0 0 48 48\"");
	}

	@Test
	void theButtonCarriesGooglesMandatedPaletteInBothThemes() throws Exception {
		String page = chooser();

		assertThat(page).contains("#747775").contains("#1f1f1f");
		assertThat(page).contains("#131314").contains("#8e918f").contains("#e3e3e3");
	}

	@Test
	void everyBrandedButtonReadsTheSameWayWhereTheGuidelinesAllowIt() throws Exception {
		// GitHub mandates no wording of its own and takes the shared phrasing, so a
		// chooser offering both reads as one set of buttons rather than two conventions.
		String page = chooser();

		assertThat(page).contains("Sign in with Google").contains("Sign in with GitHub");
	}

	@Test
	void theDividerDoesNotRepeatWhatEveryButtonAlreadySays() throws Exception {
		// "or continue with" above a column of "Sign in with X" buttons said the same
		// thing twice, and in wording Google does not list for Microsoft.
		assertThat(chooser()).doesNotContain("or continue with");
	}

	private String chooser() throws Exception {
		return this.mockMvc.perform(get("/login"))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith("text/html"))
			.andReturn()
			.getResponse()
			.getContentAsString();
	}

}
