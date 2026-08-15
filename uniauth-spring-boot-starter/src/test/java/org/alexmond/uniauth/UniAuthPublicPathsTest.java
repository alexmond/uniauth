package org.alexmond.uniauth;

import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code uniauth.public-paths} exists so an application can open up routes without
 * declaring its own {@code SecurityFilterChain} — which would make the whole starter back
 * off. The test guards both halves: the listed path opens, and everything else stays
 * shut.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "uniauth.internal.enabled=true", "uniauth.internal.users[0].username=alice",
		"uniauth.internal.users[0].password={noop}s3cret", "uniauth.public-paths[0]=/",
		"uniauth.public-paths[1]=/assets/**" })
class UniAuthPublicPathsTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void listedPathIsServedWithoutASession() throws Exception {
		this.mockMvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	void wildcardPathIsServedWithoutASession() throws Exception {
		// No handler is mapped there, so 404 is the proof: security let it through rather
		// than bouncing it to the login page.
		this.mockMvc.perform(get("/assets/app.css")).andExpect(status().isNotFound());
	}

	@Test
	void unlistedPathStillRequiresASession() throws Exception {
		this.mockMvc.perform(get("/private")).andExpect(redirectedUrl("/login"));
	}

}
