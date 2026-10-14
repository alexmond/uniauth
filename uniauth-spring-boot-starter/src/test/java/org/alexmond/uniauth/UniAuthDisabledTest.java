package org.alexmond.uniauth;

import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * The master switch has to genuinely stand down, leaving Boot's own security in charge —
 * otherwise an app cannot opt out without also excluding the auto-configuration.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = "uniauth.enabled=false")
class UniAuthDisabledTest {

	@Autowired
	ApplicationContext context;

	@Autowired
	MockMvc mockMvc;

	@Test
	void noUniAuthBeansAreContributed() {
		assertThat(context.getBeanNamesForType(AuthProviderRegistry.class)).isEmpty();
		assertThat(context.containsBean("uniAuthSecurityFilterChain")).isFalse();
	}

	@Test
	void standingDownDoesNotLeaveTheApplicationOpen() throws Exception {
		// What "backs off entirely" actually means, and the documentation used to imply
		// otherwise (#33). Boot's own security auto-configuration is still on the
		// classpath and takes over, so every path stays shut — behind a login nobody
		// configured, with a generated password. An application that wants to run open
		// declares a permit-all chain of its own; see configuration.adoc.
		this.mockMvc.perform(get("/"))
			.andExpect(
					(result) -> assertThat(result.getResponse().getStatus()).as("UniAuth off must not mean no security")
						.isNotEqualTo(200));
	}

}
