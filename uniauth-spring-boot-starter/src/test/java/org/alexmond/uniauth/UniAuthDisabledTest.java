package org.alexmond.uniauth;

import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The master switch has to genuinely stand down, leaving Boot's own security in charge —
 * otherwise an app cannot opt out without also excluding the auto-configuration.
 */
@SpringBootTest(classes = TestApplication.class)
@TestPropertySource(properties = "uniauth.enabled=false")
class UniAuthDisabledTest {

	@Autowired
	ApplicationContext context;

	@Test
	void noUniAuthBeansAreContributed() {
		assertThat(context.getBeanNamesForType(AuthProviderRegistry.class)).isEmpty();
		assertThat(context.containsBean("uniAuthSecurityFilterChain")).isFalse();
	}

}
