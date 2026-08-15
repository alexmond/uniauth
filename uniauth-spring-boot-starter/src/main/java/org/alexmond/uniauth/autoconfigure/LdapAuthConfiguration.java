package org.alexmond.uniauth.autoconfigure;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.util.StringUtils;

/**
 * LDAP bind authentication.
 *
 * <p>
 * Shares the username/password form with {@link InternalAuthConfiguration}: both
 * contribute an {@code AuthenticationProvider}, and the chain tries each in turn, so a
 * deployment can run a directory alongside a couple of local break-glass accounts.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(LdapAuthenticationProvider.class)
@ConditionalOnProperty(prefix = "uniauth.ldap", name = "enabled", havingValue = "true")
class LdapAuthConfiguration {

	static final String UNIAUTH_LDAP_CONTEXT_SOURCE = "uniAuthLdapContextSource";

	/**
	 * A context source dedicated to UniAuth, deliberately <em>not</em> resolved by type.
	 * Boot's own {@code LdapAutoConfiguration} publishes a
	 * {@link BaseLdapPathContextSource} too (bound to {@code spring.ldap.*}); qualifying
	 * ours keeps {@code uniauth.ldap.url} from being silently ignored when both are
	 * present.
	 */
	@Bean
	@Qualifier(UNIAUTH_LDAP_CONTEXT_SOURCE)
	@ConditionalOnMissingBean(name = "uniAuthLdapContextSource")
	DefaultSpringSecurityContextSource uniAuthLdapContextSource(UniAuthProperties properties) {
		UniAuthProperties.Ldap ldap = properties.getLdap();
		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(ldap.getUrl());
		if (StringUtils.hasText(ldap.getManagerDn())) {
			contextSource.setUserDn(ldap.getManagerDn());
			contextSource.setPassword(ldap.getManagerPassword());
		}
		return contextSource;
	}

	@Bean
	AuthenticationProvider uniAuthLdapAuthenticationProvider(UniAuthProperties properties,
			@Qualifier(UNIAUTH_LDAP_CONTEXT_SOURCE) BaseLdapPathContextSource contextSource) {
		UniAuthProperties.Ldap ldap = properties.getLdap();

		BindAuthenticator authenticator = new BindAuthenticator(contextSource);
		authenticator.setUserDnPatterns(ldap.getUserDnPatterns().toArray(String[]::new));

		DefaultLdapAuthoritiesPopulator authorities = new DefaultLdapAuthoritiesPopulator(contextSource,
				ldap.getGroupSearchBase());
		authorities.setGroupSearchFilter(ldap.getGroupSearchFilter());

		return new LdapAuthenticationProvider(authenticator, authorities);
	}

}
