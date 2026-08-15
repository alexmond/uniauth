package org.alexmond.uniauth.autoconfigure;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.oauth2.GithubEmailOAuth2UserService;
import org.alexmond.uniauth.oauth2.MicrosoftMultiTenantIdTokenValidator;
import org.alexmond.uniauth.provider.AuthProviderBrand;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.web.client.RestClient;

/**
 * Opt-in fixes for providers whose behaviour Spring's defaults do not cover.
 *
 * <p>
 * Both are off unless asked for, and both are narrow. This is the layer that keeps brand
 * out of {@code AuthProviderType}: the differences these adapters paper over are real,
 * but they are adapters on one shared filter chain, not separate mechanisms.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(ClientRegistration.class)
class Oauth2AdaptersConfiguration {

	/**
	 * Adds the second call GitHub requires before an email address is available. Declared
	 * as the application's {@code OAuth2UserService}, which Spring Security picks up
	 * automatically for the userinfo stage.
	 */
	@Bean
	@ConditionalOnProperty(prefix = "uniauth.oauth2.github", name = "fetch-email", havingValue = "true")
	@ConditionalOnMissingBean
	OAuth2UserService<OAuth2UserRequest, OAuth2User> uniAuthOauth2UserService(UniAuthProperties properties) {
		return new GithubEmailOAuth2UserService(new DefaultOAuth2UserService(), RestClient.create(),
				properties.getOauth2().getGithub().getEmailsUri());
	}

	/**
	 * Relaxes id_token issuer validation to a tenant template, for Microsoft
	 * registrations only. Every other registration keeps Spring's stock validator, so
	 * turning this on cannot weaken a Google or Okta login sharing the same application.
	 */
	@Bean
	@ConditionalOnProperty(prefix = "uniauth.oauth2.microsoft", name = "multi-tenant", havingValue = "true")
	@ConditionalOnMissingBean
	JwtDecoderFactory<ClientRegistration> uniAuthIdTokenDecoderFactory() {
		OidcIdTokenDecoderFactory factory = new OidcIdTokenDecoderFactory();
		factory.setJwtValidatorFactory(Oauth2AdaptersConfiguration::validatorFor);
		return factory;
	}

	private static OAuth2TokenValidator<Jwt> validatorFor(ClientRegistration registration) {
		if (AuthProviderBrand.detect(registration) == AuthProviderBrand.MICROSOFT) {
			return new MicrosoftMultiTenantIdTokenValidator(registration);
		}
		return new OidcIdTokenValidator(registration);
	}

}
