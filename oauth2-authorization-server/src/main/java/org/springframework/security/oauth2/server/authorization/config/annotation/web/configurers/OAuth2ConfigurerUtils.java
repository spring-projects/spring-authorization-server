/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.Map;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.StringUtils;

/**
 * Utility methods for the OAuth 2.0 Configurers.
 *
 * @author Joe Grandja
 * @since 0.1.2
 */
final class OAuth2ConfigurerUtils {

	private OAuth2ConfigurerUtils() {
	}

	static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepository(B builder) {
		RegisteredClientRepository registeredClientRepository = builder.getSharedObject(RegisteredClientRepository.class);
		if (registeredClientRepository == null) {
			registeredClientRepository = getBean(builder, RegisteredClientRepository.class);
			builder.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
		}
		return registeredClientRepository;
	}

	static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationService(B builder) {
		OAuth2AuthorizationService authorizationService = builder.getSharedObject(OAuth2AuthorizationService.class);
		if (authorizationService == null) {
			authorizationService = getOptionalBean(builder, OAuth2AuthorizationService.class);
			if (authorizationService == null) {
				authorizationService = new InMemoryOAuth2AuthorizationService();
			}
			builder.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		}
		return authorizationService;
	}

	static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationConsentService getAuthorizationConsentService(B builder) {
		OAuth2AuthorizationConsentService authorizationConsentService = builder.getSharedObject(OAuth2AuthorizationConsentService.class);
		if (authorizationConsentService == null) {
			authorizationConsentService = getOptionalBean(builder, OAuth2AuthorizationConsentService.class);
			if (authorizationConsentService == null) {
				authorizationConsentService = new InMemoryOAuth2AuthorizationConsentService();
			}
			builder.setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
		}
		return authorizationConsentService;
	}

	@SuppressWarnings("unchecked")
	static <B extends HttpSecurityBuilder<B>> OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(B builder) {
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = builder.getSharedObject(OAuth2TokenGenerator.class);
		if (tokenGenerator == null) {
			tokenGenerator = getOptionalBean(builder, OAuth2TokenGenerator.class);
			if (tokenGenerator == null) {
				JwtGenerator jwtGenerator = getJwtGenerator(builder);
				OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
				OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer = getAccessTokenCustomizer(builder);
				if (accessTokenCustomizer != null) {
					accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
				}
				OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
				if (jwtGenerator != null) {
					tokenGenerator = new DelegatingOAuth2TokenGenerator(
							jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
				} else {
					tokenGenerator = new DelegatingOAuth2TokenGenerator(
							accessTokenGenerator, refreshTokenGenerator);
				}
			}
			builder.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
		}
		return tokenGenerator;
	}

	private static <B extends HttpSecurityBuilder<B>> JwtGenerator getJwtGenerator(B builder) {
		JwtGenerator jwtGenerator = builder.getSharedObject(JwtGenerator.class);
		if (jwtGenerator == null) {
			JwtEncoder jwtEncoder = getJwtEncoder(builder);
			if (jwtEncoder != null) {
				jwtGenerator = new JwtGenerator(jwtEncoder);
				OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = getJwtCustomizer(builder);
				if (jwtCustomizer != null) {
					jwtGenerator.setJwtCustomizer(jwtCustomizer);
				}
				builder.setSharedObject(JwtGenerator.class, jwtGenerator);
			}
		}
		return jwtGenerator;
	}

	private static <B extends HttpSecurityBuilder<B>> JwtEncoder getJwtEncoder(B builder) {
		JwtEncoder jwtEncoder = builder.getSharedObject(JwtEncoder.class);
		if (jwtEncoder == null) {
			jwtEncoder = getOptionalBean(builder, JwtEncoder.class);
			if (jwtEncoder == null) {
				JWKSource<SecurityContext> jwkSource = getJwkSource(builder);
				if (jwkSource != null) {
					jwtEncoder = new NimbusJwtEncoder(jwkSource);
				}
			}
			if (jwtEncoder != null) {
				builder.setSharedObject(JwtEncoder.class, jwtEncoder);
			}
		}
		return jwtEncoder;
	}

	@SuppressWarnings("unchecked")
	static <B extends HttpSecurityBuilder<B>> JWKSource<SecurityContext> getJwkSource(B builder) {
		JWKSource<SecurityContext> jwkSource = builder.getSharedObject(JWKSource.class);
		if (jwkSource == null) {
			ResolvableType type = ResolvableType.forClassWithGenerics(JWKSource.class, SecurityContext.class);
			jwkSource = getOptionalBean(builder, type);
			if (jwkSource != null) {
				builder.setSharedObject(JWKSource.class, jwkSource);
			}
		}
		return jwkSource;
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2TokenCustomizer<JwtEncodingContext> getJwtCustomizer(B builder) {
		ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, JwtEncodingContext.class);
		return getOptionalBean(builder, type);
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2TokenCustomizer<OAuth2TokenClaimsContext> getAccessTokenCustomizer(B builder) {
		ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, OAuth2TokenClaimsContext.class);
		return getOptionalBean(builder, type);
	}

	static <B extends HttpSecurityBuilder<B>> ProviderSettings getProviderSettings(B builder) {
		ProviderSettings providerSettings = builder.getSharedObject(ProviderSettings.class);
		if (providerSettings == null) {
			providerSettings = getBean(builder, ProviderSettings.class);
			builder.setSharedObject(ProviderSettings.class, providerSettings);
		}
		return providerSettings;
	}

	static <B extends HttpSecurityBuilder<B>, T> T getBean(B builder, Class<T> type) {
		return builder.getSharedObject(ApplicationContext.class).getBean(type);
	}

	@SuppressWarnings("unchecked")
	static <B extends HttpSecurityBuilder<B>, T> T getBean(B builder, ResolvableType type) {
		ApplicationContext context = builder.getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(type);
		if (names.length == 1) {
			return (T) context.getBean(names[0]);
		}
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		throw new NoSuchBeanDefinitionException(type);
	}

	static <B extends HttpSecurityBuilder<B>, T> T getOptionalBean(B builder, Class<T> type) {
		Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
				builder.getSharedObject(ApplicationContext.class), type);
		if (beansMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
					"Expected single matching bean of type '" + type.getName() + "' but found " +
							beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
		}
		return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
	}

	@SuppressWarnings("unchecked")
	static <B extends HttpSecurityBuilder<B>, T> T getOptionalBean(B builder, ResolvableType type) {
		ApplicationContext context = builder.getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(type);
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		return names.length == 1 ? (T) context.getBean(names[0]) : null;
	}

}
