package com.accesso.security.oauth2.server.authorization.authentication;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A copy of the OAuth2TokenEndpointFilters default "sendAccessTokenResponse"
 * method.  The only difference is the call to addAccessoResponseParameters that
 * is added into the heart of it, and that's really the only extension that was required.
 * (I.e. the current customization supported is a bit coarse grained if all you
 * want to do is add standard fields.)
 */
public class AccessoAccessTokenResponseCustomizer implements AuthenticationSuccessHandler {

	private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();

	private final JwtDecoder decoder;

	public AccessoAccessTokenResponseCustomizer	(JwtDecoder decoder) {
		this.decoder = decoder;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) authentication;

		OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();
		OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();
		Map<String, Object> additionalParameters = accessTokenAuthentication.getAdditionalParameters();

		OAuth2AccessTokenResponse.Builder builder =
				OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
						.tokenType(accessToken.getTokenType())
						.scopes(accessToken.getScopes());
		if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
			builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
		}
		if (refreshToken != null) {
			builder.refreshToken(refreshToken.getTokenValue());
		}

		// Start of customization
		additionalParameters = addAccessoResponseParameters(additionalParameters, accessTokenAuthentication);
		// End of customization

		if (!CollectionUtils.isEmpty(additionalParameters)) {
			builder.additionalParameters(additionalParameters);
		}

		OAuth2AccessTokenResponse accessTokenResponse = builder.build();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse);
	}

	// Based on what I see in the TE2 token endpoint, it just echos/adds all custom
	// token attributes into the http response as well, so this is coded to do exactly
	// that.
	Map<String, Object> addAccessoResponseParameters(Map<String, Object> currentAdditionalParameters,
			OAuth2AccessTokenAuthenticationToken authentication) {
		String accessTokenJwt = authentication.getAccessToken().getTokenValue();
		Jwt jwt = decoder.decode(accessTokenJwt);
		Map<String, Object> claims = jwt.getClaims();
		Set<String> stdFields = Stream.of("access_token", "refresh_token", "scope", "token_type", "expires_in", "id_token")
				.collect(Collectors.toSet());
		return Stream.concat( currentAdditionalParameters.entrySet().stream(),
				claims.entrySet().stream().filter(entry -> ! stdFields.contains(entry.getKey())))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}
}
