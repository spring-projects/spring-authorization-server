package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * Jackson Mixin class helps in serialize/deserialize
 * {@link org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken}.
 *
 * @author Junlin Zhou
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(using = OAuth2ClientAuthenticationTokenDeserializer.class)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class OAuth2ClientAuthenticationTokenMixin {
}
