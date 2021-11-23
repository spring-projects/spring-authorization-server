package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * Jackson Mixin class helps in serialize/deserialize
 * {@link org.springframework.security.oauth2.server.authorization.config.TokenSettings}.
 *
 * @author Junlin Zhou
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(using = TokenSettingsDeserializer.class)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class TokenSettingsMixin {
}
