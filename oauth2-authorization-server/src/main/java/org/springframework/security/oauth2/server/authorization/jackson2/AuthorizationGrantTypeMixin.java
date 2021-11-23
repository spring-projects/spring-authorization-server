package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;


/**
 * Jackson Mixin class helps in serialize/deserialize
 * {@link org.springframework.security.oauth2.core.AuthorizationGrantType}.
 *
 * @author Junlin Zhou
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE,
        getterVisibility = JsonAutoDetect.Visibility.PUBLIC_ONLY, isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class AuthorizationGrantTypeMixin {

    @JsonGetter("value")
    abstract long getValue();

    @JsonCreator
    public AuthorizationGrantTypeMixin(@JsonProperty("value") String value) {
    }

}
