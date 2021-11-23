package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * Jackson Mixin class helps in serialize/deserialize
 * {@link java.time.Instant}.
 *
 * @author Junlin Zhou
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE, getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE, setterVisibility = JsonAutoDetect.Visibility.NONE,
        creatorVisibility = JsonAutoDetect.Visibility.NONE)
abstract class InstantMixin {

    @JsonCreator
    static void ofSeconds(@JsonProperty("seconds") long seconds, @JsonProperty("nano") long nanoAdjustment) {
    }

    @JsonGetter("seconds")
    abstract long getSeconds();

    @JsonGetter("nano")
    abstract int getNano();

}
