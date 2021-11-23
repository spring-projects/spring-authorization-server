package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;

import java.io.IOException;
import java.util.Map;

/**
 * Deserializer used for deserializing {@link TokenSettings} from JSON.
 *
 * @author Junlin Zhou
 */
public class TokenSettingsDeserializer extends JsonDeserializer<TokenSettings> {

    /**
     * {@inheritDoc}
     */
    @Override
    public TokenSettings deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        ObjectMapper mapper = (ObjectMapper) p.getCodec();
        JsonNode root = mapper.readTree(p);
        Map<String, Object> settings = JsonNodeUtils
                .findValue(root, "settings", JsonNodeUtils.STRING_OBJECT_MAP, mapper);
        return TokenSettings.withSettings(settings).build();
    }

}
