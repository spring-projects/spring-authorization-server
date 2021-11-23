package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.StdConverter;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.io.IOException;
import java.util.Map;

/**
 * Deserializer used for deserializing {@link OAuth2ClientAuthenticationToken} from JSON.
 *
 * @author Junlin Zhou
 */
public class OAuth2ClientAuthenticationTokenDeserializer extends JsonDeserializer<OAuth2ClientAuthenticationToken> {

    private static final StdConverter<JsonNode, ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHOD_CONVERTER =
            new StdConverters.ClientAuthenticationMethodConverter();

    private static final TypeReference<RegisteredClient> REGISTERED_CLIENT_TYPE_REFERENCE =
            new TypeReference<RegisteredClient>() {
            };

    /**
     * {@inheritDoc}
     */
    @Override
    public OAuth2ClientAuthenticationToken deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        ObjectMapper mapper = (ObjectMapper) p.getCodec();
        JsonNode root = mapper.readTree(p);

        Object credentials = JsonNodeUtils.findStringValue(root, "credentials");

        ClientAuthenticationMethod clientAuthenticationMethod = CLIENT_AUTHENTICATION_METHOD_CONVERTER
                .convert(JsonNodeUtils.findObjectNode(root, "clientAuthenticationMethod"));

        boolean authenticated = findBooleanValue(root, "authenticated");

        if (authenticated) {
            RegisteredClient registeredClient = JsonNodeUtils
                    .findValue(root, "registeredClient", REGISTERED_CLIENT_TYPE_REFERENCE, mapper);
            return new OAuth2ClientAuthenticationToken(registeredClient, clientAuthenticationMethod, credentials);
        } else {
            String clientId = JsonNodeUtils.findStringValue(root, "clientId");
            Map<String, Object> additionalParameters = JsonNodeUtils
                    .findValue(root, "additionalParameters", JsonNodeUtils.STRING_OBJECT_MAP, mapper);
            return new OAuth2ClientAuthenticationToken(clientId, clientAuthenticationMethod, credentials,
                    additionalParameters);
        }
    }

    private boolean findBooleanValue(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return false;
        }
        JsonNode value = jsonNode.findValue(fieldName);
        return (value != null && value.asBoolean());
    }

}
