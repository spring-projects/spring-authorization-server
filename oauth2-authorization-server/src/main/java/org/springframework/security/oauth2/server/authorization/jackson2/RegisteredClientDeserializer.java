package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;

import java.io.IOException;
import java.time.Instant;
import java.util.Set;

/**
 * Deserializer used for deserializing {@link RegisteredClient} from JSON.
 *
 * @author Junlin Zhou
 */
public class RegisteredClientDeserializer extends JsonDeserializer<RegisteredClient> {

    private static final TypeReference<Set<AuthorizationGrantType>> AUTHORIZATION_GRANT_TYPE_SET =
            new TypeReference<Set<AuthorizationGrantType>>() {
            };

    private static final TypeReference<Set<ClientAuthenticationMethod>> CLIENT_AUTHENTICATION_METHOD_SET =
            new TypeReference<Set<ClientAuthenticationMethod>>() {
            };

    private static final TypeReference<ClientSettings> CLIENT_SETTINGS_TYPE_REFERENCE =
            new TypeReference<ClientSettings>() {
            };

    private static final TypeReference<TokenSettings> TOKEN_SETTINGS_TYPE_REFERENCE =
            new TypeReference<TokenSettings>() {
            };

    private static final TypeReference<Instant> INSTANT_TYPE_REFERENCE = new TypeReference<Instant>() {
    };

    /**
     * {@inheritDoc}
     */
    @Override
    public RegisteredClient deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        ObjectMapper mapper = (ObjectMapper) p.getCodec();
        JsonNode root = mapper.readTree(p);
        return deserialize(root, mapper);
    }

    private RegisteredClient deserialize(JsonNode root, ObjectMapper mapper) {
        String id = JsonNodeUtils.findStringValue(root, "id");
        String clientId = JsonNodeUtils.findStringValue(root, "clientId");
        String clientSecret = JsonNodeUtils.findStringValue(root, "clientSecret");
        String clientName = JsonNodeUtils.findStringValue(root, "clientName");

        Instant clientIdIssuedAt = JsonNodeUtils
                .findValue(root, "clientIdIssuedAt", INSTANT_TYPE_REFERENCE, mapper);

        Instant clientSecretExpiresAt = JsonNodeUtils
                .findValue(root, "clientSecretExpiresAtNode", INSTANT_TYPE_REFERENCE, mapper);

        Set<AuthorizationGrantType> grantTypes = JsonNodeUtils
                .findValue(root, "authorizationGrantTypes", AUTHORIZATION_GRANT_TYPE_SET, mapper);
        Set<ClientAuthenticationMethod> clientAuthenticationMethods = JsonNodeUtils
                .findValue(root, "clientAuthenticationMethods", CLIENT_AUTHENTICATION_METHOD_SET, mapper);
        Set<String> redirectUris = JsonNodeUtils
                .findValue(root, "redirectUris", JsonNodeUtils.STRING_SET, mapper);
        Set<String> scopes = JsonNodeUtils.findValue(root, "scopes", JsonNodeUtils.STRING_SET, mapper);

        ClientSettings clientSettings = JsonNodeUtils
                .findValue(root, "clientSettings", CLIENT_SETTINGS_TYPE_REFERENCE, mapper);
        TokenSettings tokenSettings = JsonNodeUtils
                .findValue(root, "tokenSettings", TOKEN_SETTINGS_TYPE_REFERENCE, mapper);

        return RegisteredClient
                .withId(id)
                .clientId(clientId)
                .clientIdIssuedAt(clientIdIssuedAt)
                .clientSecret(clientSecret)
                .clientSecretExpiresAt(clientSecretExpiresAt)
                .clientName(clientName)
                .clientAuthenticationMethods(consumer -> consumer.addAll(clientAuthenticationMethods))
                .authorizationGrantTypes(consumer -> consumer.addAll(grantTypes))
                .redirectUris(consumer -> consumer.addAll(redirectUris))
                .scopes(consumer -> consumer.addAll(scopes))
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();
    }

}
