CREATE TABLE oauth2RegisteredClient (
    id varchar(100) NOT NULL,
    clientId varchar(100) NOT NULL,
    clientIdIssuedAt timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    clientSecret varchar(200) DEFAULT NULL,
    clientSecretExpiresAt timestamp DEFAULT NULL,
    clientName varchar(200),
    clientAuthenticationMethods varchar(1000) NOT NULL,
    authorizationGrantTypes varchar(1000) NOT NULL,
    redirectUris varchar(1000) NOT NULL,
    scopes varchar(1000) NOT NULL,
    clientSettings varchar(1000) DEFAULT NULL,
    tokenSettings varchar(1000) DEFAULT NULL,
    PRIMARY KEY (id)
);
