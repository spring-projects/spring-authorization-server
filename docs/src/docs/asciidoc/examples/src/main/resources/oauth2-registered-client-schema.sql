CREATE TABLE client (
    id varchar(255) NOT NULL,
    clientId varchar(255) NOT NULL,
    clientIdIssuedAt timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    clientSecret varchar(255) DEFAULT NULL,
    clientSecretExpiresAt timestamp DEFAULT NULL,
    clientName varchar(255) NOT NULL,
    clientAuthenticationMethods varchar(1000) NOT NULL,
    authorizationGrantTypes varchar(1000) NOT NULL,
    redirectUris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    clientSettings varchar(2000) NOT NULL,
    tokenSettings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);
