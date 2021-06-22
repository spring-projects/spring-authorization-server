CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret blob NOT NULL,
    client_secret_expires_at timestamp DEFAULT NULL,
    client_name varchar(200),
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) NOT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(1000) DEFAULT NULL,
    token_settings varchar(1000) DEFAULT NULL,
    PRIMARY KEY (id));
