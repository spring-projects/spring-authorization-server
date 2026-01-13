-- ユーザー情報を格納するテーブル
CREATE TABLE users (
                       username VARCHAR(50) NOT NULL PRIMARY KEY,
                       password VARCHAR(500) NOT NULL,
                       enabled BOOLEAN NOT NULL
);

-- ユーザーに紐づく権限（ROLE_USER, ROLE_ADMINなど）を格納するテーブル
CREATE TABLE authorities (
                             username VARCHAR(50) NOT NULL,
                             authority VARCHAR(50) NOT NULL,
                             CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users(username)
);

-- 同じユーザーに同じ権限を重複して持たせないためのユニークインデックス
CREATE UNIQUE INDEX ix_auth_username ON authorities (username, authority);

