
CREATE TABLE IF NOT EXISTS tb_users (
  id       UUID PRIMARY KEY,
  login    VARCHAR(255)  NOT NULL,
  password VARCHAR(255)  NOT NULL,
  role     VARCHAR(20)   NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tb_users_login ON tb_users(login);

INSERT INTO tb_users (id, login, password, role)
VALUES (RANDOM_UUID(), 'felipe','$2a$10$rotrJk9GdcgAoqGFpCI9C.8V.BBLs/XEFSlwhISirk/yGBAHqb0DK', 'ADMIN');