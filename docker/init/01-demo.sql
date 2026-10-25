-- Demo data for the strict proxy (`proxy-strict` service).
--
-- The `app` role owns the database and therefore *could* read everything, but
-- the proxy only lets it run the statement configured on the command line.

CREATE ROLE app LOGIN PASSWORD 'hunter2';

CREATE DATABASE appdb OWNER app;

\connect appdb

CREATE TABLE items (
    id     integer PRIMARY KEY,
    name   text NOT NULL,
    secret text NOT NULL
);

INSERT INTO items (id, name, secret) VALUES
    (1, 'alpha', 'classified-alpha'),
    (2, 'beta',  'classified-beta');

GRANT ALL ON SCHEMA public TO app;
GRANT ALL ON items TO app;
