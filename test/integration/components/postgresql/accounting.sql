--
-- PostgreSQL database dump
--

-- Dumped from database version 14.11 (Ubuntu 14.11-0ubuntu0.22.04.1)
-- Dumped by pg_dump version 14.11 (Ubuntu 14.11-0ubuntu0.22.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: accounting; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA accounting;


ALTER SCHEMA accounting OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: contacts; Type: TABLE; Schema: accounting; Owner: postgres
--

CREATE TABLE accounting.contacts (
    id integer NOT NULL,
    name text NOT NULL,
    last_names text NOT NULL,
    address text NOT NULL
);


ALTER TABLE accounting.contacts OWNER TO postgres;

--
-- Name: invoices; Type: TABLE; Schema: accounting; Owner: postgres
--

CREATE TABLE accounting.invoices (
    id integer,
    amount numeric,
    c_id integer,
    description text
);


ALTER TABLE accounting.invoices OWNER TO postgres;

--
-- Data for Name: contacts; Type: TABLE DATA; Schema: accounting; Owner: postgres
--

COPY accounting.contacts (id, name, last_names, address) FROM stdin;
1	Bob	Smith	1234 Some Street, Balmy Springs, Wonderland
\.


--
-- Data for Name: invoices; Type: TABLE DATA; Schema: accounting; Owner: postgres
--

COPY accounting.invoices (id, amount, c_id, description) FROM stdin;
1	123.45	1	Pineapples
2	345.67	1	Bananas
\.

--
-- Name: INDEX_0PJX; Type: INDEX; Schema: accounting; Owner: postgres
--

CREATE UNIQUE INDEX "INDEX_0PJX" ON accounting.contacts USING btree (id);


--
-- Name: INDEX_ELB5; Type: INDEX; Schema: accounting; Owner: postgres
--

CREATE UNIQUE INDEX "INDEX_ELB5" ON accounting.invoices USING btree (id);


--
-- PostgreSQL database dump complete
--

