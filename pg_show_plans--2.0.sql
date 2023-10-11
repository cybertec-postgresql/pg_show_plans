/* pg_show_plans/pg_show_plans--2.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_show_plans" to load this file. \quit

-- Register functions.
CREATE FUNCTION pg_show_plans_enable()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION pg_show_plans_disable()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION pg_show_plans(
	OUT pid int,
	OUT level int,
	OUT userid oid,
	OUT dbid oid,
	OUT plan text
)
RETURNS SETOF record
AS 'MODULE_PATHNAME'
LANGUAGE C;

-- Register a view on the function for ease of use.
CREATE VIEW pg_show_plans AS
	SELECT * FROM pg_show_plans();

GRANT SELECT ON pg_show_plans TO PUBLIC;

-- Don't want this to be available to non-superusers.
REVOKE ALL ON FUNCTION pg_show_plans_enable() FROM PUBLIC;
REVOKE ALL ON FUNCTION pg_show_plans_disable() FROM PUBLIC;
