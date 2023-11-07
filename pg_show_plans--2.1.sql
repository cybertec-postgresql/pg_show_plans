/* pg_show_plans/pg_show_plans--2.1.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_show_plans" to load this file. \quit

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

-- Register a view to see query plans along with the corresponding queries.
CREATE VIEW pg_show_plans_q AS
	SELECT p.pid, p.level, p.plan, a.query
	FROM pg_show_plans p
	LEFT JOIN pg_stat_activity a
	ON p.pid = a.pid AND p.level = 0 ORDER BY p.pid, p.level;

GRANT SELECT ON pg_show_plans TO PUBLIC;
GRANT SELECT ON pg_show_plans_q TO PUBLIC;
