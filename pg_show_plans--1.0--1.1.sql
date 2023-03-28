-- pid/level changed from int8 to int
DROP VIEW pg_show_plans;
DROP FUNCTION pg_show_plans;

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

-- Some 1.0 versions already contained yaml/xml, use "or replace" here
CREATE OR REPLACE FUNCTION pgsp_format_yaml()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE OR REPLACE FUNCTION pgsp_format_xml()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

REVOKE ALL ON FUNCTION pgsp_format_yaml() FROM PUBLIC;
REVOKE ALL ON FUNCTION pgsp_format_xml() FROM PUBLIC;
