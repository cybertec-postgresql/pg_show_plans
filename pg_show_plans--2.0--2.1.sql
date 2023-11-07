-- Register a view to see query plans along with the corresponding queries.
CREATE VIEW pg_show_plans_q AS
	SELECT p.pid, p.level, p.plan, a.query
	FROM pg_show_plans p
	LEFT JOIN pg_stat_activity a
	ON p.pid = a.pid AND p.level = 0 ORDER BY p.pid, p.level;

GRANT SELECT ON pg_show_plans_q TO PUBLIC;
