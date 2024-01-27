# pg_show_plans

PostgreSQL extension that shows query plans of all the currently running SQL
statements. Query plans can be shown in several formats, like `JSON` or `YAML`.

*This extension creates a hash table within shared memory. The hash table is
not resizable, thus, no new plans can be added once it has been filled up.*

# INSTALL

Either use PGXS infrastructure (recommended), or compile within the source
tree. PostgreSQL versions 12 and newer are supported.

## PGXS

Install PostgreSQL before proceeding. Make sure to have `pg_config` binary,
these are typically included in `-dev` and `-devel` packages.

```bash
git clone https://github.com/cybertec-postgresql/pg_show_plans.git
cd pg_show_plans
make
make install
```

## Within Source Tree

```bash
PG_VER='15.3' # Set the required PostgreSQL version.
curl -O "https://download.postgresql.org/pub/source/v${PG_VER}/postgresql-${PG_VER}.tar.bz2"
tar xvfj "postgresql-${PG_VER}.tar.bz2"
cd postgresql-${PG_VER}
./configure

cd contrib
git clone https://github.com/cybertec-postgresql/pg_show_plans.git
cd pg_show_plans
make USE_PGXS=
make USE_PGXS= install
```

## Configure

Add `pg_show_plans` to `shared_preload_libraries` within `postgresql.conf`:

```
shared_preload_libraries = 'pg_show_plans'
```

Restart the server, and invoke `CREATE EXTENSION pg_show_plans;`:

```
postgresql=# CREATE EXTENSION pg_show_plans;
CREATE EXTENSION
postgresql=#
```

# USAGE

To see the query plans:

```
testdb=# SELECT * FROM pg_show_plans;
  pid  | level | userid | dbid  |                                 plan
-------+-------+--------+-------+-----------------------------------------------------------------------
 11473 |     0 |     10 | 16384 | Function Scan on pg_show_plans  (cost=0.00..10.00 rows=1000 width=56)
 11504 |     0 |     10 | 16384 | Function Scan on print_item  (cost=0.25..10.25 rows=1000 width=524)
 11504 |     1 |     10 | 16384 | Result  (cost=0.00..0.01 rows=1 width=4)
(3 rows)
```

To get query plans and see the corresponding query expression:

```
testdb=# \x
Expanded display is on.
testdb=# SELECT * FROM pg_show_plans_q;
-[ RECORD 1 ]-----------------------------------------------------------------------------------------
pid   | 11473
level | 0
plan  | Sort  (cost=72.08..74.58 rows=1000 width=80)                                                  +
      |   Sort Key: pg_show_plans.pid, pg_show_plans.level                                            +
      |   ->  Hash Left Join  (cost=2.25..22.25 rows=1000 width=80)                                   +
      |         Hash Cond: (pg_show_plans.pid = s.pid)                                                +
      |         Join Filter: (pg_show_plans.level = 0)                                                +
      |         ->  Function Scan on pg_show_plans  (cost=0.00..10.00 rows=1000 width=48)             +
      |         ->  Hash  (cost=1.00..1.00 rows=100 width=44)                                         +
      |               ->  Function Scan on pg_stat_get_activity s  (cost=0.00..1.00 rows=100 width=44)
query | SELECT p.pid, p.level, p.plan, a.query FROM pg_show_plans p                                   +
      |    LEFT JOIN pg_stat_activity a                                                               +
      |    ON p.pid = a.pid AND p.level = 0 ORDER BY p.pid, p.level;
-[ RECORD 2 ]-----------------------------------------------------------------------------------------
pid   | 11517
level | 0
plan  | Function Scan on print_item  (cost=0.25..10.25 rows=1000 width=524)
query | SELECT * FROM print_item(1,20);
-[ RECORD 3 ]-----------------------------------------------------------------------------------------
pid   | 11517
level | 1
plan  | Result  (cost=0.00..0.01 rows=1 width=4)
query |

```

# BENCHMARKS

`pgbench -c 10 -j 3 -t 5000 -S` plain PostgreSQL `16.1`:

```
tps = 193655.084802 (without initial connection time)
tps = 200890.346014 (without initial connection time)
tps = 199931.223659 (without initial connection time)
```

`pgbench -c 10 -j 3 -t 5000 -S` PostgreSQL `16.1` with `pg_show_plans` version
`2.1.0`:

```
tps = 166564.507102 (without initial connection time)
tps = 172814.245424 (without initial connection time)
tps = 174658.455390 (without initial connection time)
```

In overall approximately 15% performance penalty.

# REFERENCE

## GUC Variables

* `pg_show_plans.plan_format = text`: query plans output format, either of
  `text`, `json`, `yaml`, and `xml`.
* `pg_show_plans.max_plan_length = 16384`: query plan maximal length in bytes.
  This value affects the amount of shared memory the extension asks for, the
  server may not start if the value is too high.
* `pg_show_plans.is_enabled = true`: enable or disable the extension by
  assigning to this variable.

*Default values are shown after '=' sign.*

## Views

* `pg_show_plans`: defined as `SELECT * FROM pg_show_plans();` for convenience.
* `pg_show_plans_q`: same as `pg_show_plans`, but it has one more column with
  the corresponding query strings.

## Functions

* `pg_show_plans()`: show query plans:
  - `pid`: server process ID that runs the query.
  - `level`: query nest level. Top level is 0. For example, if you execute a
    simple select query, the level of this query's plan is 0. If you execute a
    function that invokes a select query, level 0 is the plan of the function
    and level 1 is the plan of the select query invoked by the function.
  - `userid`: user ID who runs the query.
  - `dbid`: database ID the query runs in.
  - `plan`: query plan.
