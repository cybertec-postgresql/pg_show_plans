# pg_show_plans

`pg_show_plans` is a module which shows the query plans of all currently running SQL statements.
This is implemented based on [pg_stat_statements](https://www.postgresql.org/docs/current/pgstatstatements.html).

You can select the output format of plans: JSON or TEXT.

This module supports PostgreSQL 12 beta 2 or earlier.

## Version

*Version 0.3.*

This module is a developing version yet.
After implementing all features described in the TODO section, where is at the end of this document, version 1.0 will be released.

## Installation

Assume that the package of this module is `pg_show_plans-0.3.tar.gz`,
you can install it to do the usual way shown below.

```
$ cd contrib
$ tar xvfz pg_show_plans-0.3.tar.gz
$ cd pg_show_plans
$ make && make install
```

You must add the line shown below in your postgresql.conf.

```
shared_preload_libraries = 'pg_show_plans'
```

After starting your server, you must issue `CREATE EXTENSION` statement shown below.

```
testdb=# CREATE EXTENSION pg_show_plans;
```

## How to use

By issuing the following query, it shows the query plan and related information of the currently running SQL statements.

```
testdb=# SELECT * FROM pg_show_plans;
  pid  | level | userid | dbid  |                                 plan                                  
-------+-------+--------+-------+-----------------------------------------------------------------------
 31600 |     0 |     10 | 16384 | Function Scan on pg_show_plans  (cost=0.00..10.00 rows=1000 width=56)
 31602 |     0 |     10 | 16384 | Result  (cost=0.00..0.01 rows=1 width=4)
(2 rows)
```

If you need the query plans of running SQL statements and also the corresponding query string, you issue the following query which is combined with pg_show_plans and pg_stat_activity.

```
testdb=# \x
Expanded display is on.

testdb=# SELECT p.pid, p.plan, a.query FROM pg_show_plans p, pg_stat_activity a WHERE p.pid = a.pid;
-[ RECORD 1 ]--------------------------------------------------------------------------------------
pid   | 31600
plan  | Hash Join  (cost=2.25..21.00 rows=500 width=72)                                            +
      |   Hash Cond: (pg_show_plans.pid = s.pid)                                                   +
      |   ->  Function Scan on pg_show_plans  (cost=0.00..10.00 rows=1000 width=40)                +
      |   ->  Hash  (cost=1.00..1.00 rows=100 width=44)                                            +
      |         ->  Function Scan on pg_stat_get_activity s  (cost=0.00..1.00 rows=100 width=44)
query | SELECT p.pid, p.plan, a.query FROM pg_show_plans p, pg_stat_activity a WHERE p.pid = a.pid;
-[ RECORD 2 ]--------------------------------------------------------------------------------------
pid   | 31605
plan  | Result  (cost=0.00..0.01 rows=1 width=4)
query | SELECT pg_sleep(10);
```

## pg_show_plans View
 - *pid*: the pid of the process which the query is running.    
 - *level*: the level of the query which runs the query. Top level is `0`.
 - *userid*: the userid of the user which runs the query.
 - *dbid*: the database id of the database which the query is running.
 - *plan*: the query plan of the running query.

## Functions
 - *pg_show_plans_delete_all()* : Delete all stored plans in the hashtable.
 - *pg_show_plans_delete(pid)* : Delete the stored plan related to the specified pid.

## Configuration Parameters

 - *pg_show_plans.show_level* : pg_show_plans.show_level controls the level of query plans. You can select one of `all`,`top` and `none`. "all" shows all level of the query plan. For example, when you execute a function defined by PL/pgSQL, the caller SQL statement (level 0) and the internal SQL statements in the function (level 1) are shown. "top" shows the top level of the query plan. "none" does not store the query plans, so the pg_show_plans view does not show anything. Default is `top`.

 - *pg_show_plans.format* : pg_show_plans.format controls the output format of query plans. It can be selected either `json` or `text`. Default is`json`.


## TODO

### 1. Support long query plan string.
The current version can only store the query plan string whose length is less than 3kb and this maximum length is embedded.

### 2. Support parallel query.

## Change Log

 - 12 Aug, 2019: Version 0.3 Released. Supported garbage collection.

 - 9 Aug, 2019: Version 0.2 Released. Supported nested queries.

 - 8 Aug, 2019: Version 0.1 Released.


