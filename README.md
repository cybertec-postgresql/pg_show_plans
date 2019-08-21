# pg_show_plans

`pg_show_plans` is a module which shows the query plans of all currently running SQL statements.
This is implemented based on [pg_stat_statements](https://www.postgresql.org/docs/current/pgstatstatements.html).

You can select the output format of plans: JSON or TEXT.

This module supports PostgreSQL 12 beta 2 or earlier.

### Note
When the server starts, pg_show_plans makes a hashtable  on the shared-memory in order to temporarily store query plans.
The hashtable size cannot be changed, so the plans are not stored if the hashtable is full.

## Version

*Version 0.8 = Alpha version*

This module is still a developing version, so the features have not fixed yet.

After implementing all features described in the TODO section, where is at the end of this document, version 1.0 will be released.

## Installation

You can install it to do the usual way shown below.

```
$ tar xvfj postgresql-11.4.tar.bz2
$ cd postgresql-11.4/contrib
$ git clone https://github.com/cybertec-postgresql/pg_show_plans.git
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
 11473 |     0 |     10 | 16384 | Function Scan on pg_show_plans  (cost=0.00..10.00 rows=1000 width=56)
 11504 |     0 |     10 | 16384 | Function Scan on print_item  (cost=0.25..10.25 rows=1000 width=524)
 11504 |     1 |     10 | 16384 | Result  (cost=0.00..0.01 rows=1 width=4)
(3 rows)
```

If you need the query plans of running SQL statements and also the corresponding query string, you issue the following query which is combined with pg_show_plans and pg_stat_activity.

```
testdb=# \x
Expanded display is on.
testdb=# SELECT p.pid, p.level, p.plan, a.query FROM pg_show_plans p 
   LEFT JOIN pg_stat_activity a
   ON p.pid = a.pid AND p.level = 0 ORDER BY p.pid, p.level;
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


## pg_show_plans View
 - *pid*: the pid of the process which the query is running.    
 - *level*: the level of the query which runs the query. Top level is `0`.
 - *userid*: the userid of the user which runs the query.
 - *dbid*: the database id of the database which the query is running.
 - *plan*: the query plan of the running query.

## Configuration Parameters
 - *pg_show_plans.show_level* : It controls the level of query plans. You can select one of `all`,`top` and `none`. "all" shows all level of the query plan. For example, when you execute a function defined by PL/pgSQL, the caller SQL statement (level 0) and the internal SQL statements in the function (level 1) are shown. "top" shows the top level of the query plan. "none" does not store the query plans, so the pg_show_plans view does not show anything. Default is `top`.

 - *pg_show_plans.format* : It controls the output format of query plans. It can be selected either `json` or `text`. Default is`json`.

 - *pg_show_plans.max_plan_length* : It sets the maximum length of query plans. Default is `3kb`.

## Functions
 - *pg_show_plans_disable()* disables the feature. Only superuser can execute it.
 - *pg_show_plans_enable()* enables the feature. Only superuser can execute it.

## TODO

1. Improve nested_level display style.
2. Alpha testing.

## Change Log

 - 16 Aug, 2019: Version 0.8 Released. Supported the parameter:max_plan_length.

 - 12 Aug, 2019: Version 0.3 Released. Supported garbage collection.

 - 9 Aug, 2019: Version 0.2 Released. Supported nested queries.

 - 8 Aug, 2019: Version 0.1 Released.
