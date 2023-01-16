/*-------------------------------------------------------------------------
 *
 * pg_show_plans.c
 *		Show query plans of all currently running SQL statements
 *
 * Copyright (c) 2008-2022, PostgreSQL Global Development Group
 * Copyright (c) 2019-2022, Cybertec Schönig & Schönig GmbH
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include <unistd.h>
#include <dlfcn.h>

#include "access/hash.h"
#include "access/transam.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "catalog/pg_authid.h"
#include "funcapi.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/spin.h"
#include "storage/shmem.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "commands/explain.h"
#include "pgstat.h"

PG_MODULE_MAGIC;

/*
 * Define constant
 */
#define MAX_NESTED_LEVEL         10 /* MAX_NESTED_LEVEL plan can be stored in
									 * hash entry */

/*
 * Define data types
 */
typedef struct pgspHashKey
{
	pid_t		pid;
}			pgspHashKey;

typedef struct pgspEntry
{
	pgspHashKey key;			/* hash key of entry - MUST BE FIRST */
	Oid			userid;			/* user OID */
	Oid			dbid;			/* database OID */
	int			encoding;		/* query encoding */
	int			plan_len;		/* # of valid bytes in query string */
	slock_t		mutex;			/* protects the entry */
	pid_t		pid;			/* it is used for the hash key */
	int			terminalByte[MAX_NESTED_LEVEL]; /* Refer to the comment of
												 * entry_store() */
	bool		isSnipped[MAX_NESTED_LEVEL];	/* whether plan in each
												 * nested_level is snipped */
	int			nestedLevel;	/* max nested_level of this query */
	char		plan[0];		/* query plan string */
}			pgspEntry;

/* Global shared state */
typedef struct pgspSharedState
{
	LWLock	   *lock;			/* protects hashtable search/modification */
	bool		is_enable;		/* Whether to enable the feature or not */
	int			plan_format;	/* plan format */
	slock_t		elock;			/* protects the variable `is_enable` and
								 * `plan_format` */
}			pgspSharedState;

/* Static variables */
static int	nested_level = 0;	/* Current nesting depth of
								 * ExecutorRun+ProcessUtility calls */
static int	pgsp_max;			/* max plans to show */
static int	plan_format;		/* output format */
static int	max_plan_length;	/* max length of query plan */
static bool pgsp_enable;		/* Whether the plan can be shown */
static bool pgsp_enable_txid;	/* For backward compatibility. */

/* Saved hook values in case of unload */
#if PG_VERSION_NUM >= 150000
static shmem_request_hook_type prev_shmem_request_hook = NULL;
#endif
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;
static ExecutorFinish_hook_type prev_ExecutorFinish = NULL;
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;

/* Links to shared memory state */
static pgspSharedState * pgsp = NULL;
static HTAB *pgsp_hash = NULL;

/*
 * GUC variables
 */
typedef enum
{
	PLAN_FORMAT_TEXT,
	PLAN_FORMAT_JSON
}			PGSPPlanFormats;

static const struct config_enum_entry plan_formats[] =
{
	{"text", PLAN_FORMAT_TEXT, false},
	{"json", PLAN_FORMAT_JSON, false},
	{NULL, 0, false}
};

/*
 * Function declarations
 */
void		_PG_init(void);

Datum		pg_show_plans(PG_FUNCTION_ARGS);
Datum		pg_show_plans_enable(PG_FUNCTION_ARGS);
Datum		pg_show_plans_disable(PG_FUNCTION_ARGS);
Datum		pgsp_format_json(PG_FUNCTION_ARGS);
Datum		pgsp_format_text(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pg_show_plans);
PG_FUNCTION_INFO_V1(pg_show_plans_enable);
PG_FUNCTION_INFO_V1(pg_show_plans_disable);
PG_FUNCTION_INFO_V1(pgsp_format_json);
PG_FUNCTION_INFO_V1(pgsp_format_text);

#if PG_VERSION_NUM >= 150000
static void pgsp_shmem_request(void);
#endif
static Size pgsp_memsize(void);
static void pgsp_shmem_startup(void);
static void pgsp_shmem_shutdown(int code, Datum arg);
static void pgsp_ExecutorStart(QueryDesc *queryDesc, int eflags);
static void pgsp_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once);
static void pgsp_ExecutorFinish(QueryDesc *queryDesc);
static void pgsp_ExecutorEnd(QueryDesc *queryDesc);

static pgspEntry * alloc_entry(const pgspHashKey * key);
static void store_entry(const char *plan, const int plan_len, const int nested_level);
static void store_plan_into_entry(pgspEntry * entry, const int nested_level,
								  const char *plan, const int len, const pgspHashKey key);
static void delete_entry(const pid_t pid);
static uint32 gen_hashkey(const void *key, Size keysize);
static int	compare_hashkey(const void *key1, const void *key2, Size keysize);
static void set_state(const bool state);

/*
 * Module callback
 */
void
_PG_init(void)
{
	if (!process_shared_preload_libraries_in_progress)
		return;

	DefineCustomBoolVariable("pg_show_plans.enable",
							 "Whether the plan can be shown.",
							 NULL,
							 &pgsp_enable,
							 true,
							 PGC_USERSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomIntVariable("pg_show_plans.max_plan_length",
							gettext_noop("Set the maximum plan length. "
										 "Note that this module allocates (max_plan_length*max_connections) "
										 "bytes on the shared memory."),
							gettext_noop("A hash entry whose length is max_plan_length stores the plans of "
										 "all nested levels, so this value should be set enough size. "
										 "However, if it is too large, the server may not be able to start "
										 "because of the shortage of memory due to the huge shared memory size."),
							&max_plan_length,
							16 * 1024,
							1024,
							100 * 1024,
							PGC_POSTMASTER,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomEnumVariable("pg_show_plans.plan_format",
							 "Set the output format of query plans.",
							 NULL,
							 &plan_format,
							 PLAN_FORMAT_TEXT,
							 plan_formats,
							 PGC_POSTMASTER,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomBoolVariable("pg_show_plans.enable_txid",
							 "(Obsoleted) Whether txid is used as a hash key.",
							 "This has been obsoleted and remains for backward compatibility.",
							 &pgsp_enable_txid,
							 false,
							 PGC_USERSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	EmitWarningsOnPlaceholders("pg_show_plans");

#if PG_VERSION_NUM >= 150000
	prev_shmem_request_hook = shmem_request_hook;
	shmem_request_hook = pgsp_shmem_request;
#else
	RequestAddinShmemSpace(pgsp_memsize());
	RequestNamedLWLockTranche("pg_show_plans", 1);
#endif

	/* Install hooks. */
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pgsp_shmem_startup;

	prev_ExecutorStart = ExecutorStart_hook;
	ExecutorStart_hook = pgsp_ExecutorStart;

	prev_ExecutorRun = ExecutorRun_hook;
	ExecutorRun_hook = pgsp_ExecutorRun;

	prev_ExecutorFinish = ExecutorFinish_hook;
	ExecutorFinish_hook = pgsp_ExecutorFinish;

	prev_ExecutorEnd = ExecutorEnd_hook;
	ExecutorEnd_hook = pgsp_ExecutorEnd;
}

/*
 * shmem_startup hook: allocate or attach to shared memory.
 */
static void
pgsp_shmem_startup(void)
{
	bool		found;
	HASHCTL		info;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	pgsp_max = MaxConnections;
	pgsp = NULL;
	pgsp_hash = NULL;

	/* Create or attach to the shared memory state, including hash table */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	pgsp = ShmemInitStruct("pg_show_plans", sizeof(pgspSharedState), &found);

	if (!found)
	{
		/* First time through ... */
		pgsp->lock = &(GetNamedLWLockTranche("pg_show_plans"))->lock;
		SpinLockInit(&pgsp->elock);
	}

	/* Set the initial value to is_enable */
	pgsp->is_enable = true;
	pgsp->plan_format = plan_format;

	/* Be sure everyone agrees on the hash table entry size */
	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(pgspHashKey);
	info.entrysize = offsetof(pgspEntry, plan) + max_plan_length;

	info.hash = gen_hashkey;
	info.match = compare_hashkey;

	pgsp_hash = ShmemInitHash("pg_show_plans hash",
							  pgsp_max, pgsp_max,
							  &info,
							  HASH_ELEM | HASH_FUNCTION | HASH_COMPARE);

	LWLockRelease(AddinShmemInitLock);

	if (!IsUnderPostmaster)
		on_shmem_exit(pgsp_shmem_shutdown, (Datum) 0);
}

static void
pgsp_shmem_shutdown(int code, Datum arg)
{
	/* Do nothing */
	return;
}

/*
 * ExecutorStart hook: start up tracking if needed
 */
static void
pgsp_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	ExplainState *es = NewExplainState();

	if (prev_ExecutorStart)
		prev_ExecutorStart(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);

	/* Bypass the following steps if this pgsp_enable is set to false  */
	if (!pgsp_enable)
		return;

	/*
	 * Execute EXPLAIN and Store the query plan into the hashtable
	 */

	/* Skip subsequent processing if is_enable is false */
	SpinLockAcquire(&pgsp->elock);
	if (!pgsp->is_enable)
	{
		SpinLockRelease(&pgsp->elock);
		return;
	}

	switch (pgsp->plan_format)
	{
		case PLAN_FORMAT_TEXT:
			es->format = EXPLAIN_FORMAT_TEXT;
			break;
		case PLAN_FORMAT_JSON:
		default:
			es->format = EXPLAIN_FORMAT_JSON;
			break;
	};
	SpinLockRelease(&pgsp->elock);

	ExplainBeginOutput(es);
	ExplainPrintPlan(es, queryDesc);
	ExplainEndOutput(es);

	SpinLockAcquire(&pgsp->elock);
	if (es->str->len >= max_plan_length)
	{
		/*
		 * Note: If the length of the query plan is longer than
		 * max_plan_length, the message below is shown instead of the plan
		 * string.
		 */
		char	   *msg = "<too long query plan string>";

		memcpy(es->str->data, msg, strlen(msg));
		es->str->len = strlen(msg);
		es->str->data[es->str->len] = '\0';
	}
	else
	{
		if (pgsp->plan_format == PLAN_FORMAT_JSON)
		{
			es->str->data[0] = '{';
			es->str->data[es->str->len - 1] = '}';
			es->str->data[es->str->len] = '\0';
		}
		else if (pgsp->plan_format == PLAN_FORMAT_TEXT)
		{
			es->str->len--;
			es->str->data[es->str->len] = '\0';
		}
	}
	SpinLockRelease(&pgsp->elock);

	store_entry(es->str->data, es->str->len, nested_level);
	pfree(es->str->data);
}

/*
 * ExecutorRun hook: all we need do is show nesting depth
 */
static void pgsp_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once)
{
	nested_level++;
	PG_TRY();
	{
		if (prev_ExecutorRun)
			prev_ExecutorRun(queryDesc, direction, count, execute_once);
		else
			standard_ExecutorRun(queryDesc, direction, count, execute_once);
		nested_level--;
	}
	PG_CATCH();
	{
		nested_level--;
		PG_RE_THROW();
	}
	PG_END_TRY();
}

/*
 * ExecutorFinish hook: all we need do is show nesting depth
 */
static void
pgsp_ExecutorFinish(QueryDesc *queryDesc)
{
	nested_level++;
	PG_TRY();
	{
		if (prev_ExecutorFinish)
			prev_ExecutorFinish(queryDesc);
		else
			standard_ExecutorFinish(queryDesc);
		nested_level--;
	}
	PG_CATCH();
	{
		nested_level--;
		PG_RE_THROW();
	}
	PG_END_TRY();
}

/*
 * ExecutorEnd hook:
 */
static void
pgsp_ExecutorEnd(QueryDesc *queryDesc)
{
	/* Bypass the following steps if this pgsp_enable is set to false  */
	if (pgsp_enable)
	{
		/* Delete entry */
		SpinLockAcquire(&pgsp->elock);
		if (pgsp->is_enable)
		{
			SpinLockRelease(&pgsp->elock);
			delete_entry(MyProcPid);
		}
		else
			SpinLockRelease(&pgsp->elock);
	}

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}

/*---
 * Store a plan to the hashtable.
 *
 * Internal format:
 * Plans are packed in the entry->plan[]. Each plan is terminated by '\0'.
 * The positions of the terminators are recorded in the entry->terminalByte[]
 * array; the total plan length is stored in the entry->plan_len.
 *
 * Example:
 * Three massages are packed in the entry->data:
 *   msg1 = 'abc', msg2 = 'ABCD', msg3 = 'xyz'
 *
 *         byte   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  ...
 * entry->plan  | a | b | c |\0 | A | B | C | D |\0 | x | y | z |\0 |   |   |   |
 *
 * In this case,
 * entry->plan_len = 13, entry->terminalByte[0] = 3, entry->terminalByte[1] = 8,
 * entry->terminalByte[2] = 12.
 */
static void
store_entry(const char *plan, const int plan_len, const int nested_level)
{
	pgspHashKey key;
	pgspEntry  *entry;

	pgspEntry  *e;

	Assert(plan != NULL);

	/* Safety check... */
	if (!pgsp || !pgsp_hash)
		return;

	key.pid = MyProcPid;

	Assert(0 <= plan_len && plan_len < max_plan_length);

	/* Look up the hash table entry with shared lock. */
	LWLockAcquire(pgsp->lock, LW_SHARED);
	entry = (pgspEntry *) hash_search(pgsp_hash, &key, HASH_FIND, NULL);
	LWLockRelease(pgsp->lock);

	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);

	if (nested_level == 0)
	{
		/*
		 * Create a new entry
		 */

		/* Delete old entry if exist. */
		if (entry != NULL)
		{
			pgspHashKey tmp_key;

			tmp_key.pid = key.pid;
			hash_search(pgsp_hash, &tmp_key, HASH_REMOVE, NULL);
		}

		/* Create a new entry */
		if ((entry = alloc_entry(&key)) == NULL)
		{
			/* New entry was not created since hashtable is full. */
			LWLockRelease(pgsp->lock);
			return;
		}

		/*
		 * Store data into the entry.
		 */
		e = (pgspEntry *) entry;
		SpinLockAcquire(&e->mutex);
		store_plan_into_entry(entry, nested_level, plan, plan_len, key);
		SpinLockRelease(&e->mutex);
	}
	else if (0 < nested_level && nested_level < MAX_NESTED_LEVEL)
	{
		/*
		 * Append plan to the entry whose key is MyProcPid
		 */
		if (entry == NULL)
		{
			LWLockRelease(pgsp->lock);
			elog(WARNING,
				 gettext_noop("The %dth level plan could not be stored "
							  "in the entry whose pid is %d because the entry could not find."),
				 nested_level, MyProcPid);
			return;
		}

		/*
		 * Store data into the entry.
		 */
		e = (pgspEntry *) entry;
		SpinLockAcquire(&e->mutex);
		store_plan_into_entry(entry, nested_level, plan, plan_len, key);
		SpinLockRelease(&e->mutex);
	}
	else
	{
		LWLockRelease(pgsp->lock);
		elog(WARNING,
			 gettext_noop("The %dth level plan could not be stored in the entry whose pid is %d "
						  "because MAX_NESTED_LEVEL is %d."),
			 nested_level, MyProcPid, MAX_NESTED_LEVEL);
		return;
	}

	LWLockRelease(pgsp->lock);
}

static void
store_plan_into_entry(pgspEntry * entry, const int nested_level,
					  const char *plan, const int len, const pgspHashKey key)
{
	int			plan_len = len;

	/* Initialize the entry data except the plan. */
	if (nested_level == 0)
	{
		entry->userid = GetUserId();
		entry->dbid = MyDatabaseId;
		entry->encoding = GetDatabaseEncoding();
		entry->pid = key.pid;
	}

	/*
	 * Check the plan_len and recalculate it if it is long to store into the
	 * entry.
	 */
	if (plan_len + entry->plan_len >= max_plan_length)
	{
		plan_len = max_plan_length - entry->plan_len;
		entry->isSnipped[nested_level] = true;
		if (plan_len <= 0)
			plan_len = 0;
	}

	/* Store the plan into the entry. */
	memcpy((void *) (entry->plan + entry->plan_len), plan, plan_len);
	entry->plan_len += plan_len;
	entry->plan[entry->plan_len] = '\0';
	entry->plan_len++;			/* add 1 byte:'\0' */
	entry->terminalByte[nested_level] = entry->plan_len;
	entry->nestedLevel = nested_level;
}

#if (PG_VERSION_NUM >= 150000)
/*
 * Requests any additional shared memory required for our extension
 */
static void
pgsp_shmem_request(void)
{
	if (prev_shmem_request_hook)
		prev_shmem_request_hook();

	RequestAddinShmemSpace(pgsp_memsize());
	RequestNamedLWLockTranche("pg_show_plans", 1);
}
#endif

/*
 * Estimate shared memory space needed.
 */
static Size
pgsp_memsize(void)
{
	Size		size;

	size = MAXALIGN(sizeof(pgspSharedState));
	size = add_size(size, hash_estimate_size(pgsp_max, sizeof(pgspEntry)));
	return size;
}

/*
 * Generate a unique value from hashkey for the hashtable.
 */
static uint32
gen_hashkey(const void *key, Size keysize)
{
	const		pgspHashKey *k = (const pgspHashKey *) key;

	return (uint32) k->pid;
}

/*
 * Compare hashkeys
 */
static int
compare_hashkey(const void *key1, const void *key2, Size keysize)
{
	const		pgspHashKey *k1 = (const pgspHashKey *) key1;
	const		pgspHashKey *k2 = (const pgspHashKey *) key2;

	return (k1->pid == k2->pid) ? 0 : 1;
}

/*
 * Allocate a new hashtable entry.
 * caller must hold an exclusive lock on pgsp->lock
 *
 */
static pgspEntry *
alloc_entry(const pgspHashKey * key)
{
	pgspEntry  *entry;
	bool		found;
	int			i;

	/*
	 * Find or create an entry with desired hash code. If hashtable is full,
	 * return NULL.
	 */
	if ((entry = (pgspEntry *) hash_search(pgsp_hash, key, HASH_ENTER_NULL, &found)) == NULL)
		return entry;

	if (!found)
	{
		/* New entry, initialize it */
		SpinLockInit(&entry->mutex);
		entry->plan_len = 0;
		for (i = 0; i < MAX_NESTED_LEVEL; i++)
		{
			entry->terminalByte[i] = 0;
			entry->isSnipped[nested_level] = false;
		}
		entry->nestedLevel = 0;
		entry->plan[0] = '\0';
	}

	return entry;
}

/*
 * Delete all stored plans related to pid.
 */
static void
delete_entry(const pid_t pid)
{
	pgspHashKey key;

	/* Safety check... */
	if (!pgsp || !pgsp_hash)
		return;

	key.pid = pid;

	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
	hash_search(pgsp_hash, &key, HASH_REMOVE, NULL);
	LWLockRelease(pgsp->lock);
}

/*
 * Set state to is_enable
 */
static void
set_state(const bool state)
{
	bool		is_allowed_role = false;

	/* Safety check... */
	if (!pgsp || !pgsp_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_show_plans must be loaded via shared_preload_libraries")));

	/* Superusers or members of pg_read_all_stats members are allowed */
#if PG_VERSION_NUM >= 140000
	is_allowed_role = is_member_of_role(GetUserId(), ROLE_PG_READ_ALL_STATS);
#else
	is_allowed_role = is_member_of_role(GetUserId(), DEFAULT_ROLE_READ_ALL_STATS);
#endif

	if (is_allowed_role)
	{
		SpinLockAcquire(&pgsp->elock);
		pgsp->is_enable = state;
		SpinLockRelease(&pgsp->elock);
	}
}

/*
 * Change the state of this extension: enable or disable
 */
Datum
pg_show_plans_enable(PG_FUNCTION_ARGS)
{
	set_state(true);
	PG_RETURN_VOID();
}

Datum
pg_show_plans_disable(PG_FUNCTION_ARGS)
{
	set_state(false);
	PG_RETURN_VOID();
}

/*
 * Set format to plan_format
 */
static void
set_format(int format)
{
	bool		is_allowed_role = false;

	/* Safety check... */
	if (!pgsp || !pgsp_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_show_plans must be loaded via shared_preload_libraries")));

	/* Superusers or members of pg_read_all_stats members are allowed */
#if PG_VERSION_NUM >= 140000
	is_allowed_role = is_member_of_role(GetUserId(), ROLE_PG_READ_ALL_STATS);
#else
	is_allowed_role = is_member_of_role(GetUserId(), DEFAULT_ROLE_READ_ALL_STATS);
#endif

	if (is_allowed_role)
	{
		SpinLockAcquire(&pgsp->elock);
		pgsp->plan_format = format;
		SpinLockRelease(&pgsp->elock);
	}
}

/*
 * Change the output format.
 */
Datum
pgsp_format_json(PG_FUNCTION_ARGS)
{
	set_format(PLAN_FORMAT_JSON);
	PG_RETURN_VOID();
}

Datum
pgsp_format_text(PG_FUNCTION_ARGS)
{
	set_format(PLAN_FORMAT_TEXT);
	PG_RETURN_VOID();
}

/*
 * Retrieve stored plans.
 */
Datum
pg_show_plans(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	Oid			userid = GetUserId();
	bool		is_allowed_role = false;
	HASH_SEQ_STATUS hash_seq;
	pgspEntry  *entry;

	/* Superusers or members of pg_read_all_stats members are allowed */
#if PG_VERSION_NUM >= 140000
	is_allowed_role = is_member_of_role(GetUserId(), ROLE_PG_READ_ALL_STATS);
#else
	is_allowed_role = is_member_of_role(GetUserId(), DEFAULT_ROLE_READ_ALL_STATS);
#endif

	/* hash table must exist already */
	if (!pgsp || !pgsp_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_show_plans must be loaded via shared_preload_libraries")));

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	/* Switch into long-lived context to construct returned data structures */
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	/* Build a tuple descriptor for our result type */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	/* Skip hashtable retrieving */
	SpinLockAcquire(&pgsp->elock);
	if (!pgsp->is_enable)
	{
		SpinLockRelease(&pgsp->elock);
		return (Datum) 0;
	}
	SpinLockRelease(&pgsp->elock);

	/*----
	 * Get shared lock, and iterate over the hashtable entries
	 */
	LWLockAcquire(pgsp->lock, LW_SHARED);
	PG_TRY();
	{
		hash_seq_init(&hash_seq, pgsp_hash);
		while ((entry = hash_seq_search(&hash_seq)) != NULL)
		{
#define PG_SHOW_PLANS_COLS		 5

			Datum		values[PG_SHOW_PLANS_COLS];
			bool		nulls[PG_SHOW_PLANS_COLS];
			int			i,
						j;

			int			num_backends = pgstat_fetch_stat_numbackends();
			int			curr_backend;
			pid_t		pid = entry->pid;
			bool		exists = false;

			/*----
			 * Delete the garbage plans, which occur when the corresponding
			 * SQL statement is canceled or the executed process crashes.
			 */

			/* Check whether the pid of the entry is running or not */
			for (curr_backend = 1; curr_backend <= num_backends; curr_backend++)
			{
				LocalPgBackendStatus *local_beentry;
				PgBackendStatus *beentry;

				local_beentry = pgstat_fetch_stat_local_beentry(curr_backend);
				beentry = &local_beentry->backendStatus;
				if (beentry->st_procpid == pid && beentry->st_state == STATE_RUNNING)
				{
					exists = true;
					break;
				}
			}

			/*
			 * Delete the pid's entry, because the plan's query is not
			 * running, i.e., it is already committed or aborted.
			 */
			if (!exists)
			{
				LWLockRelease(pgsp->lock);

				LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
				hash_search(pgsp_hash, &entry->key, HASH_REMOVE, NULL);
				LWLockRelease(pgsp->lock);

				LWLockAcquire(pgsp->lock, LW_SHARED);

				continue;
			}

			/*----
			 * Set values
			 */
			for (j = 0; j <= entry->nestedLevel; j++)
			{
				memset(values, 0, sizeof(values));
				memset(nulls, 0, sizeof(nulls));

				i = 0;
				nulls[i] = false;
				values[i++] = ObjectIdGetDatum(entry->key.pid);
				nulls[i] = false;
				values[i++] = ObjectIdGetDatum(j);	/* nested_level */
				nulls[i] = false;
				values[i++] = ObjectIdGetDatum(entry->userid);
				nulls[i] = false;
				values[i++] = ObjectIdGetDatum(entry->dbid);

				if (is_allowed_role || entry->userid == userid)
				{
					char	   *pstr = entry->plan;
					int			offset,
								len;

					offset = (j == 0) ? 0 : entry->terminalByte[j - 1];
					len = (j == 0) ? entry->terminalByte[0] : entry->terminalByte[j] - entry->terminalByte[j - 1];
					nulls[i] = false;
					if (len > 12)	/* If the plan is snipped, we overwrite
									 * the 12 characters string to the plan in
									 * order to show it explicitly. To
									 * simplify the overwrite range issue, I
									 * decided to display the message that is
									 * in the else clause instead of a plan,
									 * if a plan whose length is 12 characters
									 * or less.
									 *
									 * A 12-character SQL plan is too short,
									 * so there is no practical problem. */
					{
						if (entry->isSnipped[j])
						{
							/*
							 * Overwrite the string "...snip..." on the tail
							 * of the plan.
							 */
							char	   *str = "...snip...";

							memcpy((void *) (pstr + offset + len - strlen(str) - 1),
								   str, strlen(str));
						}

						values[i++]
							= CStringGetTextDatum((char *) pg_do_encoding_conversion(
																					 (unsigned char *) (pstr + offset),
																					 len,
																					 entry->encoding,
																					 GetDatabaseEncoding()));
					}
					else
					{
						values[i++] = CStringGetTextDatum(gettext_noop("<Could not store plan because the length of plans "
																	   "already exceeds the max_plan_length.>"));
					}

					if (pstr != entry->plan)
						pfree(pstr);
				}
				else
				{
					nulls[i] = false;
					values[i++] = CStringGetTextDatum("<insufficient privilege>");
				}

				tuplestore_putvalues(tupstore, tupdesc, values, nulls);
			}
		}
	}
	PG_CATCH();
	{
		if (LWLockHeldByMe(pgsp->lock))
			LWLockRelease(pgsp->lock);
	}
	PG_END_TRY();

	LWLockRelease(pgsp->lock);

	tuplestore_donestoring(tupstore);

	return (Datum) 0;
}
