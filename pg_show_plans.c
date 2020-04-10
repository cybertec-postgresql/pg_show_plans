/*-------------------------------------------------------------------------
 *
 * pg_show_plans.c
 *		Show query plans of all currently running SQL statements
 *
 * Copyright (c) 2008-2019, PostgreSQL Global Development Group
 * Copyright (c) 2019-2020, Cybertec Schönig & Schönig GmbH
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
 * Define constants
 */
#define PG_SHOW_PLANS_COLS		 5
#define MAX_NESTED_LEVEL         5	/* This is a misleading name. It is used
									 * to calculate the number of hash table
									 * items: MaxConnections times
									 * MAX_NESTED_LEVEL */

/*
 * Define data types
 */
typedef struct pgspHashKey
{
	pid_t		pid;
	int			nested_level;
}			pgspHashKey;

typedef struct pgspEntry
{
	pgspHashKey key;			/* hash key of entry - MUST BE FIRST */
	Oid			userid;			/* user OID */
	Oid			dbid;			/* database OID */
	int			encoding;		/* query encoding */
	int			plan_len;		/* # of valid bytes in query string */
	slock_t		mutex;			/* protects the entry */
	TransactionId topxid;		/* Top level transaction id of this query */
	char		plan[0];		/* query plan string */
}			pgspEntry;

/* Global shared state */
typedef struct pgspSharedState
{
	LWLock	   *lock;			/* protects hashtable search/modification */
	bool		is_enable;		/* Whether to enable the feature or not */
#if PG_VERSION_NUM >= 90500
	int			plan_format;	/* plan format */
#endif
	slock_t		elock;			/* protects the variable `is_enable` and
								 * `plan_format` */
}			pgspSharedState;

/*
 * Local variables
*/
/* Current nesting depth of ExecutorRun+ProcessUtility calls */
static int	nested_level = 0;

/* Saved hook values in case of unload */
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

#if PG_VERSION_NUM >= 90500
static const struct config_enum_entry plan_formats[] =
{
	{"text", PLAN_FORMAT_TEXT, false},
	{"json", PLAN_FORMAT_JSON, false},
	{NULL, 0, false}
};
#endif

/*
 * static variables
 */
static int	pgsp_max;			/* max plans to show */
#if PG_VERSION_NUM >= 90500
static int	plan_format;		/* output format */
#endif
static int	max_plan_length;	/* max length of query plan */

/*
 * Function declarations
 */
void		_PG_init(void);
void		_PG_fini(void);

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

static Size pgsp_memsize(void);
static void pgsp_shmem_startup(void);
static void pgsp_shmem_shutdown(int code, Datum arg);
static void pgsp_ExecutorStart(QueryDesc *queryDesc, int eflags);
static void pgsp_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction,
#if PG_VERSION_NUM >= 100000
							 uint64 count, bool execute_once);
#elif PG_VERSION_NUM >= 90600
							 uint64 count);
#else
							 long count);
#endif
static void pgsp_ExecutorFinish(QueryDesc *queryDesc);
static void pgsp_ExecutorEnd(QueryDesc *queryDesc);

static pgspEntry * entry_alloc(pgspHashKey * key, const char *query, int plan_len);
static void entry_store(char *plan, const int nested_level);
static void entry_delete(const uint32 pid, const int nested_level);
static uint32 gen_hashkey(const void *key, Size keysize);
static int	compare_hashkey(const void *key1, const void *key2, Size keysize);
static void set_state(bool state);

/*
 * Module callback
 */
void
_PG_init(void)
{
	if (!process_shared_preload_libraries_in_progress)
		return;

	DefineCustomIntVariable("pg_show_plans.max_plan_length",
							"Set the maximum plan length.",
							NULL,
							&max_plan_length,
							8 * 1024,
							1024,
							100 * 1024,
							PGC_POSTMASTER,
							0,
							NULL,
							NULL,
							NULL);

#if PG_VERSION_NUM >= 90500
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
#endif

	EmitWarningsOnPlaceholders("pg_show_plans");

	RequestAddinShmemSpace(pgsp_memsize());
#if PG_VERSION_NUM >= 90600
	RequestNamedLWLockTranche("pg_show_plans", 1);
#else
	RequestAddinLWLocks(1);
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

void
_PG_fini(void)
{
	/* Uninstall hooks. */
	shmem_startup_hook = prev_shmem_startup_hook;
	ExecutorStart_hook = prev_ExecutorStart;
	ExecutorRun_hook = prev_ExecutorRun;
	ExecutorFinish_hook = prev_ExecutorFinish;
	ExecutorEnd_hook = prev_ExecutorEnd;
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
#if PG_VERSION_NUM >= 90600
		pgsp->lock = &(GetNamedLWLockTranche("pg_show_plans"))->lock;
#else
		pgsp->lock = LWLockAssign();
#endif
		SpinLockInit(&pgsp->elock);
	}

	/* Set the initial value to is_enable */
	pgsp->is_enable = true;
#if PG_VERSION_NUM >= 90500
	pgsp->plan_format = plan_format;
#endif

	/* Be sure everyone agrees on the hash table entry size */
	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(pgspHashKey);
	info.entrysize = offsetof(pgspEntry, plan) + max_plan_length;

	info.hash = gen_hashkey;
	info.match = compare_hashkey;

	pgsp_hash = ShmemInitHash("pg_show_plans hash",
							  pgsp_max, pgsp_max * MAX_NESTED_LEVEL,
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
#if PG_VERSION_NUM >= 90500
	ExplainState *es = NewExplainState();
#else
	ExplainState es;
#endif

	if (prev_ExecutorStart)
		prev_ExecutorStart(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);

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
	SpinLockRelease(&pgsp->elock);

#if PG_VERSION_NUM >= 90500
	SpinLockAcquire(&pgsp->elock);
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
		SpinLockAcquire(&pgsp->elock);
		if (pgsp->plan_format == PLAN_FORMAT_JSON)
		{
			es->str->data[0] = '{';
			es->str->data[es->str->len - 1] = '}';
		}
		else if (pgsp->plan_format == PLAN_FORMAT_TEXT)
		{
			es->str->len--;
			es->str->data[es->str->len] = '\0';
		}
		SpinLockRelease(&pgsp->elock);
	}

	entry_store(es->str->data, nested_level);
	pfree(es->str->data);

#else

	ExplainInitState(&es);

	ExplainBeginOutput(&es);
	ExplainPrintPlan(&es, queryDesc);
	ExplainEndOutput(&es);

	if (es.str->len >= max_plan_length)
	{
		/*
		 * Note: If the length of the query plan is longer than
		 * max_plan_length, the message below is shown instead of the plan
		 * string.
		 */
		char	   *msg = "<too long query plan string>";

		memcpy(es.str->data, msg, strlen(msg));
		es.str->len = strlen(msg);
		es.str->data[es.str->len] = '\0';
	}
	else
	{
		SpinLockAcquire(&pgsp->elock);
		es.str->len--;
		es.str->data[es.str->len] = '\0';
		SpinLockRelease(&pgsp->elock);
	}

	entry_store(es.str->data, nested_level);
	pfree(es.str->data);
#endif
}

/*
 * ExecutorRun hook: all we need do is show nesting depth
 */
static void
pgsp_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction,
#if PG_VERSION_NUM >= 100000
							 uint64 count, bool execute_once)
#elif PG_VERSION_NUM >= 90600
							 uint64 count)
#else
							 long count)
#endif
{
	nested_level++;
	PG_TRY();
	{
		if (prev_ExecutorRun)
#if PG_VERSION_NUM >= 100000
			prev_ExecutorRun(queryDesc, direction, count, execute_once);
#else
			prev_ExecutorRun(queryDesc, direction, count);
#endif
		else
#if PG_VERSION_NUM >= 100000
			standard_ExecutorRun(queryDesc, direction, count, execute_once);
#else
			standard_ExecutorRun(queryDesc, direction, count);
#endif
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
	/* Delete entry */

	SpinLockAcquire(&pgsp->elock);
	if (pgsp->is_enable)
	{
		SpinLockRelease(&pgsp->elock);
		entry_delete(getpid(), nested_level);
	}
	else
		SpinLockRelease(&pgsp->elock);

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}

/*
 * Store a plan to the hashtable.
 */
static void
entry_store(char *plan, const int nested_level)
{
	pgspHashKey key;
	pgspEntry  *entry;
	int			plan_len;

	pgspEntry  *e;

	Assert(plan != NULL);

	/* Safety check... */
	if (!pgsp || !pgsp_hash)
		return;

	key.pid = getpid();
	key.nested_level = nested_level;
	plan_len = strlen(plan);

	Assert(plan_len >= 0 && plan_len < max_plan_length);

	/* Look up the hash table entry with shared lock. */
	LWLockAcquire(pgsp->lock, LW_SHARED);
	entry = (pgspEntry *) hash_search(pgsp_hash, &key, HASH_FIND, NULL);
	LWLockRelease(pgsp->lock);

	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);

	/* Delete old entries if exist. */
	if (entry != NULL)
	{
		pgspHashKey tmp_key;

		tmp_key.pid = key.pid;
		tmp_key.nested_level = nested_level;
		do
		{
			hash_search(pgsp_hash, &tmp_key, HASH_REMOVE, NULL);
			tmp_key.nested_level++;
		}
		while (hash_search(pgsp_hash, &tmp_key, HASH_FIND, NULL) != NULL);
	}

	/* Create new entry */
	if ((entry = entry_alloc(&key, "", 0)) == NULL)
	{
		/* New entry was not created since hashtable is full. */
		LWLockRelease(pgsp->lock);
		return;
	}

	/* Store data into the entry. */
	e = (pgspEntry *) entry;
	SpinLockAcquire(&e->mutex);
	e->userid = GetUserId();
	e->dbid = MyDatabaseId;
	e->encoding = GetDatabaseEncoding();
	if (!RecoveryInProgress())
		e->topxid = GetTopTransactionId();
	else
		/*
		 * In recovery mode, we use pid as the key instead of txid for garbage
		 * collection.
		 */
		e->topxid = (uint32) key.pid;
	memcpy(entry->plan, plan, plan_len);
	entry->plan_len = plan_len;
	entry->plan[plan_len] = '\0';

	SpinLockRelease(&e->mutex);

	LWLockRelease(pgsp->lock);
}

/*
 * Estimate shared memory space needed.
 */
static Size
pgsp_memsize(void)
{
	Size		size;

	size = MAXALIGN(sizeof(pgspSharedState));
	size = add_size(size, hash_estimate_size(pgsp_max * MAX_NESTED_LEVEL, sizeof(pgspEntry)));
	return size;
}

/*
 * Generate a unique value from hashkey for the hashtable.
 */
static uint32
gen_hashkey(const void *key, Size keysize)
{
	const		pgspHashKey *k = (const pgspHashKey *) key;

	/*
	 * The maximum pid number is 2^23 in Linux, so we make a unique value
	 * shown below as a hash key.
	 */
	return (uint32) (k->pid + (k->nested_level * (0x1 << 24)));
}

/*
 * Compare hashkeys
 */
static int
compare_hashkey(const void *key1, const void *key2, Size keysize)
{
	const		pgspHashKey *k1 = (const pgspHashKey *) key1;
	const		pgspHashKey *k2 = (const pgspHashKey *) key2;

	if (k1->pid == k2->pid &&
		k1->nested_level == k2->nested_level)
		return 0;
	else
		return 1;
}

/*
 * Allocate a new hashtable entry.
 * caller must hold an exclusive lock on pgsp->lock
 *
 * "plan" need not be null-terminated.
 */
static pgspEntry *
entry_alloc(pgspHashKey * key, const char *plan, int plan_len)
{
	pgspEntry  *entry;
	bool		found;

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

		Assert(plan_len >= 0 && plan_len < max_plan_length);
		entry->plan_len = plan_len;
		memcpy(entry->plan, plan, plan_len);
		entry->plan[plan_len] = '\0';
	}

	return entry;
}

/*
 * Delete all stored plans related to pid.
 */
static void
entry_delete(const uint32 pid, const int nested_level)
{
	pgspHashKey key;

	/* Safety check... */
	if (!pgsp || !pgsp_hash)
		return;

	key.pid = pid;
	key.nested_level = nested_level;

	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
	hash_search(pgsp_hash, &key, HASH_REMOVE, NULL);
	LWLockRelease(pgsp->lock);
}

/*
 * Set state to is_enable
 */
static void
set_state(bool state)
{
	bool		is_allowed_role = false;

	/* Superusers or members of pg_read_all_stats members are allowed */
#if PG_VERSION_NUM >= 100000
	is_allowed_role = is_member_of_role(GetUserId(), DEFAULT_ROLE_READ_ALL_STATS);
#else
	is_allowed_role = superuser();
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

	/* Superusers or members of pg_read_all_stats members are allowed */
#if PG_VERSION_NUM >= 100000
	is_allowed_role = is_member_of_role(GetUserId(), DEFAULT_ROLE_READ_ALL_STATS);
#else
	is_allowed_role = superuser();
#endif

	if (is_allowed_role)
	{
#if PG_VERSION_NUM >= 90500
		SpinLockAcquire(&pgsp->elock);
		pgsp->plan_format = format;
		SpinLockRelease(&pgsp->elock);
#endif
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
#if PG_VERSION_NUM >= 100000
	is_allowed_role = is_member_of_role(GetUserId(), DEFAULT_ROLE_READ_ALL_STATS);
#else
	is_allowed_role = superuser();
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

	/* Get shared lock, and iterate over the hashtable entries */
	LWLockAcquire(pgsp->lock, LW_SHARED);

	hash_seq_init(&hash_seq, pgsp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		Datum		values[PG_SHOW_PLANS_COLS];
		bool		nulls[PG_SHOW_PLANS_COLS];
		int			i = 0;

		/*
		 * Delete stored plans which the corresponding SQL statements have
		 * been already committed or aborted.
		 *
		 * These garbage plans occur when the corresponding SQL statement is
		 * canceled or the executed process crashes.
		 */
		if (!RecoveryInProgress())
		{
			if (TransactionIdDidCommit(entry->topxid)
				|| TransactionIdDidAbort(entry->topxid))
			{
				LWLockRelease(pgsp->lock);

				LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
				hash_search(pgsp_hash, &entry->key, HASH_REMOVE, NULL);
				LWLockRelease(pgsp->lock);

				LWLockAcquire(pgsp->lock, LW_SHARED);

				continue;
			}
		}
		else
		{
			/*
			 * In recovery mode, we cannot use txid. Therefore, we check
			 * whether the pid of the entry is still running and the state of
			 * the pid is active in each entry.
			 *
			 * If the pid of the entry does not already exist, the entry has
			 * to be removed. And the pid of the entry still exists but the
			 * state of the pid is not active, we have to also remove the
			 * entry because it is a garbege plan created by canceling the
			 * previous transaction.
			 *
			 * This part is not efficient because of a for-loop, however, we
			 * do not care about it because this function is not often
			 * executed.
			 */
			int			num_backends = pgstat_fetch_stat_numbackends();
			int			curr_backend;
			uint32		pid = (uint32) entry->topxid;
			bool		exists = false;

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

			if (!exists)
			{
				LWLockRelease(pgsp->lock);

				LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
				hash_search(pgsp_hash, &entry->key, HASH_REMOVE, NULL);
				LWLockRelease(pgsp->lock);

				LWLockAcquire(pgsp->lock, LW_SHARED);

				continue;
			}
		}

		/* Set values */
		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		values[i++] = ObjectIdGetDatum(entry->key.pid);
		values[i++] = ObjectIdGetDatum(entry->key.nested_level);
		values[i++] = ObjectIdGetDatum(entry->userid);
		values[i++] = ObjectIdGetDatum(entry->dbid);

		if (is_allowed_role || entry->userid == userid)
		{
			char	   *pstr = entry->plan;

			values[i++]
				= CStringGetTextDatum((char *) pg_do_encoding_conversion(
																		 (unsigned char *) pstr,
																		 entry->plan_len,
																		 entry->encoding,
																		 GetDatabaseEncoding()));

			if (pstr != entry->plan)
				pfree(pstr);
		}
		else
		{
			values[i++] = CStringGetTextDatum("<insufficient privilege>");
		}

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}

	LWLockRelease(pgsp->lock);

	tuplestore_donestoring(tupstore);

	return (Datum) 0;
}
