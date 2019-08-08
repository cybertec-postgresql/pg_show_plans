/*-------------------------------------------------------------------------
 *
 * pg_show_plans.c
 *		Show query plans of all currently running SQL statements
 *
 * Copyright (c) 2008-2019, PostgreSQL Global Development Group
 * Copyright (c) 2019, Cybertec Schönig & Schönig GmbH
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <unistd.h>
#include <dlfcn.h>

#include "access/hash.h"
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

PG_MODULE_MAGIC;

/*
 * Define constants
 */
#define PLAN_SIZE             3000 /* Max length of query plan string */
#define PG_SHOW_PLANS_COLS		 4

/*
 * Define data types
 */
typedef struct pgspHashKey
{
	pid_t       pid;
} pgspHashKey;

typedef struct pgspEntry
{
	pgspHashKey	key;			/* hash key of entry - MUST BE FIRST */
	Oid			userid;			/* user OID */
	Oid			dbid;			/* database OID */
	int			encoding;		/* query encoding */
	int			plan_len;		/* # of valid bytes in query string */
	slock_t		mutex;			/* protects the counters only */
	char		plan[PLAN_SIZE];/* query plan */
} pgspEntry;

/*
 * Global shared state
 */
typedef struct pgspSharedState
{
	LWLock	*lock;			/* protects hashtable search/modification */
} pgspSharedState;

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
static pgspSharedState *pgsp = NULL;
static HTAB *pgsp_hash = NULL;

/*
 * GUC variables
 */
typedef enum
{
	PGSP_SHOW_LEVEL_TOP,			/* only top level statement's query plans */
	PGSP_SHOW_LEVEL_NONE			/* show no plans */
}	PGSPShowLevel;

static const struct config_enum_entry show_options[] =
{
	{"top", PGSP_SHOW_LEVEL_TOP, false},
	{"none", PGSP_SHOW_LEVEL_NONE, false},
	{NULL, 0, false}
};

typedef enum
{
	PLAN_FORMAT_JSON,
	PLAN_FORMAT_TEXT
}	PGSPPlanFormats;

static const struct config_enum_entry plan_formats[] =
{
	{"json", PLAN_FORMAT_JSON, false},
	{"text", PLAN_FORMAT_TEXT, false},
	{NULL, 0, false}
};

static int	pgsp_max;			/* max # plans to show */
static int	pgsp_show_level;	/* show level */

static int  plan_format;

#define pgsp_enabled() \
	(pgsp_show_level == PGSP_SHOW_LEVEL_TOP && nested_level == 0)

/*
 * Function declarations
 */
void		_PG_init(void);
void		_PG_fini(void);

Datum		pg_show_plans(PG_FUNCTION_ARGS);
Datum		pg_show_plans_delete_all(PG_FUNCTION_ARGS);
Datum		pg_show_plans_delete(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pg_show_plans);
PG_FUNCTION_INFO_V1(pg_show_plans_delete_all);
PG_FUNCTION_INFO_V1(pg_show_plans_delete);

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

static pgspEntry *entry_alloc(pgspHashKey *key, const char *query, int plan_len);
static void entry_store(char *plan);
static void entry_delete_all(void);
static void entry_delete(const uint32 pid);


/*
 * Module callback
 */
void
_PG_init(void)
{
	if (!process_shared_preload_libraries_in_progress)
		return;

	DefineCustomEnumVariable("pg_show_plans.show_level",
							 "Selects which plans are shown by pg_show_plans.",
							 NULL,
							 &pgsp_show_level,
							 PGSP_SHOW_LEVEL_TOP,
							 show_options,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomEnumVariable("pg_show_plans.plan_format",
							 "Selects which format to be appied for plan representation in pg_show_plans.",
							 NULL,
							 &plan_format,
							 PLAN_FORMAT_JSON,
							 plan_formats,
							 PGC_USERSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

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
		/* First time through ... */
#if PG_VERSION_NUM >= 90600
		pgsp->lock = &(GetNamedLWLockTranche("pg_show_plans"))->lock;
#else
		pgsp->lock = LWLockAssign();
#endif

	/* Be sure everyone agrees on the hash table entry size */
	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(pgspHashKey);
	info.entrysize = sizeof(pgspEntry);
	pgsp_hash = ShmemInitHash("pg_show_plans hash",
							  pgsp_max, pgsp_max,
							  &info,
							  HASH_ELEM);

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
	if (prev_ExecutorStart)
		prev_ExecutorStart(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);

	/*
	 * Execute EXPLAIN and Store the query plan into the hashtable
	 */
	if (pgsp_enabled())
	{
		ExplainState *es     = NewExplainState();
	    switch (plan_format)
		{
			case PLAN_FORMAT_TEXT:
				es->format = EXPLAIN_FORMAT_TEXT;
				break;
			case PLAN_FORMAT_JSON:
			default:
				es->format = EXPLAIN_FORMAT_JSON;
				break;		
		};

		ExplainBeginOutput(es);
		ExplainPrintPlan(es, queryDesc);
		ExplainEndOutput(es);

		if (es->str->len >= PLAN_SIZE)
		{
			/* 
			 * Note: If the length of the query plan is longer than PLAN_SIZE, 
			 * the message below is shown instead of the plan string.
			 */
			char *msg = "<too long query plan string>";
			memcpy(es->str->data, msg, strlen(msg));
			es->str->len = strlen(msg);
			es->str->data[es->str->len] = '\0';
		}
		else {
			if (plan_format == PLAN_FORMAT_JSON)
			{
				es->str->data[0] = '{';
				es->str->data[es->str->len - 1] = '}';
			}
			else if (plan_format == PLAN_FORMAT_TEXT)
			{
				es->str->len--;
				es->str->data[es->str->len] = '\0';
			}
		}

		entry_store(es->str->data);

		pfree(es->str->data);
	}
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
	/* Delete entry. */
	if (pgsp_enabled())
		entry_delete(getpid());

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}

/*
 * Store a plan to the hashtable.
 */
static void
entry_store(char *plan)
{
	pgspHashKey key;
	pgspEntry  *entry;
	char	   *norm_query = NULL;
	int 		plan_len;

	pgspEntry *e;

	Assert(plan != NULL);

	/* Safety check... */
	if (!pgsp || !pgsp_hash)
		return;

	key.pid = getpid();
	plan_len = strlen(plan);
	Assert(plan_len >= 0 && plan_len < PLAN_SIZE);
	
	/* Look up the hash table entry with shared lock. */
	LWLockAcquire(pgsp->lock, LW_SHARED);

	entry = (pgspEntry *) hash_search(pgsp_hash, &key, HASH_FIND, NULL);

	/* Create new entry, if not present */
	if (!entry)
	{
		LWLockRelease(pgsp->lock);

		LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
		entry = entry_alloc(&key, "", 0);
	}

	/* Grab the spinlock while updating the entry */
	e = (pgspEntry *) entry;
	SpinLockAcquire(&e->mutex);

	e->userid = GetUserId();
	e->dbid = MyDatabaseId;
	e->encoding = GetDatabaseEncoding();

	memcpy(entry->plan, plan, plan_len);
	entry->plan_len = plan_len;
	entry->plan[plan_len] = '\0';

	SpinLockRelease(&e->mutex);

	LWLockRelease(pgsp->lock);

	/* We postpone this pfree until we're out of the lock */
	if (norm_query)
		pfree(norm_query);
}

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
 * Allocate a new hashtable entry.
 * caller must hold an exclusive lock on pgsp->lock
 *
 * "plan" need not be null-terminated.
 */
static pgspEntry *
entry_alloc(pgspHashKey *key, const char *plan, int plan_len)
{
	pgspEntry  *entry;
	bool		found;

	/* Find or create an entry with desired hash code */
	entry = (pgspEntry *) hash_search(pgsp_hash, key, HASH_ENTER, &found);

	if (!found)
	{
		/* New entry, initialize it */
		SpinLockInit(&entry->mutex);

		Assert(plan_len >= 0 && plan_len < PLAN_SIZE);
		entry->plan_len = plan_len;
		memcpy(entry->plan, plan, plan_len);
		entry->plan[plan_len] = '\0';
	}

	return entry;
}

/*
 * Delete all entries.
 */
static void
entry_delete_all(void)
{
	HASH_SEQ_STATUS hash_seq;
	pgspEntry  *entry;

	/* Safety check... */
	if (!pgsp || !pgsp_hash)
		return;

	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
	hash_seq_init(&hash_seq, pgsp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		hash_search(pgsp_hash, &entry->key, HASH_REMOVE, NULL);
	}
	LWLockRelease(pgsp->lock);
}

/*
 * Delete the entry
 */
static void
entry_delete(const uint32 pid)
{
	pgspHashKey key;

	/* Safety check... */
	if (!pgsp || !pgsp_hash)
		return;

	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
	key.pid = pid;
	hash_search(pgsp_hash, &key, HASH_REMOVE, NULL);
	LWLockRelease(pgsp->lock);
}

/*
 * Delete all plans.
 */
Datum
pg_show_plans_delete_all(PG_FUNCTION_ARGS)
{
	if (!pgsp || !pgsp_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_show_plans must be loaded via shared_preload_libraries")));
	entry_delete_all();
	PG_RETURN_VOID();
}

/*
 * Delete the specified plan.
 */
Datum
pg_show_plans_delete(PG_FUNCTION_ARGS)
{
	uint32 pid = PG_GETARG_UINT32(0);

	if (!pgsp || !pgsp_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_show_plans must be loaded via shared_preload_libraries")));

	entry_delete(pid);
	PG_RETURN_VOID();
}


/*
 * Retrieve statement statistics.
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

	/*
	 * Get shared lock, and iterate over the hashtable entries.
	 */
	LWLockAcquire(pgsp->lock, LW_SHARED);

	hash_seq_init(&hash_seq, pgsp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		Datum		values[PG_SHOW_PLANS_COLS];
		bool		nulls[PG_SHOW_PLANS_COLS];
		int			i = 0;

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		values[i++] = ObjectIdGetDatum(entry->key.pid);
		values[i++] = ObjectIdGetDatum(entry->userid);
		values[i++] = ObjectIdGetDatum(entry->dbid);

		if (is_allowed_role || entry->userid == userid)
		{
			char *pstr = entry->plan;

			values[i++] 
				= CStringGetTextDatum((char *)pg_do_encoding_conversion((unsigned char *) pstr,
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
