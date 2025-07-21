/*
 * -------------------------------------------------------------------------
 *
 * pg_show_plans.c
 *             Show query plans of all currently running SQL statements
 *
 * Copyright (c) 2008-2022, PostgreSQL Global Development Group
 * Copyright (c) 2019-2023, CYBERTEC PostgreSQL International GmbH
 *
 * -------------------------------------------------------------------------
 */

/* Includes */
#include "postgres.h"

#include "catalog/pg_authid.h"
#include "commands/explain.h"
#if PG_VERSION_NUM >= 180000
#include "commands/explain_state.h"
#include "commands/explain_format.h"
#endif
#include "fmgr.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"

/* Constants and Macros */
PG_MODULE_MAGIC;

#if PG_VERSION_NUM < 120000
#error "Unsupported PostgreSQL Version"
#endif

#define MAX_NEST_LEVEL 10

/* Typedefs */
typedef struct pgspHashKey /* Hash entry key. */
{
	pid_t pid;
} pgspHashKey;

typedef struct pgspEntry /* Hash table entry. */
{
	pgspHashKey hash_key; /* Entry hash key, must be first. */
	slock_t     mutex;    /* Protects the entry. */
	Oid         user_id;  /* User OID. */
	Oid         db_id;    /* Database OID. */
	int         plan_len[MAX_NEST_LEVEL]; /* Query plan length in bytes. */
	int         n_plans;  /* Query plan count. */
	char        plan[];   /* Query plan string. */
} pgspEntry;

typedef struct pgspSharedState /* Shared state of the extension. */
{
	LWLock *lock;       /* Protects shared hash table. */
	bool    is_enabled; /* Enables or disables the extension. */
	int     plan_format;
} pgspSharedState;

typedef struct pgspCtx { /* Used as `funcctx->user_fctx` in pg_show_plans(). */
	HASH_SEQ_STATUS *hash_seq;
	pgspEntry       *pgsp_tmp_entry; /* PGSP entry currently processing. */
	int              curr_nest; /* Current nest level porcessing. */
	bool             is_done; /* Done processing current PGSP entry? */
} pgspCtx;

/* Function Prototypes */
void _PG_init(void);
/* Returns shared hash entry size. */
static Size hash_entry_size(void);
/* Calculates shared memory size required for the extension. */
static Size shmem_required(void);
/* Generates a hash entry key. */
static uint32 gen_hash_key(const void *key, Size keysize);
/* Hash entry comparison function. */
static int compare_hash_key(const void *key1, const void *key2, Size keysize);
/* Caches the process' hash entry (if not already). Returns 1 on success. */
static int ensure_cached(void);
/* Grabs an exclusive lock, and creates a new hash table entry. */
static pgspEntry *create_hash_entry(const pgspHashKey *key);
/* Add a new query plan to the shared hash entry. */
static void append_query_plan(ExplainState *es);
/* on_shmem_exit() callback to delete hash entry on client disconnect. */
static void cleanup(int code, Datum arg);
/* Set extension state, either enable or disable. */
static void set_state(bool state, void *extra);
static const char *show_state(void);
/* Set query plan output format: text, json, ... */
static void set_format(const int format);
/* Propagate GUC variable value to shared memory (assign hook). */
static void prop_format_to_shmem(int newval, void *extra);
static const char *show_format(void);
/* Check the extension has been properly loaded. */
static inline void shmem_safety_check(void);
/* Check whether the user has required privileges. */
static bool is_allowed_role(void);
/* Hook functions. */
/* Ask for shared memory. */
#if PG_VERSION_NUM >= 150000
static void pgsp_shmem_request(void);
#endif
static void pgsp_shmem_startup(void);
/* Saves query plans to the shared hash table. */
static void pgsp_ExecutorStart(QueryDesc *queryDesc, int eflags);
/* Keeps track of the nest level. */
static void pgsp_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction,
                             uint64 count
#if PG_VERSION_NUM < 180000
							 , bool execute_once
#endif
							);

/* Show query plans of all the currently running statements. */
Datum pg_show_plans(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pg_show_plans);

/* Global Variables */
/* Shared extension state. */
static pgspSharedState *pgsp = NULL;
/* Current process' hash entry. */
static pgspEntry *pgsp_cache = NULL;
/* Shared hash table with query plans. */
static HTAB *pgsp_hash = NULL;
/* Current query plan nested level. */
static unsigned int nest_level = 0;
/* To save old hook values. */
#if PG_VERSION_NUM >= 150000
static shmem_request_hook_type prev_shmem_request_hook = NULL;
#endif
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;

/* GUC variables. */
/* Maximal query plan length. */
static int max_plan_length;
/* Start extension enabled or not?. */
static bool start_enabled;
/* pg_show_plans() query plan output format. */
static int plan_format;
/* Available query plan formats. */
static const struct config_enum_entry plan_formats[] =
{
	{"text", EXPLAIN_FORMAT_TEXT, false},
	{"json", EXPLAIN_FORMAT_JSON, false},
	{"yaml", EXPLAIN_FORMAT_YAML, false},
	{"xml",  EXPLAIN_FORMAT_XML,  false},
	{NULL, 0, false}
};

void
_PG_init(void)
{
	/* Must be in shared_preload_libraries="...". */
	if (!process_shared_preload_libraries_in_progress)
		return;

	DefineCustomBoolVariable("pg_show_plans.is_enabled",
	                         "Start with the extension enabled?",
	                         NULL,
	                         &start_enabled,
	                         true,
#if PG_VERSION_NUM >= 150000
	                         PGC_USERSET,
#else
	                         PGC_POSTMASTER,
#endif
	                         0,
	                         NULL, set_state, show_state);
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
	                        NULL, NULL, NULL);
	DefineCustomEnumVariable("pg_show_plans.plan_format",
	                         "Set the output format of query plans.",
	                         NULL,
	                         &plan_format,
	                         EXPLAIN_FORMAT_TEXT,
	                         plan_formats,
#if PG_VERSION_NUM >= 150000
	                         PGC_USERSET,
#else
	                         PGC_POSTMASTER,
#endif
	                         0,
	                         NULL, prop_format_to_shmem, show_format);

	/* Save old hooks, and install new ones. */
#if PG_VERSION_NUM >= 150000
	prev_shmem_request_hook = shmem_request_hook;
	shmem_request_hook = pgsp_shmem_request;
#else
	RequestAddinShmemSpace(shmem_required());
	RequestNamedLWLockTranche("pg_show_plans", 1);
#endif
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pgsp_shmem_startup;

	prev_ExecutorStart = ExecutorStart_hook;
	ExecutorStart_hook = pgsp_ExecutorStart; /* Store new plans. */

	prev_ExecutorRun = ExecutorRun_hook;
	ExecutorRun_hook = pgsp_ExecutorRun;     /* Track nest level. */
}

static Size
hash_entry_size(void)
{	/* Structure size & variable array maximal length. */
	return offsetof(pgspEntry, plan) + max_plan_length;
}

static Size
shmem_required(void)
{
	Size s;
	s = MAXALIGN(sizeof(pgspSharedState));
	s = add_size(s,
	             hash_estimate_size(MaxConnections, hash_entry_size()) );
	return s;
}

static uint32
gen_hash_key(const void *key, Size keysize)
{
	const pgspHashKey *k = (const pgspHashKey *) key;
	return (uint32) k->pid;
}

static int
compare_hash_key(const void *key1, const void *key2, Size keysize)
{
	const pgspHashKey *k1 = (const pgspHashKey *) key1;
	const pgspHashKey *k2 = (const pgspHashKey *) key2;
	return (k1->pid == k2->pid) ? 0 : 1;
}

static int
ensure_cached(void)
{
	pgspHashKey pgsp_hash_hey;

	if (pgsp_cache)
		return 1;

	pgsp_hash_hey.pid = MyProcPid;
	pgsp_cache = create_hash_entry(&pgsp_hash_hey);
	if (!pgsp_cache)
		return 0; /* Ran out of memory. */

	pgsp_cache->user_id = GetUserId();
	pgsp_cache->plan[0] = '\0';
	pgsp_cache->n_plans = 0;
	on_shmem_exit(cleanup, (Datum)NULL);
	return 1;
}

/* Returns NULL if the hash table is full. */
static pgspEntry *
create_hash_entry(const pgspHashKey *key)
{
	pgspEntry *entry;
	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
	entry = (pgspEntry *)hash_search(pgsp_hash,
	                                 key,
	                                 HASH_ENTER_NULL,
	                                 NULL);
	LWLockRelease(pgsp->lock);
	return entry;
}

static void
append_query_plan(ExplainState *es)
{
	const StringInfo new_plan = es->str;
	int i;
	int space_left; /* Space left within a shared hash map entry. */
	int offset; /* Beginning of free space within an entry. */

	offset = 0;
	for (i = 0; i < nest_level; i++)
		offset += pgsp_cache->plan_len[i] + 1; /* +1 for '\0'. */
	space_left = max_plan_length - offset;

	if (pgsp->plan_format == EXPLAIN_FORMAT_TEXT)
		new_plan->len--; /* Discard '\n'. */

	if (space_left < new_plan->len+1) {
		ereport(WARNING,
		        errcode(ERRCODE_OUT_OF_MEMORY),
		        errmsg("not enough memory to append new query plans"),
		        errhint("Try increasing 'pg_show_plans.max_plan_length'."));
		return;
	}

	memcpy(pgsp_cache->plan + offset,
		   new_plan->data, new_plan->len);
	pgsp_cache->plan[offset + new_plan->len] = '\0';
	pgsp_cache->plan_len[nest_level] = new_plan->len;
	pgsp_cache->db_id = MyDatabaseId;
	pgsp_cache->n_plans = nest_level+1;
}

static void
cleanup(int code, Datum arg)
{
	pgspHashKey key;
	key.pid = pgsp_cache->hash_key.pid;
	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
	hash_search(pgsp_hash, &key, HASH_REMOVE, NULL);
	LWLockRelease(pgsp->lock);
}

static void
set_state(bool state, void *extra)
{
	/* Shared memory may not be fully available at server start, so we do not
	 * check for pgsp_hash availability here. That is why the following line is
	 * commented out. */
	/* shmem_safety_check(); */

	if (pgsp != NULL)
		pgsp->is_enabled = state;
}

/* since we can't update start_enabled in running backends, provide a show hook
 * that reads the value from shared memory */
static const char *
show_state()
{
	if (pgsp->is_enabled)
		return "on";
	else
		return "off";
}

static void
set_format(const int format)
{
	/* Shared memory may not be fully available at server start, so we do not
	 * check for pgsp_hash availability here. That is why the following line is
	 * commented out. */
	/* shmem_safety_check(); */

	if (pgsp != NULL && is_allowed_role())
		pgsp->plan_format = format;
}

static void
prop_format_to_shmem(int newval, void *extra)
{
	set_format(newval);
}

static const char *
show_format()
{
	if (pgsp->plan_format == EXPLAIN_FORMAT_TEXT)
		return "text";
	else if (pgsp->plan_format == EXPLAIN_FORMAT_JSON)
		return "json";
	else if (pgsp->plan_format == EXPLAIN_FORMAT_YAML)
		return "yaml";
	else if (pgsp->plan_format == EXPLAIN_FORMAT_XML)
		return "xml";
	else
		ereport(ERROR,
		        errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
		        errmsg("unexpected plan_format value: %d", pgsp->plan_format),
		        errhint("Valid values are 'text', 'json', 'yaml', 'xml'."));
}

static inline void
shmem_safety_check(void)
{
	if (pgsp && pgsp_hash)
		return;

	ereport(ERROR,
	        errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
	        errmsg("shared library not found"),
	        errhint("Add 'pg_show_plans' to 'shared_preload_libraries', "
	                "and restart the server."));
}

static bool
is_allowed_role(void)
{
	bool is_allowed_role = false;
#if PG_VERSION_NUM >= 140000
	is_allowed_role = is_member_of_role(GetUserId(), ROLE_PG_READ_ALL_STATS);
#else
	is_allowed_role = is_member_of_role(GetUserId(), DEFAULT_ROLE_READ_ALL_STATS);
#endif
	return is_allowed_role;

}

#if PG_VERSION_NUM >= 150000
static void
pgsp_shmem_request(void)
{
	if (prev_shmem_request_hook)
		prev_shmem_request_hook();
	RequestAddinShmemSpace(shmem_required());
	RequestNamedLWLockTranche("pg_show_plans", 1);
}
#endif

static void
pgsp_shmem_startup(void)
{
	bool    found;
	HASHCTL info;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/* Reset in case this is a restart within the postmaster. */
	pgsp = NULL;
	pgsp_hash = NULL;

	/* Create or attach to the shared memory state, including hash table. */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	pgsp = ShmemInitStruct("pg_show_plans",
	                       sizeof(pgspSharedState), &found);
	if (!found) /* First time. */
	{
		pgsp->lock = &(GetNamedLWLockTranche("pg_show_plans"))->lock;
		pgsp->is_enabled = start_enabled;
		pgsp->plan_format = plan_format;
	}

	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(pgspHashKey);
	info.entrysize = hash_entry_size();
	info.hash = gen_hash_key;
	info.match = compare_hash_key;
	pgsp_hash = ShmemInitHash("pg_show_plans hash",
	                          MaxConnections,
	                          MaxConnections,
	                          &info,
	                          HASH_ELEM|HASH_FUNCTION|HASH_COMPARE);

	LWLockRelease(AddinShmemInitLock);
}

static void
pgsp_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	ExplainState *es;

	if (prev_ExecutorStart)
	{
		prev_ExecutorStart(queryDesc, eflags);
	}
	else
	{
		standard_ExecutorStart(queryDesc, eflags);
	}

	if (!ensure_cached()) {
		ereport(WARNING,
		        errcode(ERRCODE_OUT_OF_MEMORY),
		        errmsg("not enough memory to append new query plans"),
		        errhint("Try increasing 'pg_show_plans.max_plan_length'."));
		return;
	}

	if (!pgsp->is_enabled)
	{
		return;
	}

	es = NewExplainState();
	es->format = pgsp->plan_format;
	ExplainBeginOutput(es);
	ExplainPrintPlan(es, queryDesc);
	ExplainEndOutput(es);

	append_query_plan(es);
	pfree(es->str->data);

	return;
}

static void
pgsp_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction,
                 uint64 count
#if PG_VERSION_NUM < 180000
				 , bool execute_once
#endif
				)
{
	nest_level++;
	PG_TRY();
	{
		/* These functions return *after* the nested quries do. */
		if (prev_ExecutorRun)
			prev_ExecutorRun(queryDesc, direction, count
#if PG_VERSION_NUM < 180000
					, execute_once);
#else
		);
#endif
		else
			standard_ExecutorRun(queryDesc, direction, count
#if PG_VERSION_NUM < 180000
					, execute_once
#endif
					);

		nest_level--;
		/* Wait for reading to complete, then delete. */
		if (nest_level < 1) { /* Mark hash entry as empty. */
			SpinLockAcquire(&pgsp_cache->mutex);
			pgsp_cache->n_plans = 0;
			SpinLockRelease(&pgsp_cache->mutex);
		}
	}
	PG_CATCH(); /* Since 13 PG_FINALLY() is available. */
	{
		nest_level--;
		/* Wait for reading to complete, then delete. */
		if (nest_level < 1) { /* Mark hash entry as empty. */
			SpinLockAcquire(&pgsp_cache->mutex);
			pgsp_cache->n_plans = 0;
			SpinLockRelease(&pgsp_cache->mutex);
		}

		PG_RE_THROW();
	}
	PG_END_TRY();
}

Datum
pg_show_plans(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	TupleDesc        tupdesc;
	int              call_cntr;
	int              max_calls;
	int              offset;
	int              i;

	pgspCtx         *pgsp_ctx;
	HASH_SEQ_STATUS *hash_seq;
	pgspEntry       *pgsp_tmp_entry;
	int              curr_nest;
	bool             is_done;

	shmem_safety_check();

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;
		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		LWLockAcquire(pgsp->lock, LW_SHARED);
		pgsp_ctx = (pgspCtx *)palloc(sizeof(pgspCtx));
		pgsp_ctx->is_done = true;
		pgsp_ctx->curr_nest = 0;
		pgsp_ctx->hash_seq = (HASH_SEQ_STATUS *)palloc(sizeof(HASH_SEQ_STATUS));
		hash_seq_init(pgsp_ctx->hash_seq, pgsp_hash);
		funcctx->user_fctx = (void *)pgsp_ctx;
		funcctx->max_calls = hash_get_num_entries(pgsp_hash);

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			ereport(ERROR,
			        errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			        errmsg("function returning record called in context "
			               "that cannot accept type record"));
		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();
	/* Restore context. */
	pgsp_ctx = (pgspCtx *)funcctx->user_fctx;
	hash_seq = pgsp_ctx->hash_seq;
	is_done = pgsp_ctx->is_done;
	pgsp_tmp_entry = pgsp_ctx->pgsp_tmp_entry;
	curr_nest = pgsp_ctx->curr_nest;
	/* Pull other stuff from `funcctx`. */
	call_cntr = funcctx->call_cntr;
	max_calls = funcctx->max_calls;
	if (call_cntr < max_calls)
	{
		Datum     values[5];
		bool      nulls[5];
		HeapTuple htup;

		if (is_done) /* Done processing a hash entry? */
		{ /* Grab a new one. */
			pgsp_tmp_entry = hash_seq_search(hash_seq);
			/* Skip empty entries and the ones the user is not
			 * allowed to see. */
			for (;;) {
				if (pgsp_tmp_entry->n_plans >= 1) {
					if (is_allowed_role())
						break;
					else if (pgsp_tmp_entry->user_id == GetUserId())
						break;
				}
				if (call_cntr == max_calls-1) { /* No more entries. */
					hash_seq_term(hash_seq);
					LWLockRelease(pgsp->lock);
					SRF_RETURN_DONE(funcctx);
				}
				pgsp_tmp_entry = hash_seq_search(hash_seq);
				call_cntr++;
			}
			SpinLockAcquire(&pgsp_tmp_entry->mutex);
		}

		/* A single hash entry may store multiple (nested) plans, so
		 * count offset to get the desired plan. */
		offset = 0;
		for (i = 0; i < curr_nest; i++)
			offset += pgsp_tmp_entry->plan_len[i] + 1;

		MemSet(nulls, 0, sizeof(nulls));
		values[0] = Int32GetDatum(pgsp_tmp_entry->hash_key.pid);
		values[1] = Int32GetDatum(curr_nest);
		values[2] = ObjectIdGetDatum(pgsp_tmp_entry->user_id);
		values[3] = ObjectIdGetDatum(pgsp_tmp_entry->db_id);
		values[4] = CStringGetTextDatum(pgsp_tmp_entry->plan + offset);
		htup = heap_form_tuple(funcctx->tuple_desc, values, nulls);

		if (curr_nest < pgsp_tmp_entry->n_plans-1)
		{ /* Still have nested plans. */
			curr_nest++;
			call_cntr--; /* May not be legal, but it works. */
			is_done = false;
		} else { /* No more nested plans, get a new entry. */
			curr_nest = 0;
			is_done = true;
			SpinLockRelease(&pgsp_tmp_entry->mutex);
		}
		/* Save values back to the context. */
		pgsp_ctx->is_done = is_done;
		pgsp_ctx->curr_nest = curr_nest;
		pgsp_ctx->pgsp_tmp_entry = pgsp_tmp_entry;
		funcctx->call_cntr = call_cntr;

		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(htup));
	} else {
		hash_seq_term(hash_seq);
		LWLockRelease(pgsp->lock);
		SRF_RETURN_DONE(funcctx);
	}
}
