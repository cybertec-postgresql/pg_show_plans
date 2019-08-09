# pg_show_plans/Makefile

MODULE_big = pg_show_plans
OBJS = pg_show_plans.o

EXTENSION = pg_show_plans
DATA = pg_show_plans--1.0.sql

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_show_plans
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

