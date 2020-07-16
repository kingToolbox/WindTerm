noinst_PROGRAMS = encode listcap names posix simple sql syntax crnl

libname = $(top_builddir)/libonig.la
LDADD   = $(libname)
INCLUDES  = -I$(top_srcdir) -I$(includedir)

encode_SOURCES  = encode.c
listcap_SOURCES = listcap.c
names_SOURCES   = names.c
posix_SOURCES   = posix.c
simple_SOURCES  = simple.c
sql_SOURCES     = sql.c
syntax_SOURCES  = syntax.c


sampledir = $(top_builddir)/sample

test: encode listcap names posix simple sql syntax
	@$(sampledir)/encode
	@$(sampledir)/listcap
	@$(sampledir)/names
	@$(sampledir)/posix
	@$(sampledir)/simple
	@$(sampledir)/sql
	@$(sampledir)/syntax
