CC = $(CROSS)$(TARGET)gcc
LINK = $(CROSS)$(TARGET)ld -o
MKDEP = $(CC) -M -o $*.d $<

LIBRARY_LINK_OPTS =  -L. -r
CFLAGS = -O2 -ggdb -std=c99 -D_GNU_SOURCE
CFLAGS += -Wall -Wextra -Wshadow -Wformat-security -Wstrict-prototypes
RM = /bin/rm -f
Q=@

OBJS = log.o tsfuncs.o crc.o misc.o time.o \
	sections.o secdata.o \
	descs.o \
	pat.o pat_desc.o \
	cat.o \
	pmt.o \
	nit.o nit_desc.o \
	sdt.o sdt_desc.o \
	eit.o eit_desc.o \
	tdt.o tdt_desc.o \
	pes.o pes_data.o \
	pes_es.o \
	privsec.o
PROG = libtsfuncs.a

tstest_OBJS = tstest.o libtsfuncs.a
all: $(PROG) tstest

$(PROG): $(OBJS) tsdata.h tsfuncs.h
	$(Q)echo "  LINK	$(PROG)"
	$(Q)$(LINK) $@ $(LIBRARY_LINK_OPTS) $(OBJS)

tstest: $(tstest_OBJS)
	$(Q)echo "  LINK	tstest"
	$(Q)$(CC) $(CFLAGS) $(tstest_OBJS) -o tstest

%.o: %.c tsdata.h tsfuncs.h
	@$(MKDEP)
	$(Q)echo "  CC	libtsfuncs	$<"
	$(Q)$(CC) $(CFLAGS) -c $<

-include $(OBJS:.o=.d)

clean:
	$(Q)echo "  RM	$(PROG) $(OBJS:.o=.{o,d})"
	$(Q)$(RM) $(PROG) tstest $(OBJS:.o=.{o,d}) *~

distclean: clean
