CC = cc
LINK = ld -o
CROSS := $(TARGET)
MKDEP = $(CROSS)$(CC) -M -o $*.d $<

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
all: $(PROG)

$(PROG): $(OBJS) tsdata.h tsfuncs.h
	$(Q)echo "  LINK	$(PROG)"
	$(Q)$(CROSS)$(LINK) $@ $(LIBRARY_LINK_OPTS) $(OBJS)

tstest: $(tstest_OBJS)
	$(Q)echo "  LINK	tstest"
	$(Q)$(CROSS)$(CC) $(CFLAGS) $(tstest_OBJS) -o tstest

%.o: %.c tsdata.h tsfuncs.h
	@$(MKDEP)
	$(Q)echo "  CC	libtsfuncs	$<"
	$(Q)$(CROSS)$(CC) $(CFLAGS) -c $<

-include $(OBJS:.o=.d)

clean:
	$(Q)echo "  RM	$(PROG) $(OBJS) $(OBJS:.o=.d})"
	$(Q)$(RM) $(PROG) tstest tstest.o tstest.d $(OBJS) $(OBJS:.o=.d) *~

distclean: clean
