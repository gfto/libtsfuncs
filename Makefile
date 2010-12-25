CC = $(CROSS)$(TARGET)gcc
LINK = $(CROSS)$(TARGET)ld -o
LIBRARY_LINK_OPTS =  -L. -r
CFLAGS = -ggdb -D_GNU_SOURCE -Wall -Wextra -Wshadow -Wformat-security -O2
RM = /bin/rm -f
Q=@

OBJS = log.o tsfuncs.o tsfuncs_crc.o tsfuncs_misc.o tsfuncs_time.o \
	tsfuncs_sections.o tsfuncs_section_data.o \
	tsfuncs_descriptors.o \
	tsfuncs_pat.o tsfuncs_pat_desc.o \
	tsfuncs_pmt.o \
	tsfuncs_nit.o tsfuncs_nit_desc.o \
	tsfuncs_sdt.o tsfuncs_sdt_desc.o \
	tsfuncs_eit.o tsfuncs_eit_desc.o \
	tsfuncs_tdt.o \
	tsfuncs_pes.o tsfuncs_pes_data.o \
	tsfuncs_pes_es.o
PROG = libts.a

all: $(PROG)

$(PROG): $(OBJS) tsdata.h
	$(Q)echo "  LINK	$(PROG)"
	$(Q)$(LINK) $@ $(LIBRARY_LINK_OPTS) $(OBJS) 

%.o: %.c
	$(Q)echo "  CC	libts	$<"
	$(Q)$(CC) $(CFLAGS) -c $<

clean:
	$(Q)echo "  RM	$(PROG) $(OBJS)"
	$(Q)$(RM) $(PROG) *.o *~

distclean: clean
