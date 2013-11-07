#
# Warning: you may need more libraries than are included here on the
# build line.  The agent frequently needs various libraries in order
# to compile pieces of it, but is OS dependent and we can't list all
# the combinations here.  Instead, look at the libraries that were
# used when linking the snmpd master agent and copy those to this
# file.
#

# make file appropriated from 
# http://www.net-snmp.org/wiki/index.php/TUT:Simple_Application

CC=gcc

OBJS1=snmpapp.o
OBJS2=example-demon.o nstAgentSubagentObject.o
OBJS3=asyncapp.o
TARGETS=example-demon snmpapp asyncapp

CFLAGS=-I. `net-snmp-config --cflags` -w
BUILDLIBS=`net-snmp-config --libs`
BUILDAGENTLIBS=`net-snmp-config --agent-libs`

# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared

all: $(TARGETS)

snmpapp: $(OBJS1)
	$(CC) -o snmpapp $(OBJS1) $(BUILDLIBS)

clean:
	rm $(OBJS2) $(OBJS2) $(TARGETS)
