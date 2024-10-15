
CFLAGS  =  -Wall -O2 -fomit-frame-pointer -Wimplicit-function-declaration
LDFLAGS = -s
LDLIBS  = -lldg -lmbedtls -lmbedx509 -lmbedcrypto -lgem -lz

#
# create manualy ./build/68000/ and ./build/68020/ and ./build/ColdFire/ folder for the targets to be placed.
#

TARGET = mbedtls.ldg

# list header files here
HEADER =

# list C files here
COBJS = main.c

# list assembler files here
SOBJS =

SRCFILES = $(HEADER) $(COBJS) $(SOBJS)

#############################
CROSSPREFIX=/opt/cross-mint/bin/m68k-atari-mint-
PREFIX=/opt/cross-mint
PATH = $(PREFIX)/m68k-atari-mint/bin:$(PREFIX)/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
LD_LIBRARY_PATH=$(PREFIX)/lib:$(PREFIX)/m68k-atari-mint/lib:$LD_LIBRARY_PATH

CC = $(CROSSPREFIX)gcc
AS = $(CC)
AR = $(CROSSPREFIX)ar
RANLIB = $(CROSSPREFIX)ranlib
STRIP = $(CROSSPREFIX)strip
FLAGS = $(CROSSPREFIX)flags
STACK = $(CROSSPREFIX)stack

OBJS = $(COBJS:.c=.o)

all: $(TARGET)
	$(STRIP) ./build/68000/$(TARGET)
	$(STACK) -S 128k ./build/68000/$(TARGET)
	rm -f ./build/68000/*.o
	$(STRIP) ./build/68020/$(TARGET)
	$(STACK) -S 128k ./build/68020/$(TARGET)
	rm -f ./build/68020/*.o
	$(STRIP) ./build/ColdFire/$(TARGET)
	$(STACK) -S 128k ./build/ColdFire/$(TARGET)
	rm -f ./build/ColdFire/*.o
	$(STRIP) ./build/68040/$(TARGET)
	$(STACK) -S 128k ./build/68040/$(TARGET)
	rm -f ./build/68040/*.o
	@echo All done

clean:
	-@rm -f ./build/68000/$(OBJS)
	-@rm -f ./build/68000/$(TARGET)
	-@rm -f ./build/68020/$(OBJS)
	-@rm -f ./build/68020/$(TARGET)
	-@rm -f ./build/ColdFire/$(OBJS)
	-@rm -f ./build/ColdFire/$(TARGET)
	-@rm -f ./build/68040/$(OBJS)
	-@rm -f ./build/68040/$(TARGET)
	@echo Cleaned

new: clean
	-@rm -f $(TARGET)
	$(MAKE) all


.SUFFIXES:
.SUFFIXES: .c .S .o

.c.o:
	$(CC) $(CFLAGS) -m68000 -c $*.c -o ./build/68000/$*.o
	$(CC) $(CFLAGS) -m68020-60 -c $*.c -o ./build/68020/$*.o
	$(CC) $(CFLAGS) -mcpu=5475 -c $*.c -o ./build/ColdFire/$*.o
	$(CC) $(CFLAGS) -m68040 -c $*.c -o ./build/68040/$*.o

$(TARGET): $(OBJS)
	$(CC) ./build/68000/*.o $(CFLAGS) -m68000 $(LDLIBS) -o ./build/68000/$(TARGET)
	$(CC) ./build/68020/*.o $(CFLAGS) -m68020-60 $(LDLIBS) -o ./build/68020/$(TARGET)
	$(CC) ./build/ColdFire/*.o $(CFLAGS) -mcpu=5475 $(LDLIBS) -o ./build/ColdFire/$(TARGET)
	$(CC) ./build/68000/*.o $(CFLAGS) -m68040 $(LDLIBS) -o ./build/68040/$(TARGET)
