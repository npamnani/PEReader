/**
	AUTHOR: nishant_pamnani@yahoo.com
**/
PROGNAME = PEReader

INCLUDES = PEFileStructs.h PEReader.h PEUtils.h
SOURCES = main.cpp PEReader.cpp
OBJS = main.obj PEReader.obj

all:
	@echo "make gcc/sunos/windows"

gcc: $(PROGNAME)_gcc
$(PROGNAME)_gcc: $(INCLUDES) $(SOURCES) Makefile
	g++ -O1 -o $(PROGNAME)_gcc $(SOURCES)

sunos: $(PROGNAME)_sun
$(PROGNAME)_sun: $(INCLUDES) $(SOURCES) Makefile
	CC -O1 -library=stlport4 -o $(PROGNAME)_sun $(SOURCES)
	rm -f main.o PEReader.o

windows: $(PROGNAME).exe
$(PROGNAME).exe: $(INCLUDES) $(SOURCES) Makefile
	cl /c /O1 /Ob1 /EHsc $(SOURCES)
	link /OUT:$(PROGNAME).exe $(OBJS)
	del $(OBJS)
