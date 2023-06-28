CFLAGS = -std=c17 -O2 -Wall -Wextra -I./include -fPIC -fstrict-aliasing
CP = cp

Prefix = /usr
Package = hdrbg
Header = ./include/$(Package).h
HeaderDestination = $(Prefix)/include/$(Package).h
Sources = $(wildcard lib/*.c)
Objects = $(Sources:.c=.o)
ifeq ($(OS), Windows_NT)
Library = ./lib/$(Package).dll
LibraryDestination = $(Prefix)/lib/$(Package).dll
LibraryDestinationWindows = $(Prefix)/bin/$(Package).dll
else
Library = ./lib/$(Package).so
LibraryDestination = $(Prefix)/lib/lib$(Package).so
endif

.PHONY: install uninstall

install: uninstall $(Library)
	$(CP) $(Header) $(HeaderDestination)
	$(CP) $(Library) $(LibraryDestination)
	if [ -n "$(LibraryDestinationWindows)" ];  \
	then  \
	    $(CP) $(Library) $(LibraryDestinationWindows);  \
	fi

uninstall:
	$(RM) $(HeaderDestination) $(LibraryDestination) $(LibraryDestinationWindows)

$(Library): $(Objects)
	$(CC) $(CFLAGS) -shared -o $@ $^
