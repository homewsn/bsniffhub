#
# Copyright (c) 2020 Vladimir Alemasov
# All rights reserved
#
# This program and the accompanying materials are distributed under 
# the terms of GNU General Public License version 2 
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

TARGET_CLI := bsniffhub
TARGET_GUI := bsniffhubgui
OBJDIR := obj
SRCDIR := src
HDRDIR := src
INCLPATH := -I$(HDRDIR)
LIBPATH :=
SOURCES := $(wildcard $(SRCDIR)/*.c)
HEADERS := $(wildcard $(HDRDIR)/*.h)
OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
VPATH := $(SRCDIR)
UNAME_S := $(shell uname -s)
DEPS := $(HEADERS)
CFLAGS :=
LIBS := -lpthread -lpcap

ifeq ($(UNAME_S),Linux)
    LIBS += -lrt
endif

OBJDIR_CLI := $(OBJDIR)/cli
OBJDIR_GUI := $(OBJDIR)/gui

include src/cli/module.mk
include src/gui/module.mk
include lib/tinycrypt/module.mk

# Create build with libpcap 1.9.1 in usr/local
INCLPATH += -I/usr/local/include
LIBPATH += -L/usr/local/lib

# source directories for $(OBJECTS)
#$(info VPATH is $(VPATH))

# debug version
#CFLAGS += -g
# the highest warning level
#CFLAGS += -Wall -Wextra -pedantic -Wcast-align -Wcast-qual -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wredundant-decls -Wshadow -Wstrict-overflow=5 -Wundef -Wno-unused -Wno-variadic-macros -Wno-parentheses -fdiagnostics-show-option

# Installation directories by convention
# http://www.gnu.org/prep/standards/html_node/Directory-Variables.html
PREFIX ?= /usr/local
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
SYSCONFDIR = $(PREFIX)/etc
LOCALSTATEDIR = $(PREFIX)/var

# main goal
all: $(TARGET_CLI) $(TARGET_GUI)

# target executables
$(TARGET_CLI): $(OBJECTS) $(OBJECTS_CLI)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBPATH) $(LIBS)

$(TARGET_GUI): $(OBJECTS) $(OBJECTS_GUI)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBPATH) $(LIBS)

# object files
$(OBJECTS): $(OBJDIR)/%.o: %.c $(DEPS) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLPATH)

$(OBJECTS_CLI): $(OBJDIR_CLI)/%.o: $(SRCDIR_CLI)/%.c $(DEPS) $(DEPS_CLI) | $(OBJDIR_CLI)
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLPATH) $(INCLPATH_CLI)

$(OBJECTS_GUI): $(OBJDIR_GUI)/%.o: $(SRCDIR_GUI)/%.c $(DEPS) $(DEPS_GUI) | $(OBJDIR_GUI)
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLPATH) $(INCLPATH_GUI)

# create object files directories
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR_CLI):
	mkdir -p $(OBJDIR_CLI)

$(OBJDIR_GUI):
	mkdir -p $(OBJDIR_GUI)

# clean
clean:
	rm -rf $(OBJDIR)

# distclean
distclean: clean
	rm -f $(TARGET_CLI)
	rm -f $(TARGET_GUI)

# install
install: all
	install -d -m 755 "$(BINDIR)"
	install -m 755 $(TARGET_CLI) "$(BINDIR)/"
	install -m 755 $(TARGET_GUI) "$(BINDIR)/"

# uninstall
uninstall:
	rm -f $(BINDIR)/$(TARGET_CLI)
	rm -f $(BINDIR)/$(TARGET_GUI)

.PHONY: all clean distclean install uninstall
