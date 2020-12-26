MODULE_SRCDIR   := $(SRCDIR)/gui
MODULE_HDRDIR   := $(SRCDIR)/gui
MODULE_INCLPATH := $(SRCDIR)/gui
IUP_HDRDIR      := /usr/include/iup
IUP_INCLPATH    := $(IUP_HDRDIR)

MODULE_SOURCES  := $(wildcard $(MODULE_SRCDIR)/*.c)
MODULE_HEADERS  := $(wildcard $(MODULE_HDRDIR)/*.h)

LIBS += -liup

OBJECTS_GUI  := $(MODULE_SOURCES:$(MODULE_SRCDIR)/%.c=$(OBJDIR_GUI)/%.o)
SRCDIR_GUI   := $(MODULE_SRCDIR)
DEPS_GUI     := $(MODULE_HEADERS)
INCLPATH_GUI := -I$(MODULE_INCLPATH) -I$(IUP_INCLPATH)
