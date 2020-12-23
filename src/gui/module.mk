MODULE_SRCDIR   := $(SRCDIR)/gui
MODULE_HDRDIR   := $(SRCDIR)/gui
MODULE_INCLPATH := $(SRCDIR)/gui
IUP_HDRDIR      := lib/iup-3.30/include
IUP_INCLPATH    := $(IUP_HDRDIR)

MODULE_SOURCES  := $(wildcard $(MODULE_SRCDIR)/*.c)
MODULE_HEADERS  := $(wildcard $(MODULE_HDRDIR)/*.h)
IUP_HEADERS     := $(wildcard $(IUP_HDRDIR)/*.h)

ifeq ($(UNAME_S),Linux)
    LIBPATH += -Llib/iup-3.30/lib/Linux415_64
endif
LIBS += -liup

OBJECTS_GUI  := $(MODULE_SOURCES:$(MODULE_SRCDIR)/%.c=$(OBJDIR_GUI)/%.o)
SRCDIR_GUI   := $(MODULE_SRCDIR)
DEPS_GUI     := $(MODULE_HEADERS)
INCLPATH_GUI := -I$(MODULE_INCLPATH) -I$(IUP_INCLPATH)
DEPS         += $(IUP_HEADERS)