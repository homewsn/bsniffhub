MODULE_SRCDIR   := lib/tinycrypt/source
MODULE_HDRDIR   := lib/tinycrypt/include/tinycrypt
MODULE_INCLPATH := lib/tinycrypt/include

MODULE_SOURCES  := $(wildcard $(MODULE_SRCDIR)/*.c)
MODULE_HEADERS  := $(wildcard $(MODULE_HDRDIR)/*.h)

INCLPATH += -I$(MODULE_INCLPATH)
OBJECTS  += $(MODULE_SOURCES:$(MODULE_SRCDIR)/%.c=$(OBJDIR)/%.o)
VPATH    += $(MODULE_SRCDIR)
DEPS     += $(MODULE_HEADERS)