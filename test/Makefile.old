# Directories.
TOPDIR = ..
BINDIR = $(TOPDIR)/bin
LIBDIR = $(TOPDIR)/lib
OBJDIR = ./obj
NTRUENCRYPT_DIR = $(TOPDIR)/src
UNAME := $(shell uname)

# Flags.
ifeq ($(DEBUG), yes)
CFLAGS?=-g
else
CFLAGS?=-O3 -march=native -fomit-frame-pointer
endif

INCFLAGS = -I../include
CFLAGS += -Wall -Wno-parentheses -Wshadow -fPIC $(INCFLAGS)

ifeq ($(UNAME), Darwin)
LDFLAGS  += -L$(LIBDIR) -Wl,
else
LDFLAGS  += -L$(LIBDIR) -Wl,-R,$(shell cd $(TOPDIR); pwd)/lib
endif

tgts:=test_poly_mul sanity

# Source files.
sanity_srcs  := sanity.c
test_poly_mul_srcs  := test_poly_mul.c

# Object files.
sanity_objs  := $(addprefix $(OBJDIR)/, $(sanity_srcs:%.c=%.o))
test_poly_mul_objs  := $(addprefix $(OBJDIR)/, $(test_poly_mul_srcs:%.c=%.o))

# Extra include dirs
test_poly_mul_INCFLAGS = -I$(TOPDIR)/src

# Shared library files.
ifeq ($(UNAME), Darwin)
NTRUEncryptlib := $(LIBDIR)/libNTRUEncrypt.dylib
else
NTRUEncryptlib := $(LIBDIR)/libNTRUEncrypt.so
endif

# Targets.
.PHONY : all
all : $(tgts) 
# all : $(tgts) $(patsubst %, clean_%, $(tgts)) -- not sure why we always clean?

# Directory rules.
$(BINDIR) $(OBJDIR) :
	mkdir -p $@

# Executable rules.
# Ensure BINDIR exists before building excutables in it.
.SECONDEXPANSION:
$(tgts): $$($$@_objs) $$(NTRUEncryptlib) | $$(BINDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $^
	-$(BINDIR)/$@

# Shared library rules.
.PHONY : $(NTRUEncryptlib)
$(NTRUEncryptlib) :
	$(MAKE) -C $(NTRUENCRYPT_DIR) NTRUEncrypt

# Object file rules.
# In a dependency file (%.d), this macro appends a line with each
# prerequisite as a target itself with no prerequisites so that if the
# prerequisite is ever no longer a prerequisite, the build will still complete.
EXPAND_DEPENDENCY_FILE =                                            \
	sed -e 's/.*://' -e 's/\\$$//' < $(1) | fmt -1 | \
            sed -e 's/^ *//' -e 's/$$/:/' > $(1).tmp;               \
	(echo; cat $(1).tmp) >> $(1);                                   \
	rm -f $(1).tmp

# Explicit rule to build objects outside the current directory.
# Ensure OBJDIR exists before building objects and dependency files in it.
# Note: -MMD creates %.o and %.d simultaneously, omitting system headers.
$(OBJDIR)/%.o : %.c | $(OBJDIR)
	$(CC) -c -MMD $(CFLAGS) $($*_INCFLAGS) $< -o $@
	@$(call EXPAND_DEPENDENCY_FILE, $(@:.o=.d))

# Include dependency files.
# Ignore errors since %.d won't exist the first time.
-include $(all_objs:.o=.d)

# Clean up.
.PHONY: clean $(tgts:%=clean_%)
clean : $(tgts:%=clean_%)

$(tgts:%=clean_%):
	-rm -rf $($(@:clean_%=%)_objs) $($(@:clean_%=%)_objs:.o=.d)
	-rm -rf $(BINDIR)/$(@:clean_%=%)

install:
