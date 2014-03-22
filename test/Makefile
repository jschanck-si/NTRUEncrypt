# Directories.
TOPDIR = ..
BINDIR = $(TOPDIR)/bin
LIBDIR = $(TOPDIR)/lib
OBJDIR = ./obj
NTRUENCRYPT_DIR = $(TOPDIR)/src
UNAME := $(shell uname)

# Flags.
INCFLAGS = -I$(TOPDIR)/include -I$(NTRUENCRYPT_DIR)
CFLAGS   += -Wall -Wno-parentheses -Wshadow -fPIC $(INCFLAGS)

ifeq ($(UNAME), Darwin)
LDFLAGS  += -L$(LIBDIR) -Wl,
else
LDFLAGS  += -L$(LIBDIR) -Wl,-R,$(shell cd $(TOPDIR); pwd)/lib
endif

# Source files.
sanity_srcs  := sanity.c

# Object files.
sanity_objs  := $(addprefix $(OBJDIR)/, $(sanity_srcs:.c=.o))

# Shared library files.
ifeq ($(UNAME), Darwin)
NTRUEncryptlib := $(LIBDIR)/libNTRUEncrypt.dynlib
else
NTRUEncryptlib := $(LIBDIR)/libNTRUEncrypt.so
endif

# Targets.
.PHONY : all
all : sanity clean_sanity

# Directory rules.
$(BINDIR) $(OBJDIR) :
	mkdir -p $@

# Executable rules.
# Ensure BINDIR exists before building excutables in it.
sanity: $(sanity_objs) $(NTRUEncryptlib) | $(BINDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $^
	-$(BINDIR)/$@

# Shared library rules.
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
	$(CC) -c -MMD $(CFLAGS) $< -o $@
	@$(call EXPAND_DEPENDENCY_FILE, $(@:.o=.d))

# Include dependency files.
# Ignore errors since %.d won't exist the first time.
-include $(all_objs:.o=.d)

# Clean up.
.PHONY: clean clean_sanity
clean : clean_sanity

clean_sanity :
	-rm -rf $(sanity_objs) $(sanity_objs:.o=.d)
	-rm -rf $(BINDIR)/sanity

install:
