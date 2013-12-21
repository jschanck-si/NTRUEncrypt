# Directories.
TOPDIR = ..
BINDIR = $(TOPDIR)/bin
LIBDIR = $(TOPDIR)/lib
OBJDIR = ./obj
NTRUENCRYPT_DIR = $(TOPDIR)/src
UNAME := $(shell uname)

# Flags.
INCFLAGS = -I$(TOPDIR)/include
CFLAGS   += -Wall -Wno-parentheses -Wshadow -fPIC $(INCFLAGS)

ifeq ($(UNAME), Darwin)
LDFLAGS  += -L$(LIBDIR) -Wl,
else
LDFLAGS  += -L$(LIBDIR) -Wl,-R,$(shell cd $(TOPDIR); pwd)/lib
endif

# Source files.
sampleNTRUEncrypt_srcs  := sample_NTRUEncrypt.c

# Object files.
sampleNTRUEncrypt_objs  := $(addprefix $(OBJDIR)/, $(sampleNTRUEncrypt_srcs:.c=.o))

# Shared library files.
ifeq ($(UNAME), Darwin)
NTRUEncryptlib := $(LIBDIR)/libNTRUEncrypt.dynlib
else
NTRUEncryptlib := $(LIBDIR)/libNTRUEncrypt.so
endif

# Targets.
.PHONY : all
all : sampleNTRUEncrypt

# Directory rules.
$(BINDIR) $(OBJDIR) :
	mkdir -p $@

# Executable rules.
# Ensure BINDIR exists before building excutables in it.
sampleNTRUEncrypt  : $(sampleNTRUEncrypt_objs) $(NTRUEncryptlib) | $(BINDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $^

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
.PHONY: clean clean_sampleNTRUEncrypt
clean : clean_sampleNTRUEncrypt

clean_sampleNTRUEncrypt :
	-rm -rf $(sampleNTRUEncrypt_objs) $(sampleNTRUEncrypt_objs:.o=.d)
	-rm -rf $(BINDIR)/sampleNTRUEncrypt
	$(MAKE) -C $(NTRUENCRYPT_DIR) cleanNTRUEncrypt

install:
