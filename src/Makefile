# Directories.
TOPDIR = ..
LIBDIR = $(TOPDIR)/lib
OBJDIR = ./obj

# Paths.
vpath %.so $(LIBDIR)

# Flags.
INCFLAGS = -I../include
CFLAGS += -Wall -Wno-parentheses -Wshadow $(INCFLAGS)

# Source files.
NTRUEncrypt_srcs := $(wildcard *.c)

# Object files.
NTRUEncrypt_objs := $(addprefix $(OBJDIR)/, $(NTRUEncrypt_srcs:.c=.o))

# Targets.
.PHONY : all NTRUEncrypt
NTRUEncrypt : libNTRUEncrypt.so

# Directory rules.
$(OBJDIR) $(LIBDIR) :
	mkdir -p $@

# Shared library fules.
# Ensure LIBDIR exists before building shared libraries in it.
libNTRUEncrypt.so : $(NTRUEncrypt_objs) | $(LIBDIR)
	$(CC) -fmessage-length=0 -fpic -shared -Wl,-soname,$@ -o $(LIBDIR)/$@ $^

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
.PHONY : clean cleanNTRUEncrypt
clean : cleanNTRUEncrypt

cleanNTRUEncrypt :
	-rm -rf $(NTRUEncrypt_objs) $(NTRUEncrypt_objs:.o=.d)
	-rm -rf $(LIBDIR)/libNTRUEncrypt.so

