# Subdirectories.
SUBDIRS := src sample

# Targets.
.PHONY : all $(SUBDIRS)
all : $(SUBDIRS)

# Subdirectory rules.
$(SUBDIRS) :
	$(MAKE) -C $@

# Clean up.
.PHONY : clean
clean :
	for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir clean; done

