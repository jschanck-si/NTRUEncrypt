# Subdirectories.
SUBDIRS := src sample include

# Targets.
.PHONY : all $(SUBDIRS)
all : $(SUBDIRS)

# Subdirectory rules.
$(SUBDIRS) :
	$(MAKE) -C $@

check :
	$(MAKE) -C test

# Clean up.
.PHONY : clean
clean :
	for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir clean; done

install: all
	for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir install; done
