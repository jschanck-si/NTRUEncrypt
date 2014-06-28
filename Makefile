# Subdirectories.
SUBDIRS := src sample include 

# Command line

CL_ARGS := DEBUG
DEBUG := no


# Targets.
.PHONY : all $(SUBDIRS)
all : $(SUBDIRS)

# Subdirectory rules.
$(SUBDIRS) :
	$(MAKE) -C $@ $(foreach clarg, $(CL_ARGS), $(clarg):=$($(clarg))) 

check :
	$(MAKE) -C test $(foreach clarg, $(CL_ARGS), $(clarg):=$($(clarg))) 

# Clean up.
.PHONY : clean
clean :
	for dir in $(SUBDIRS) test; do $(MAKE) -C $$dir clean; done

install: all
	for dir in $(SUBDIRS) test; do $(MAKE) -C $$dir install; done
