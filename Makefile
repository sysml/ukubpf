UK_ROOT=../../u/staging
ifndef UK_ROOT
$(error Error:UK_ROOT does not exist)
endif
all:
	@make -C $(UK_ROOT) A=$(PWD) L=$(LIBS)

$(MAKECMDGOALS):
	@make -C $(UK_ROOT) A=$(PWD) L=$(LIBS) $(MAKECMDGOALS)
