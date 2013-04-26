#------------------------------------------------------------------
# Makefile - Make rules for ONE-P Sample applications
#
# Copyright (c) 2011-2012 by cisco Systems, Inc.
# All rights reserved.
#------------------------------------------------------------------
TUT_SRC ?= /opt/cisco/onep/c64/sdk-c64-0.7.0.503g/c/tutorials/
include $(TUT_SRC)/Makefile.defs

# Objects file to build
OBJSNETAPP += \
	obj/myfirstapp.o

LD_LIBS += -lonep${ONEP_LBITS}_datapath

# All Target
# To build myfirstapp: "make bin/DatapathTutorial"
all: makedirs bin/myfirstapp 

# Add inputs and outputs from these tool invocations to the build variables 

makedirs:
	@if [ ! -d obj ] ; then mkdir obj ; fi
	@if [ ! -d bin ] ; then mkdir bin ; fi

makeutil:
	${MAKE} -C $(TUT_SRC)/SessionElement all

# Tool invocations
bin/myfirstapp: makedirs makeutil $(OBJSNETAPP)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) -o $@ $(OBJSNETAPP) \
        $(TUT_SRC)/SessionElement/obj/session_element_util.o $(LD_FLAGS) \
			$(LD_LIBDIRS) $(LD_LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) -rf obj bin 
	-@echo ' '

obj/%.o: %.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

.PHONY: all clean dependents
.SECONDARY:

