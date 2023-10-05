MODNAME		?= khook-demo

include $(src)/Makefile.khook

obj-m		+= $(MODNAME).o
$(MODNAME)-y	+= main.o $(KHOOK_GOALS)

ccflags-y	+= -Werror -fno-stack-protector -fomit-frame-pointer $(KHOOK_CCFLAGS)
ldflags-y	+= $(KHOOK_LDFLAGS)

KBUILD_CFLAGS	:= $(filter-out -pg,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out -mfentry,$(KBUILD_CFLAGS))
