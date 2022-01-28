MODNAME		?= khook-demo

obj-m		+= $(MODNAME).o
$(MODNAME)-y	+= main.o

ccflags-y	+= -fno-stack-protector -fomit-frame-pointer -DKBUILD_BUILD_TIMESTAMP='"$(shell date -u)"'
ldflags-y	+= -T$(src)/khook/engine.lds # use LDFLAGS for old kernels

KBUILD_CFLAGS	:= $(filter-out -pg,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out -mfentry,$(KBUILD_CFLAGS))
