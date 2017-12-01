ifneq ($(KERNELRELEASE),)
	ccflags-y += -I$(PROJECT_DIR)/include/uapi
	obj-m := can-j1939.o
	can-j1939-objs := j1939.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
modules:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) modules
modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) modules_install
endif
