ifneq ($(KERNELRELEASE),)
	obj-y := net/can/
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) PROJECT_DIR=$(PWD) modules
modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
endif
.PHONY: clean
clean:
	@find -type f '(' -name '.*.cmd' -o -name '*.ko' -o -name '*.o' -o \
		-name '*.mod.c' -o -name 'modules.order' ')' -delete
	@rm -rf .tmp_versions
	@rm -f Module.symvers
