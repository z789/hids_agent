EXTRA_CFLAGS += $(CFLAGS) -I$(PWD)/../include  -Wall  -DUSE_FENTRY_OFFSET_0

ifneq ($(KERNELRELEASE),)
        obj-m := cn_exec.o
	cn_exec-y :=  cn_exec_connect.o ftrace_hook.o
else
        KDIR := /lib/modules/`uname -r`/build


all:
	make -C $(KDIR) M=$(PWD) modules
	#./signko.sh

clean:
	rm -rf .*o.cmd .tmp* .cache* *.ko *.o *.mod.o *.mod *.mod.c *.symvers *ko.unsigned *modules.order
endif
