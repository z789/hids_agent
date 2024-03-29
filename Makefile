
#macro KERN_COMM:     get comm from kernel
#macro KERN_EXE:      get cmdline from kernel space, or get exe from /proc/$(pid)/exe file userspace
#macro KERN_CMDLINE:  get cmdline from kernel space, or get cmdline from /proc/$(pid)/cmdline file userspace
#macro EXEC_CACHE:    cache exec|connect|MMAP events in kernel 
#macro KERN_CRED:     get uid/euid/suid gid/egid/sgid fsuid/fsgid from kernel space

#macro EVENT_CONNECT: get connect event from kernel
#macro EVENT_MMAP:    get mmap event from kernel
#macro EVENT_PID_NS:  get namespaces from kernel
#macro EVENT_KMOD:    loading kernel module info
#macro KERN_HOSTNAME: get hostname from kernel

#CFLAGS += -DKERN_COMM -DKERN_CMDLINE -DKERN_EXE -DKERN_CRED -DEVENT_CONNECT -DEVENT_MMAP -DEXEC_CACHE 
#CFLAGS += -DKERN_CMDLINE -DKERN_EXE -DKERN_CRED -DEVENT_CONNECT -DEVENT_PID_NS -DKERN_HOSTNAME -DEXEC_CACHE 
#CFLAGS += -DKERN_COMM -DKERN_CMDLINE -DKERN_EXE -DKERN_CRED -DEVENT_CONNECT -DEVENT_PID_NS -DEVENT_MMAP -DEVENT_KMOD -DKERN_HOSTNAME -DEXEC_CACHE 
CFLAGS += -DKERN_COMM -DKERN_CMDLINE -DKERN_EXE -DKERN_CRED -DEVENT_CONNECT -DEVENT_SEND -DEVENT_PID_NS -DEVENT_KMOD -DKERN_HOSTNAME -DEXEC_CACHE 
#CFLAGS += -DKERN_CMDLINE -DKERN_EXE -DKERN_CRED  
CFLAGS += -fstack-protector-strong  -Wall 
export CFLAGS

all: 
	./check_file.sh
	cd kmod && make && cd ..
	cd user && make && cd ..

clean:
	cd kmod && make clean && cd ..
	cd user && make clean && cd ..
	-rm include/mount.h
	-rm include/module-internal.h

install:
	sudo mkdir -p /opt/hids
	sudo cp -f kmod/cn_exec.ko /opt/hids/
	sudo cp -f user/ucon_exec /opt/hids/

