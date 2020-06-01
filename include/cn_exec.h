#ifndef _H_CN_EXEC
#define  _H_CN_EXEC
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/utsname.h>

#define CN_IDX_EXEC (CN_NETLINK_USERS+4)
#define CN_VAL_EXEC 0x100

#define MAX_LEN_EXE_NAME  64
#define MAX_LEN_CMDLINE   256

#ifdef  EVENT_CONNECT
#define PROC_EVENT_CONNECT 0x00000400
#endif

#ifdef  EVENT_MMAP
#define PROC_EVENT_MMAP 0x00000800
#define MAX_LEN_MMAP_PATH 256
#endif

#ifdef  EVENT_PID_NS
#define PROC_EVENT_SETNS 0x00001000
#endif

#ifdef KERN_CRED
struct exec_cred {
	uid_t uid;
	uid_t euid;
	uid_t suid;
	uid_t fsuid;
	gid_t gid;
	gid_t egid;
	gid_t sgid;
	gid_t fsgid;
};
#endif

struct exec_event {
	int what;
	__u32 cpu;
	__u64 seq;

	__u64 __attribute__((aligned(8))) timestamp_ns;
	/* Number of nano seconds since system boot */
	/* must be last field of proc_event struct */
	union {
		struct {
			__u32 err;
		} ack;

		struct __exec_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;

			__kernel_pid_t parent_pid;
			__kernel_pid_t parent_tgid;

#ifdef KERN_COMM
			char comm[16];
#endif

#ifdef KERN_EXE
			char exe[MAX_LEN_EXE_NAME];
#endif
#ifdef KERN_CMDLINE
			int clen;
			char cmdline[MAX_LEN_CMDLINE];
#endif

#ifdef KERN_CRED
			struct exec_cred cred;
#endif
#ifdef EVENT_PID_NS
			unsigned int pid_ns;
#endif

#ifdef KERN_HOSTNAME
			char nodename[__NEW_UTS_LEN+1];
#endif
		} exec;

#ifdef EVENT_CONNECT
		struct __connect_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			struct sockaddr addr;
			int addrlen;
#ifdef KERN_COMM
			char comm[16];
#endif

#ifdef KERN_EXE
			char exe[MAX_LEN_EXE_NAME];
#endif
#ifdef KERN_HOSTNAME
			char nodename[__NEW_UTS_LEN+1];
#endif
		} connect;
#endif

#ifdef EVENT_MMAP
		struct __mmap_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
#ifdef KERN_COMM
			char comm[16];
#endif
			int plen;
			char path[MAX_LEN_MMAP_PATH];
#ifdef KERN_HOSTNAME
			char nodename[__NEW_UTS_LEN+1];
#endif
		} mmap;
#endif

#ifdef EVENT_PID_NS
		struct __setns_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			unsigned int old_pid_ns;
			unsigned int new_pid_ns;
			char comm[16];
#ifdef KERN_EXE
			char exe[MAX_LEN_EXE_NAME];
#endif
		} setns;
#endif

	} event_data;
};
#endif
