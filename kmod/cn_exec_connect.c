#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/timer.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/fs_struct.h>
#include <linux/sched/mm.h>
#include <linux/mutex.h>
#include <linux/binfmts.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/user_namespace.h>
#include <linux/utsname.h>
#include <linux/rcupdate.h>
#include <mount.h>
#include <cn_exec.h>
#include <ftrace_hook.h>
#include <module-internal.h>

#ifdef USE_FENTRY_OFFSET_0
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#define CN_EXEC_MSG_SIZE (sizeof(struct cn_msg) + sizeof(struct exec_event) + 4)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
static atomic_t exec_event_num_listeners = ATOMIC_INIT(0);
#else
static atomic64_t portid_pid = ATOMIC64_INIT(0);
#endif

struct cb_id cn_exec_id = { CN_IDX_EXEC, CN_VAL_EXEC };

static char cn_exec_name[] = "cn_exec";
static atomic64_t seq_exec_event = ATOMIC64_INIT(0);
/* seq_msg is used as the sequence number of the netlink message */
static DEFINE_PER_CPU(__u32, seq_msg) = {
	0
};

static asmlinkage int (*p_access_process_vm)(struct task_struct * tsk,
					     unsigned long addr,
					     void *buf, int len,
					     unsigned int gup_flags) = NULL;

static struct file *(*p_get_task_exe_file)(struct task_struct *task) = NULL;

struct cn_dev *p_cdev = NULL;

#ifdef  EXEC_CACHE
#define MAX_EXEC_EVENT 1024
#define DEFAULT_EXEC_EVENT ((MAX_EXEC_EVENT)/2)

#define MAX_TIME_FLUSH_CACHE 180000
#define DEFAULT_TIME_FLUSH_CACHE 500

#define BUFFER_SIZE (sizeof(struct cn_msg) + sizeof(struct exec_event)*(MAX_EXEC_EVENT) + 4)

static struct event_cache_t {
	int cnt;
	char __attribute__((aligned(8))) buf[BUFFER_SIZE];
} *event_cache = NULL;

static DEFINE_MUTEX(event_cache_mutex);

static int g_num_cache_ev = 128;
MODULE_PARM_DESC(g_num_cache_ev,
		 "number of cache event. range:[1, 256], default 128");
static int g_num_cache_ev_set(const char *, const struct kernel_param *);
static struct kernel_param_ops g_num_cache_ev_param_ops = {
	.set = g_num_cache_ev_set,
	.get = param_get_int,
};

module_param_cb(g_num_cache_ev, &g_num_cache_ev_param_ops, &g_num_cache_ev,
		0644);

static struct timer_list cn_exec_timer;

static int g_time_flush_cache = DEFAULT_TIME_FLUSH_CACHE;
//module_param_named(g_time_flush_cache, g_time_flush_cache, int, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(g_time_flush_cache,
		 "time of flush cache. Unit: millisecond. range:[1, 180000], default 500");

static int g_time_flush_cache_set(const char *, const struct kernel_param *);
static struct kernel_param_ops g_time_flush_cache_param_ops = {
	.set = g_time_flush_cache_set,
	.get = param_get_int,
};

module_param_cb(g_time_flush_cache, &g_time_flush_cache_param_ops,
		&g_time_flush_cache, 0644);

static int g_num_cache_ev_set(const char *val, const struct kernel_param *kp)
{
	long v;
	int ret;

	ret = kstrtol(val, 0, &v);
	if (ret)
		return ret;
	if (v < 1 || v > MAX_EXEC_EVENT)
		v = DEFAULT_EXEC_EVENT;

	g_num_cache_ev = v;
	return 0;
}

static int g_time_flush_cache_set(const char *val,
				  const struct kernel_param *kp)
{
	long v;
	int ret;

	ret = kstrtol(val, 0, &v);
	if (ret)
		return ret;
	if (v < 1 || v > MAX_TIME_FLUSH_CACHE)
		v = DEFAULT_TIME_FLUSH_CACHE;

	g_time_flush_cache = v;
	return 0;
}

static inline struct exec_event *get_exec_event(struct event_cache_t *cache)
{
	if (!cache)
		return NULL;
	if (cache->cnt < g_num_cache_ev && g_num_cache_ev <= MAX_EXEC_EVENT)
		return (struct exec_event *)(cache->buf +
					     sizeof(struct cn_msg) + 4 +
					     sizeof(struct exec_event) *
					     cache->cnt);
	else
		return NULL;
}
#endif				//EXEC_CACHE

static inline struct cn_msg *buffer_to_cn_msg(__u8 * buffer)
{
	BUILD_BUG_ON(sizeof(struct cn_msg) != 20);
	return (struct cn_msg *)(buffer + 4);
}

static inline void __send_msg(struct cn_msg *msg)
{
	int ret = 0;

	preempt_disable();
	msg->seq = __this_cpu_inc_return(seq_msg) - 1;
	//((struct exec_event *)msg->data)->cpu = smp_processor_id();

	/*
	 * Preemption remains disabled during send to ensure the messages are
	 * ordered according to their sequence numbers.
	 *
	 * If cn_netlink_send() fails, the data is not sent.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	ret = cn_netlink_send(msg, CN_IDX_EXEC, GFP_NOWAIT);
	if (ret == -ESRCH && netlink_has_listeners(p_cdev->nls, CN_IDX_EXEC) == 0) {
		atomic_set(&exec_event_num_listeners, 0);
		pr_debug("No listen process\n");
	}
#else
	ret = cn_netlink_send(msg, atomic64_read(&portid_pid), 0, GFP_NOWAIT);
	if ((ret == -ESRCH || ret == -ECONNREFUSED) && netlink_has_listeners(p_cdev->nls, CN_IDX_EXEC) == 0) {
		pr_debug("Send msg to %lld fail.  no listen process\n", atomic64_read(&portid_pid));
		atomic64_set(&portid_pid, 0);
		//pr_debug("No listen process\n");
	}
#endif
	preempt_enable();
}

static inline void send_msg(struct cn_msg *msg)
{
	preempt_disable();
	((struct exec_event *)msg->data)->cpu = smp_processor_id();
	__send_msg(msg);
	preempt_enable();
}

static void cn_exec_ack(int err, int rcvd_seq, int rcvd_ack)
{
	struct cn_msg *msg;
	struct exec_event *ev;
	__u8 buffer[CN_EXEC_MSG_SIZE] __aligned(8);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	if (atomic_read(&exec_event_num_listeners) < 1)
		return;
#else
	if (atomic64_read(&portid_pid) < 1)
		return;
#endif

	msg = buffer_to_cn_msg(buffer);
	ev = (struct exec_event *)msg->data;
	memset(&ev->event_data, 0, sizeof(ev->event_data));
	msg->seq = rcvd_seq;
	ev->timestamp_ns = ktime_get_ns();
	ev->cpu = -1;
	ev->what = PROC_EVENT_NONE;
	ev->event_data.ack.err = err;
	memcpy(&msg->id, &cn_exec_id, sizeof(msg->id));
	msg->ack = rcvd_ack + 1;
	msg->len = sizeof(*ev);
	msg->flags = 0;		/* not used */
	send_msg(msg);
}

/**
 * cn_proc_mcast_ctl
 * @data: message sent from userspace via the connector
 */
static void cn_exec_mcast_ctl(struct cn_msg *msg, struct netlink_skb_parms *nsp)
{
	enum proc_cn_mcast_op *mc_op = NULL;
	int err = 0;

	if (msg->len != sizeof(*mc_op))
		return;

	/*
	 * Events are reported with respect to the initial pid
	 * and user namespaces so ignore requestors from
	 * other namespaces.
	 */
	if ((current_user_ns() != &init_user_ns) ||
	    (task_active_pid_ns(current) != &init_pid_ns))
		return;

	/* Can only change if privileged. */
	if (!__netlink_ns_capable(nsp, &init_user_ns, CAP_NET_ADMIN)) {
		err = EPERM;
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	mc_op = (enum proc_cn_mcast_op *)msg->data;
	switch (*mc_op) {
	case PROC_CN_MCAST_LISTEN:
		atomic_inc(&exec_event_num_listeners);
		break;
	case PROC_CN_MCAST_IGNORE:
		atomic_dec(&exec_event_num_listeners);
		break;
	default:
		err = EINVAL;
		break;
	}
#else
	if (atomic64_read(&portid_pid) == 0 || netlink_has_listeners(p_cdev->nls, CN_IDX_EXEC) == 1){
		atomic64_set(&portid_pid, nsp->portid);
		pr_debug("Process %lld listen\n", atomic64_read(&portid_pid));
	}
	return;
#endif
 out:
	cn_exec_ack(err, msg->seq, msg->ack);
}

/*
 No export the func <kallsyms_lookup_name> from v5.7.1
*/
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 1)
unsigned long find_kallsyms_addr(const char *name)
{
	return kallsyms_lookup_name(name);
}
#else

#ifdef CONFIG_KGDB_KDB
/* Symbol table format returned by kallsyms. */
typedef struct __ksymtab {
	unsigned long value;    /* Address of symbol */
	const char *mod_name;   /* Module containing symbol or
				 * "kernel" */
	unsigned long mod_start;
	unsigned long mod_end;
	const char *sec_name;   /* Section containing symbol */
	unsigned long sec_start;
	unsigned long sec_end;
	const char *sym_name;   /* Full symbol name, including
				 * any version */
	unsigned long sym_start;
	unsigned long sym_end;
} kdb_symtab_t;

int kdbgetsymval(const char *symname, kdb_symtab_t *symtab);
#endif

struct kprobe kp;

static int __kprobes pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static void __kprobes post_handler(struct kprobe *p, struct pt_regs *regs,
                                unsigned long flags)
{
	return;
}

unsigned long find_kallsyms_addr(const char *name)
{
#ifdef CONFIG_KGDB_KDB
        kdb_symtab_t symtab; 
#endif
        unsigned long addr = 0;
        if (!name)
                goto end;

#ifdef CONFIG_KGDB_KDB
        if (kdbgetsymval(name, &symtab)) {
                addr = symtab.sym_start;
	} else {
#endif
		addr = (unsigned long )__symbol_get(name);
		if (addr <= 0) {
			kp.symbol_name = name;
			kp.offset = 0;
			kp.addr = 0;
			kp.pre_handler = pre_handler;
			kp.post_handler = post_handler;
			if (register_kprobe(&kp) == 0) {
				addr = (unsigned long) kp.addr;
				unregister_kprobe(&kp);
			}
			addr = (unsigned long) kp.addr;
		}
#ifdef CONFIG_KGDB_KDB
	}
#endif 
end:
        return addr;

}
#endif

#ifdef KERN_EXE
static int get_task_exe(char *buf, int buflen, struct task_struct *task)
{
	int ret = -1;
	struct file *exe_file = NULL;
	char *p = NULL;
	char *pathname = kmalloc(PATH_MAX+11, GFP_KERNEL);
	
	if (!buf || buflen <= 0 || !task || !pathname)
		goto end;

	exe_file = p_get_task_exe_file(task);
	if (exe_file) {
		p = d_path(&(exe_file->f_path), pathname, PATH_MAX+11);
		fput(exe_file);

		if (IS_ERR_OR_NULL(p)) {
			buf[0] = '\0';
		} else {
			ret = strlen(p);
			if (ret > buflen)
				ret = buflen;
			memcpy(buf, p, ret);
			buf[ret] = '\0';
		}
	}

end:
	if (pathname)
		kfree(pathname);
	return ret;
}
#endif

#ifdef KERN_CMDLINE
static int get_task_cmdline(char *buffer, int buflen, struct task_struct *task)
{
	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);
	unsigned long arg_start, arg_end, env_start, env_end;

	if (!mm)
		goto out;
	if (!mm->arg_end)
		goto out_mm;


#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,2,1)
	down_read(&mm->mmap_sem);
#else
	spin_lock(&mm->arg_lock);
#endif
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	env_start = mm->env_start;
	env_end = mm->env_end;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,2,1)
	up_read(&mm->mmap_sem);
#else
	spin_unlock(&mm->arg_lock);
#endif

	len = arg_end - arg_start;

	if (len > buflen)
		len = buflen;

	res = p_access_process_vm(task, arg_start, buffer, len, FOLL_FORCE);

	/*
	 * If the nul at the end of args has been overwritten, then
	 * assume application is using setproctitle(3).
	 */
	if (res > 0 && buffer[res - 1] != '\0' && len < buflen) {
		len = strnlen(buffer, res);
		if (len < res) {
			res = len;
		} else {
			len = env_end - env_start;
			if (len > buflen - res)
				len = buflen - res;
			res += p_access_process_vm(task, env_start,
						   buffer + res, len,
						   FOLL_FORCE);
			res = strnlen(buffer, res);
		}
	}
 out_mm:
	mmput(mm);
 out:
	return res;
}
#endif

#ifdef KERN_CRED
static inline void get_kernel_cred(struct exec_cred *c,
				   struct task_struct *task)
{
	const struct cred *cred;

	if (!c || !task)
		return;

	cred = __task_cred(task);
	c->uid = from_kuid_munged(&init_user_ns, cred->uid);
	c->euid = from_kuid_munged(&init_user_ns, cred->euid);
	c->suid = from_kuid_munged(&init_user_ns, cred->suid);
	c->fsuid = from_kuid_munged(&init_user_ns, cred->fsuid);
	c->gid = from_kgid_munged(&init_user_ns, cred->gid);
	c->egid = from_kgid_munged(&init_user_ns, cred->egid);
	c->sgid = from_kgid_munged(&init_user_ns, cred->sgid);
	c->fsgid = from_kgid_munged(&init_user_ns, cred->fsgid);

	return;
}
#endif

#ifdef EVENT_PID_NS
static inline int assign_ns(struct exec_namespace *exec_ns, struct nsproxy *ns)
{
	if (!exec_ns || !ns)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	exec_ns->net_ns = ns->net_ns->proc_inum;
	exec_ns->uts_ns = ns->uts_ns->proc_inum;
	exec_ns->ipc_ns = ns->ipc_ns->proc_inum;
	exec_ns->mnt_ns = ns->mnt_ns->proc_inum;
	exec_ns->user_ns = ns->mnt_ns->user_ns->proc_inum;
#else
	exec_ns->net_ns = ns->net_ns->ns.inum;
	exec_ns->uts_ns = ns->uts_ns->ns.inum;
	exec_ns->ipc_ns = ns->ipc_ns->ns.inum;
	exec_ns->mnt_ns = ns->mnt_ns->ns.inum;
	exec_ns->user_ns = ns->mnt_ns->user_ns->ns.inum;
#endif

	return 0;
}

static inline unsigned int get_task_ns(struct exec_namespace *ns, struct task_struct *task)
{
	struct pid_namespace *pid_ns = NULL;
	int ret = -1;

	if (!ns || !task)
		goto end;

	rcu_read_lock();
	pid_ns = task_active_pid_ns(task);
	if (pid_ns)
		get_pid_ns(pid_ns);
	rcu_read_unlock();
	if (!pid_ns)
		goto end;

	task_lock(task);
	assign_ns(ns, task->nsproxy);
	task_unlock(task);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	ns->pid_ns = pid_ns->proc_inum;
#else
	ns->pid_ns = pid_ns->ns.inum;
#endif
	put_pid_ns(pid_ns);
	ret = 0;

end:
	return ret;
}
#endif

#ifdef KERN_HOSTNAME
static inline void get_kernel_nodename(char *buffer, int buflen)
{
	char tmp[__NEW_UTS_LEN + 1] = {0};
	int len = 0;

	if (!buffer || buflen < 1)
		return;
	
	//down_read(&uts_sem);
	memcpy(tmp, utsname()->nodename, sizeof(tmp));
	//up_read(&uts_sem);

	len = strlen(tmp);
	if (len > buflen-1)
		len = buflen; 
	memcpy(buffer, tmp, len);
	buffer[len] = '\0';

	return;
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
#ifdef EVENT_CONNECT
static asmlinkage int (*real_ss_connect)(struct pt_regs * regs) = NULL;
static asmlinkage int fh_ss_connect(struct pt_regs *regs)
{
	return real_ss_connect(regs);
}
#endif

#ifdef EVENT_MMAP
static asmlinkage int (*real_security_mmap_file)(struct pt_regs * regs) = NULL;
static asmlinkage int fh_security_mmap_file(struct pt_regs *regs)
{
	return real_security_mmap_file(regs);
}
#endif

#ifdef EVENT_KMOD
static asmlinkage struct module* (*real_layout_and_allocate)(struct pt_regs *regs) = NULL;
static asmlinkage struct module* (*fh_layout_and_allocate)(struct pt_regs *regs)
{
	return real_layout_and_allocate(regs);
}
#endif

#ifdef EVENT_PID_NS
static asmlinkage void (*real_switch_task_namespaces)(
				struct task_struct *tsk, struct nsproxy *new) = NULL;
static asmlinkage void fh_switch_task_namespaces(
				struct task_struct *tsk, struct nsproxy *new)
{
	return real_switch_task_namespaces(tsk, new);
}
#endif

static asmlinkage int (*real_proc_exec_connector)(struct pt_regs * regs);
static asmlinkage int fh_proc_exec_connector(struct pt_regs *regs)
{
	return real_proc_exec_connector(regs);
}

#else				//PTREGS_SYSCALL_STUBS

#ifdef EVENT_CONNECT
static asmlinkage int (*real_ss_connect)(struct socket *,
					 struct sockaddr * address,
					 int addrlen) = NULL;
static asmlinkage int fh_ss_connect(struct socket *sock,
				    struct sockaddr *address, int addrlen)
{
	int ret;
	//struct sockaddr_in *addr = (struct sockaddr_in *) address;
	struct cn_msg *msg;
	struct exec_event *ev;
	struct task_struct *task = current;
#ifndef EXEC_CACHE
	__u8 buffer[CN_EXEC_MSG_SIZE] __aligned(8);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	if (atomic_read(&exec_event_num_listeners) < 1)
		goto real_connect;
#else
	if (atomic64_read(&portid_pid) < 1)
		goto real_connect;
#endif

	if (address->sa_family != AF_INET && address->sa_family != AF_INET6)
		goto real_connect;
	/*
	   may be filter 127.0.0.1 
	 */

#ifdef EXEC_CACHE
	mutex_lock(&event_cache_mutex);
	msg = buffer_to_cn_msg(event_cache->buf);
	ev = get_exec_event(event_cache);
	if (!ev)
		goto events_send;
#else
	msg = buffer_to_cn_msg(buffer);
	ev = (struct exec_event *)msg->data;
#endif

	memset(&ev->event_data, 0, sizeof(ev->event_data));
	ev->timestamp_ns = ktime_get_ns();
	ev->what = PROC_EVENT_CONNECT;
	ev->event_data.connect.process_pid = current->pid;
	ev->event_data.connect.process_tgid = current->tgid;
	memcpy(&(ev->event_data.connect.addr), address, addrlen);
	ev->event_data.connect.addrlen = addrlen;
	strlcpy(ev->event_data.connect.prot_name, sock->sk->sk_prot->name, sizeof(ev->event_data.connect.prot_name));

#ifdef KERN_COMM
	get_task_comm(ev->event_data.connect.comm, task);
#endif

#ifdef KERN_EXE
	get_task_exe(ev->event_data.connect.exe,
		     sizeof(ev->event_data.connect.exe) - 1, task);
#endif

#ifdef KERN_HOSTNAME
	get_kernel_nodename(ev->event_data.connect.nodename, sizeof(ev->event_data.connect.nodename));
#endif

	ev->seq = atomic64_inc_return(&seq_exec_event);
	preempt_disable();
	ev->cpu = smp_processor_id();
	preempt_enable();

#ifdef EXEC_CACHE
	if (++(event_cache->cnt) < g_num_cache_ev)
		goto end;
 events_send:
#endif
	memcpy(&msg->id, &cn_exec_id, sizeof(msg->id));
	msg->ack = 0;		/* not used */
	msg->flags = 0;		/* not used */
#ifdef EXEC_CACHE
	msg->len = sizeof(*ev) * event_cache->cnt;
	__send_msg(msg);
	event_cache->cnt = 0;
 end:
	mutex_unlock(&event_cache_mutex);
#else
	msg->len = sizeof(*ev);
	send_msg(msg);
#endif

 real_connect:
	ret = real_ss_connect(sock, address, addrlen);

	return ret;
}
#endif

#ifdef EVENT_MMAP
static int get_so_path(struct file *file, char *buf, int blen)
{
	char *p = NULL;
	int len = -1;
	char *pathname = kmalloc(PATH_MAX+11, GFP_KERNEL);

	if (!file || !buf || blen <= 0 || !pathname)
		goto end;

	get_file(file);
	p = d_path(&file->f_path, pathname, PATH_MAX+11);
	fput(file);
	if (IS_ERR_OR_NULL(p)) {
		buf[0] = '\0';
	} else {
		len = strlen(p);
		if (len > blen)
			len = blen;
		memcpy(buf, p, len);
		buf[len] = '\0';
	}

end:
	if (pathname)
		kfree(pathname);
	return len;
}

static asmlinkage int (*real_security_mmap_file)(struct file * file,
						 unsigned long prot,
						 unsigned long flags) = NULL;

static asmlinkage int fh_security_mmap_file(struct file *file,
					    unsigned long prot,
					    unsigned long flags)
{
	int ret;
	struct cn_msg *msg;
	struct exec_event *ev;
#ifndef EXEC_CACHE
	__u8 buffer[CN_EXEC_MSG_SIZE] __aligned(8);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	if (atomic_read(&exec_event_num_listeners) < 1)
		goto real_mmap_file;
#else
	if (atomic64_read(&portid_pid) < 1)
		goto real_mmap_file;
#endif

	if (!file || !(prot & PROT_EXEC))
		goto real_mmap_file;

#ifdef EXEC_CACHE
	mutex_lock(&event_cache_mutex);
	msg = buffer_to_cn_msg(event_cache->buf);
	ev = get_exec_event(event_cache);
	if (!ev)
		goto events_send;
#else
	msg = buffer_to_cn_msg(buffer);
	ev = (struct exec_event *)msg->data;
#endif

	memset(&ev->event_data, 0, sizeof(ev->event_data));
	ev->timestamp_ns = ktime_get_ns();
	ev->what = PROC_EVENT_MMAP;
	ev->event_data.mmap.process_pid = current->pid;
	ev->event_data.mmap.process_tgid = current->tgid;
	ev->event_data.mmap.plen = get_so_path(file, ev->event_data.mmap.path,
					       sizeof(ev->event_data.mmap.
						      path) - 1);
#ifdef KERN_COMM
	get_task_comm(ev->event_data.mmap.comm, current);
#endif

#ifdef KERN_HOSTNAME
	get_kernel_nodename(ev->event_data.mmap.nodename, sizeof(ev->event_data.mmap.nodename));
#endif

	ev->seq = atomic64_inc_return(&seq_exec_event);
	preempt_disable();
	ev->cpu = smp_processor_id();
	preempt_enable();

#ifdef EXEC_CACHE
	if (++(event_cache->cnt) < g_num_cache_ev)
		goto end;
 events_send:
#endif
	memcpy(&msg->id, &cn_exec_id, sizeof(msg->id));
	msg->ack = 0;		/* not used */
	msg->flags = 0;		/* not used */
#ifdef EXEC_CACHE
	msg->len = sizeof(*ev) * event_cache->cnt;
	__send_msg(msg);
	event_cache->cnt = 0;
 end:
	mutex_unlock(&event_cache_mutex);
#else
	msg->len = sizeof(*ev);
	send_msg(msg);
#endif

 real_mmap_file:
	ret = real_security_mmap_file(file, prot, flags);

	return ret;
}
#endif

#ifdef EVENT_PID_NS
static inline int fill_ns(struct __setns_event *setns, struct nsproxy *new, struct task_struct *task)
{
	struct nsproxy *ns = NULL;
	struct pid_namespace *pid_ns = NULL;
	int ret = -1;

	if (!setns || !task)
		goto end;

	rcu_read_lock();
	pid_ns = task_active_pid_ns(task);
	if (pid_ns)
		get_pid_ns(pid_ns);
	rcu_read_unlock();
	if (!pid_ns)
		goto end;

	task_lock(task);
	ns = task->nsproxy;
	assign_ns(&setns->old, ns);
	assign_ns(&setns->new, new);
	task_unlock(task);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	setns->old.pid_ns = pid_ns->proc_inum;
	setns->new.pid_ns = new->pid_ns->proc_inum;
#else
	setns->old.pid_ns = pid_ns->ns.inum;
	setns->new.pid_ns = new->pid_ns_for_children->ns.inum;
#endif
	ret = 0;

end:    
	if (pid_ns)
		put_pid_ns(pid_ns);

	return ret;
}

static asmlinkage void (*real_switch_task_namespaces)(
				struct task_struct *task, struct nsproxy *new) = NULL;
static asmlinkage void fh_switch_task_namespaces(
				struct task_struct *task, struct nsproxy *new)
{
	struct cn_msg *msg = NULL;
	struct exec_event *ev = NULL;
#ifndef EXEC_CACHE
	__u8 buffer[CN_EXEC_MSG_SIZE] __aligned(8);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	if (atomic_read(&exec_event_num_listeners) < 1)
		goto  real_switch_ns;
#else
	if (atomic64_read(&portid_pid) < 1)
		goto  real_switch_ns;
#endif
	if (!task || !new)
		goto  real_switch_ns;

#ifdef EXEC_CACHE
	mutex_lock(&event_cache_mutex);
	msg = buffer_to_cn_msg(event_cache->buf);
	ev = get_exec_event(event_cache);
	if (!ev)
		goto events_send;
#else
	msg = buffer_to_cn_msg(buffer);
	ev = (struct exec_event *)msg->data;
#endif

	memset(&ev->event_data, 0, sizeof(ev->event_data));
	ev->timestamp_ns = ktime_get_ns();
	ev->what = PROC_EVENT_SETNS;
	ev->event_data.setns.process_pid = task->pid;
	ev->event_data.setns.process_tgid = task->tgid;
	
	if (fill_ns(&ev->event_data.setns, new, task) < 0)
		goto  real_switch_ns;

#ifdef KERN_COMM
	get_task_comm(ev->event_data.setns.comm, task);
#endif

#ifdef KERN_EXE
	get_task_exe(ev->event_data.setns.exe,
		     sizeof(ev->event_data.setns.exe) - 1, task);
#endif

#ifdef KERN_HOSTNAME
	get_kernel_nodename(ev->event_data.setns.nodename, sizeof(ev->event_data.setns.nodename));
#endif

	ev->seq = atomic64_inc_return(&seq_exec_event);
	preempt_disable();
	ev->cpu = smp_processor_id();
	preempt_enable();

#ifdef EXEC_CACHE
	if (++(event_cache->cnt) < g_num_cache_ev)
		goto end;
 events_send:
#endif
	memcpy(&msg->id, &cn_exec_id, sizeof(msg->id));
	msg->ack = 0;		/* not used */
	msg->flags = 0;		/* not used */
#ifdef EXEC_CACHE
	msg->len = sizeof(*ev) * event_cache->cnt;
	__send_msg(msg);
	event_cache->cnt = 0;
 end:
	mutex_unlock(&event_cache_mutex);
#else
	msg->len = sizeof(*ev);
	send_msg(msg);
#endif

real_switch_ns:
	return real_switch_task_namespaces(task, new);
}
#endif

static asmlinkage int (*real_proc_exec_connector)(struct task_struct * tsk) =
    NULL;
static asmlinkage int fh_proc_exec_connector(struct task_struct *tsk)
{
	struct cn_msg *msg;
	struct exec_event *ev = NULL;
	struct task_struct *task = current;
	struct task_struct *parent = NULL;
#ifndef EXEC_CACHE
	__u8 buffer[CN_EXEC_MSG_SIZE] __aligned(8);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	if (atomic_read(&exec_event_num_listeners) < 1)
		goto real_proc_exec_connector;
#else
	if (atomic64_read(&portid_pid) < 1)
		goto real_proc_exec_connector;
#endif

#ifdef EXEC_CACHE
	mutex_lock(&event_cache_mutex);
	msg = buffer_to_cn_msg(event_cache->buf);
	ev = get_exec_event(event_cache);
	if (!ev)
		goto events_send;
#else
	msg = buffer_to_cn_msg(buffer);
	ev = (struct exec_event *)msg->data;
#endif

	memset(&ev->event_data, 0, sizeof(ev->event_data));
	ev->timestamp_ns = ktime_get_ns();
	ev->what = PROC_EVENT_EXEC;
	ev->event_data.exec.process_pid = task->pid;
	ev->event_data.exec.process_tgid = task->tgid;

	rcu_read_lock();
	parent = rcu_dereference(task->real_parent);
	ev->event_data.exec.parent_pid = parent->pid;
	ev->event_data.exec.parent_tgid = parent->tgid;
	rcu_read_unlock();

#ifdef KERN_COMM
	get_task_comm(ev->event_data.exec.comm, task);
#endif

#ifdef KERN_EXE
	get_task_exe(ev->event_data.exec.exe,
		     sizeof(ev->event_data.exec.exe) - 1, task);
#endif

#ifdef KERN_CMDLINE
	ev->event_data.exec.clen =
	    get_task_cmdline(ev->event_data.exec.cmdline,
			     sizeof(ev->event_data.exec.cmdline) - 1, task);
#endif

#ifdef KERN_CRED
	get_kernel_cred(&ev->event_data.exec.cred, task);
#endif

#ifdef EVENT_PID_NS
	get_task_ns(&ev->event_data.exec.ns, task);
#endif

#ifdef KERN_HOSTNAME
	get_kernel_nodename(ev->event_data.exec.nodename, sizeof(ev->event_data.exec.nodename));
#endif

	ev->seq = atomic64_inc_return(&seq_exec_event);
	preempt_disable();
	ev->cpu = smp_processor_id();
	preempt_enable();

#ifdef EXEC_CACHE
	if (++(event_cache->cnt) < g_num_cache_ev)
		goto end;
 events_send:
#endif
	memcpy(&msg->id, &cn_exec_id, sizeof(msg->id));
	msg->ack = 0;		/* not used */
	msg->flags = 0;		/* not used */
#ifdef EXEC_CACHE
	msg->len = sizeof(*ev) * event_cache->cnt;
	__send_msg(msg);
	event_cache->cnt = 0;
 end:
	mutex_unlock(&event_cache_mutex);
#else
	msg->len = sizeof(*ev);
	send_msg(msg);
#endif

 real_proc_exec_connector:
	return real_proc_exec_connector(tsk);
}

#ifdef EVENT_KMOD
static asmlinkage struct module* (*real_layout_and_allocate)(struct load_info *info, int flags) = NULL;
static asmlinkage struct module* fh_layout_and_allocate(struct load_info *info, int flags)
{
	struct cn_msg *msg;
	struct exec_event *ev;
#ifndef EXEC_CACHE
	__u8 buffer[CN_EXEC_MSG_SIZE] __aligned(8);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	if (atomic_read(&exec_event_num_listeners) < 1)
		goto real_layout_and_allocate;
#else
	if (atomic64_read(&portid_pid) < 1)
		goto real_layout_and_allocate;
#endif

#ifdef EXEC_CACHE
	mutex_lock(&event_cache_mutex);
	msg = buffer_to_cn_msg(event_cache->buf);
	ev = get_exec_event(event_cache);
	if (!ev)
		goto events_send;
#else
	msg = buffer_to_cn_msg(buffer);
	ev = (struct exec_event *)msg->data;
#endif

	memset(&ev->event_data, 0, sizeof(ev->event_data));
	ev->timestamp_ns = ktime_get_ns();
	ev->what = PROC_EVENT_KMOD;
	ev->event_data.kmod.process_pid = current->pid;
	ev->event_data.kmod.process_tgid = current->tgid;
	strlcpy(ev->event_data.kmod.name, info->name, sizeof(ev->event_data.kmod.name));

#ifdef KERN_HOSTNAME
	get_kernel_nodename(ev->event_data.kmod.nodename, sizeof(ev->event_data.kmod.nodename));
#endif
	ev->seq = atomic64_inc_return(&seq_exec_event);
	preempt_disable();
	ev->cpu = smp_processor_id();
	preempt_enable();

#ifdef EXEC_CACHE
	if (++(event_cache->cnt) < g_num_cache_ev)
		goto end;
 events_send:
#endif
	memcpy(&msg->id, &cn_exec_id, sizeof(msg->id));
	msg->ack = 0;		/* not used */
	msg->flags = 0;		/* not used */
#ifdef EXEC_CACHE
	msg->len = sizeof(*ev) * event_cache->cnt;
	__send_msg(msg);
	event_cache->cnt = 0;
 end:
	mutex_unlock(&event_cache_mutex);
#else
	msg->len = sizeof(*ev);
	send_msg(msg);
#endif
real_layout_and_allocate:
	return real_layout_and_allocate(info, flags);
}
#endif
#endif				// PTREGS_SYSCALL_STUBS

#ifdef EXEC_CACHE
static void cn_exec_timer_func(struct timer_list *unused)
{
	struct cn_msg *msg = NULL;

	if (mutex_trylock(&event_cache_mutex)) {
		if (event_cache->cnt > 0) {
			msg = buffer_to_cn_msg(event_cache->buf);
			memcpy(&msg->id, &cn_exec_id, sizeof(msg->id));
			msg->ack = 0;	/* not used */
			msg->len = sizeof(struct exec_event) * event_cache->cnt;
			msg->flags = 0;	/* not used */
			__send_msg(msg);
			event_cache->cnt = 0;
		}
		mutex_unlock(&event_cache_mutex);
	}

	mod_timer(&cn_exec_timer,
		  jiffies + msecs_to_jiffies(g_time_flush_cache));
}
#endif

static struct ftrace_hook hooks[] = {
#ifdef EVENT_CONNECT
	HOOK("security_socket_connect", fh_ss_connect, &real_ss_connect),
#endif
#ifdef EVENT_MMAP
	HOOK("security_mmap_file", fh_security_mmap_file,
	     &real_security_mmap_file),
#endif
	HOOK("proc_exec_connector", fh_proc_exec_connector,
	     &real_proc_exec_connector),

#ifdef EVENT_PID_NS
	HOOK("switch_task_namespaces", fh_switch_task_namespaces,
	     &real_switch_task_namespaces),
#endif

#ifdef EVENT_KMOD
	HOOK("layout_and_allocate", fh_layout_and_allocate, &real_layout_and_allocate),
#endif
};

static int fh_init(void)
{
	int err = -1;

	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (err)
		pr_debug("install hooks fail\n");
	else
		pr_debug("install hooks succ\n");

	return err;
}

static void fh_exit(void)
{
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	pr_debug("remove hoos succ\n");
	return;
}

static int cn_exec_init(void)
{
	int err = -1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	p_access_process_vm = access_process_vm;
#else
	p_access_process_vm = (int (*)(struct task_struct *, unsigned long addr,
				       void *, int, unsigned int))
	    find_kallsyms_addr("access_process_vm");

#endif
	if (!p_access_process_vm) {
		pr_debug("not find symbol 'access_process_vm'");
		goto err_out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 1)
	p_get_task_exe_file = get_task_exe_file;
#else
	p_get_task_exe_file = (struct file* (*)(struct task_struct *task))
		find_kallsyms_addr("get_task_exe_file");
#endif
	if (!p_get_task_exe_file) {
		pr_debug("not find symbol 'get_task_exe_file'");
		goto err_out;
	}

	p_cdev = (struct cn_dev *)find_kallsyms_addr("cdev");
	if (!p_cdev) {
		pr_debug("not find symbol 'cdev'");
		goto err_out;
	}

#ifdef EXEC_CACHE
	event_cache = kmalloc(sizeof(struct event_cache_t), GFP_KERNEL);
	if (!event_cache)
		goto err_out;
	event_cache->cnt = 0;
#endif

	err = cn_add_callback(&cn_exec_id, cn_exec_name, cn_exec_mcast_ctl);
	if (err)
		goto err_out;

	if (fh_init() < 0)
		goto err_fh_init;

	pr_info("initialized with id={%u.%u}\n",
		cn_exec_id.idx, cn_exec_id.val);

#ifdef EXEC_CACHE
	timer_setup(&cn_exec_timer, cn_exec_timer_func, 0);
	mod_timer(&cn_exec_timer,
		  jiffies + msecs_to_jiffies(g_time_flush_cache));
#endif

	return 0;

 err_fh_init:
	cn_del_callback(&cn_exec_id);

 err_out:
#ifdef EXEC_CACHE
	if (event_cache)
		kfree(event_cache);
#endif
	return err;
}

static void cn_exec_fini(void)
{
	//notify userspace when the module will be remove for kernel
	cn_exec_ack(EPIPE, atomic64_inc_return(&seq_exec_event), -1);
#ifdef EXEC_CACHE
	del_timer_sync(&cn_exec_timer);
#endif
	fh_exit();
	cn_del_callback(&cn_exec_id);
#ifdef EXEC_CACHE
	if (event_cache)
		kfree(event_cache);
#endif
	pr_info("cn_exec id={%u.%u} removed\n", cn_exec_id.idx, cn_exec_id.val);
}

module_init(cn_exec_init);
module_exit(cn_exec_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chenfc");
MODULE_DESCRIPTION("Connector's exec module");
