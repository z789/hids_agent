/*
 * ucon_exec.c
 * test app userspace for hook_exec_connect
 */

#include <asm/types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/file.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sched.h>

#include <linux/connector.h>
#include <linux/cn_proc.h>
#include "cn_exec.h"

#define DEBUG
#define NETLINK_CONNECTOR	11
#define MAX_LEN_PROC_PATH         32
#define MAX_LEN_BUFFER         20480
#define MAX_LEN_RECV_BUFFER    20480000
#define PATH_PID_FILENAME      "/var/opt/ucon_exec_pid"

#ifdef DEBUG
#define ulog(f, a...) fprintf(stdout, f, ##a)
#else
#define ulog(f, a...) do {} while (0)
#endif

static int need_exit;
static __u32 seq;

static char g_recv_buf[MAX_LEN_RECV_BUFFER];

static int netlink_send(int s, struct cn_msg *msg)
{
	struct nlmsghdr *nlh;
	unsigned int size;
	int err = -1;
	char buf[128];
	struct cn_msg *m;

	size = NLMSG_SPACE(sizeof(struct cn_msg) + msg->len);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_seq = seq++;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_len = size;
	nlh->nlmsg_flags = 0;

	m = NLMSG_DATA(nlh);
//#if 0
	ulog("%s: [%08x.%08x] len=%u, seq=%u, ack=%u.\n",
	     __func__, msg->id.idx, msg->id.val, msg->len, msg->seq, msg->ack);
//#endif
	memcpy(m, msg, sizeof(*m) + msg->len);

	err = send(s, nlh, size, 0);
	if (err == -1)
		ulog("Failed to send: %s [%d].\n", strerror(errno), errno);

	return err;
}

static void usage(void)
{
	printf("Usage: ucon [options] [output file]\n"
	       "\n"
	       "\t-h\tthis help screen\n"
	       "\t-s\tsend buffers to the cn_exec (default)\n"
	       "\t-d\tdaemon mode. if daemon, must specify [output file] (default no daemon)\n"
	       "\n"
	       "The default behavior of ucon_conn is to subscribe to the cn_exec\n"
	       "and wait for EXEC|CONNECT|MMAP event.  Any ones received are dumped to the\n"
	       "specified output file (or stdout).  The cn_exec is assumed to\n"
	       "have an id of {%u.%u}\n"
	       "\n"
	       "If you get no output, then verify the cn_exec id matches\n"
	       "the expected id above.\n", CN_IDX_EXEC, CN_VAL_EXEC);
}

int get_exe(pid_t pid, char *buf, int buflen)
{
	char path_exe[MAX_LEN_PROC_PATH] = { 0 };
	ssize_t rd = -1;

	snprintf(path_exe, sizeof(path_exe), "/proc/%d/exe", pid);

	rd = readlink(path_exe, buf, buflen - 1);
	if (rd < 0)
		rd = 0;
	buf[rd] = '\0';

	return rd;
}

#ifndef KERN_CMDLINE
static int get_cmdline(pid_t pid, char *buf, int buflen)
{
	char path_cmdline[MAX_LEN_PROC_PATH] = { 0 };
	int len = 0;
	int rd = -1;
	int i = 0;

	snprintf(path_cmdline, sizeof(path_cmdline), "/proc/%d/cmdline", pid);
	rd = open(path_cmdline, O_RDONLY);
	if (rd < 0)
		goto end;
	len = read(rd, buf, buflen);
	close(rd);

	for (i = 0; i < len; i++)
		if (buf[i] == '\0')
			buf[i] = ' ';

 end:
	return len;
}
#endif

#if 0
static char *ns_to_date(unsigned long long ns)
{
	static char date[256] = { 0 };
	struct timespec ts = { 0 };
	struct tm t;

	//ts.tv_sec = ns / 1000000000ULL;
	//ts.tv_nsec = ns % 1000000000ULL;

	//clock_gettime(CLOCK_REALTIME, &ts);
	clock_gettime(CLOCK_MONOTONIC, &ts);

	localtime_r(&ts.tv_sec, &t);
	//t.tm_year += 1900;
	//t.tm_mon += 1;
	strftime(date, sizeof(date), "+%F %T", &t);
	//asctime_r(&t, date);
	//strftime(date, sizeof(date), "+%F %T", localtime_r(&ts.tv_sec, &t));
	//strftime(date, sizeof(date), "%F %T", gmtime_r(&ts.tv_sec, &t));

	return date;
}
#endif

static char *get_date(void)
{
	static char date[256] = { 0 };
	struct timespec ts = { 0 };
	struct tm t;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		goto end;
	strftime(date, sizeof(date), "%F %T", localtime_r(&ts.tv_sec, &t));

end:
	return date;
}

#ifdef EVENT_PID_NS
int snprint_ns(char *out, int len, struct exec_namespace *ns)
{
	if (!out || len <= 0 || !ns)
		return 0;

	return snprintf(out, len, "pidns:%u netns:%u userns:%u utsns:%u mntns:%u ipcns:%u", 
			ns->pid_ns, ns->net_ns, ns->user_ns, ns->uts_ns, ns->mnt_ns, ns->ipc_ns);
}
#endif

static int out_event_exec(FILE * out, struct exec_event *ev)
{
	char *p_cmdline = NULL;
	char *p_exe = NULL;
	char s_cred[128] = { 0 };
	char ns[128] = { 0 };
	int ret = -1;
#ifdef KERN_CMDLINE
	int j = 0;
#else
	char cmdline[MAX_LEN_CMDLINE] = { 0 };
#endif
	char exe[MAX_LEN_CMDLINE] = { 0 };
	char nodename[1] = {0};
	char *p_nodename = nodename;
	char comm[1] = {0};
	char *p_comm = comm;

	if (!ev)
		return ret;

#ifdef KERN_CMDLINE
	for (j = 0; j < ev->event_data.exec.clen && j < MAX_LEN_CMDLINE; j++) {
		if (ev->event_data.exec.cmdline[j] == '\0')
			ev->event_data.exec.cmdline[j] = ' ';
	}
	p_cmdline = ev->event_data.exec.cmdline;
#else
	get_cmdline(ev->event_data.exec.process_pid, cmdline, sizeof(cmdline));
	p_cmdline = cmdline;
#endif

#ifdef KERN_EXE
	p_exe = ev->event_data.exec.exe;
	if (p_exe[0] == '\0') {
		get_exe(ev->event_data.exec.process_pid, exe, sizeof(exe));
		p_exe = exe;
	}
#else
	get_exe(ev->event_data.exec.process_pid, exe, sizeof(exe));
	p_exe = exe;
#endif

#ifdef EVENT_PID_NS
	snprint_ns(ns, sizeof(ns), &ev->event_data.exec.ns);  
#endif

#ifdef KERN_HOSTNAME
	p_nodename = ev->event_data.exec.nodename;
#endif

#ifdef KERN_COMM
	p_comm = ev->event_data.exec.comm;
#endif

#ifdef KERN_CRED
	struct exec_cred *cred = &ev->event_data.exec.cred;
	snprintf(s_cred, sizeof(s_cred), "uid:%d euid:%d suid:%d "
		 "fsuid:%d gid:%d egid:%d sgid:%d fsgid:%d",
		 cred->uid, cred->euid, cred->suid, cred->fsuid,
		 cred->gid, cred->egid, cred->sgid, cred->fsgid);
#endif

	ret = fprintf(out, "%s monclock:%llu : EXEC: node:%s pid:%d tgid:%d ppid:%d ptgid:%d "
		      "cred:%s ns:(%s) comm:%s exe:%s cmdline:%s\n",
		      get_date(),
		      ev->timestamp_ns,
		      p_nodename,
		      //ev->timestamp_ns,
		      ev->event_data.exec.process_pid,
		      ev->event_data.exec.process_tgid,
		      ev->event_data.exec.parent_pid,
		      ev->event_data.exec.parent_tgid, s_cred, ns,
		      p_comm, p_exe, p_cmdline);
	if (ret >= 0)
		ret = 0;
	return ret;
}

#ifdef EVENT_CONNECT
static int out_event_connect(FILE * out, struct exec_event *ev)
{
	int ret = -1;
	pid_t pid = 0;
	pid_t tgid = 0;
	struct sockaddr_in *addr = NULL;
	char *p_exe = NULL;
	char exe[MAX_LEN_CMDLINE] = { 0 };
	//int addrlen = 0;

	char nodename[1] = {0};
	char *p_nodename = nodename;
	char comm[1] = {0};
	char *p_comm = comm;

	if (!ev)
		return ret;

	pid = ev->event_data.connect.process_pid;
	tgid = ev->event_data.connect.process_tgid;
	addr = (struct sockaddr_in *)&(ev->event_data.connect.addr);
	//addrlen = ev->event_data.connect.addrlen;

#ifdef KERN_EXE
	p_exe = ev->event_data.connect.exe;
	if (p_exe[0] == '\0') {
		get_exe(ev->event_data.connect.process_pid, exe, sizeof(exe));
		p_exe = exe;
	}
#else
	get_exe(ev->event_data.connect.process_pid, exe, sizeof(exe));
	p_exe = exe;
#endif

#ifdef KERN_HOSTNAME
	p_nodename = ev->event_data.connect.nodename;
#endif

#ifdef KERN_COMM
	p_comm = ev->event_data.connect.comm;
#endif

	ret = fprintf(out,
		    "%s monclock:%llu : CONNECT: node:%s pid:%d tgid:%d comm:%s exe:%s addr:%s:%d prot:%s\n",
		    get_date(), ev->timestamp_ns, p_nodename, pid, tgid, p_comm, p_exe,
		    inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), ev->event_data.connect.prot_name);

	if (ret >= 0)
		ret = 0;

	return ret;
}
#endif

#ifdef EVENT_PID_NS
static int out_event_pid_ns(FILE * out, struct exec_event *ev)
{
	int ret = -1;
	pid_t pid = 0;
	pid_t tgid = 0;
	char old_ns[128] = { 0 };
	char new_ns[128] = { 0 };
	char *p_exe = NULL;
	char exe[MAX_LEN_CMDLINE] = { 0 };

	char nodename[1] = {0};
	char *p_nodename = nodename;
	char comm[1] = {0};
	char *p_comm = comm;

	if (!ev)
		return ret;

	pid = ev->event_data.setns.process_pid;
	tgid = ev->event_data.setns.process_tgid;
	snprint_ns(old_ns, sizeof(old_ns), &ev->event_data.setns.old);
	snprint_ns(new_ns, sizeof(new_ns), &ev->event_data.setns.new);

#ifdef KERN_EXE
	p_exe = ev->event_data.setns.exe;
	if (p_exe[0] == '\0') {
		get_exe(ev->event_data.setns.process_pid, exe, sizeof(exe));
		p_exe = exe;
	}
#else
	get_exe(ev->event_data.setns.process_pid, exe, sizeof(exe));
	p_exe = exe;
#endif

#ifdef KERN_HOSTNAME
	p_nodename = ev->event_data.setns.nodename;
#endif

#ifdef KERN_COMM
	p_comm = ev->event_data.setns.comm;
#endif

	ret = fprintf(out,
		    "%s monclock:%llu : SETNS: node:%s pid:%d tgid:%d old_ns(%s), new_ns(%s), comm:%s exe:%s\n",
		    get_date(), ev->timestamp_ns, p_nodename, pid, tgid, old_ns, new_ns, p_comm, p_exe);

	if (ret >= 0)
		ret = 0;

	return ret;
}
#endif

#ifdef EVENT_MMAP
static int out_event_mmap(FILE * out, struct exec_event *ev)
{
	int ret = -1;
	pid_t pid = 0;
	pid_t tgid = 0;
	char *path = NULL;

	char nodename[1] = {0};
	char *p_nodename = nodename;
	char comm[1] = {0};
	char *p_comm = comm;

	if (!ev)
		return ret;

	pid = ev->event_data.mmap.process_pid;
	tgid = ev->event_data.mmap.process_tgid;
	path = ev->event_data.mmap.path;

#ifdef KERN_HOSTNAME
	p_nodename = ev->event_data.mmap.nodename;
#endif

#ifdef KERN_COMM
	p_comm = ev->event_data.mmap.comm;
#endif

	ret = fprintf(out, "%s monclock:%llu : MMAP: node:%s pid:%d tgid:%d comm:%s path:%s\n",
		      get_date(), ev->timestamp_ns, p_nodename, pid, tgid, p_comm, path);

	if (ret >= 0)
		ret = 0;

	return ret;
}
#endif

#ifdef EVENT_KMOD
static int out_event_kmod(FILE * out, struct exec_event *ev)
{
	int ret = -1;
	pid_t pid = 0;
	pid_t tgid = 0;
	char nodename[1] = {0};
	char *p_nodename = nodename;
	char *name = NULL;

	if (!ev)
		return ret;

	pid = ev->event_data.kmod.process_pid;
	tgid = ev->event_data.kmod.process_tgid;
	name = ev->event_data.kmod.name;

#ifdef KERN_HOSTNAME
	p_nodename = ev->event_data.kmod.nodename;
#endif
	ret = fprintf(out,
		    "%s monclock:%llu : KMOD: node:%s pid:%d tgid:%d ko_name:%s\n",
		    get_date(), ev->timestamp_ns, p_nodename, pid, tgid, name);

	if (ret >= 0)
		ret = 0;

	return ret;
}
#endif

static int open_netlink(void)
{
	int s = -1;
	//char buf[MAX_LEN_BUFFER];
	struct sockaddr_nl l_local;

	//memset(buf, 0, sizeof(buf));

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (s == -1) {
		perror("socket");
		goto end;
	}

	l_local.nl_family = AF_NETLINK;
	l_local.nl_groups = -1;	/* bitmask of requested groups */
	l_local.nl_pid = getpid();

	ulog("subscribing to %u.%u\n", CN_IDX_EXEC, CN_VAL_EXEC);

	if (bind(s, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) ==
	    -1) {
		perror("bind");
		close(s);
		s = -1;
		goto end;
	}

 end:
	return s;
}

static int set_recv_buf(int sock)
{
	int size = 0;
	int len = sizeof(size);

	if (sock < 0)
		return -1;

	if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, (socklen_t *) & len)
	    == 0) {
		fprintf(stdout, "getsockopt RCVBUF: %d\n", size);
		size *= 128;
		if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, len) == 0) {
			fprintf(stdout, "setsockopt RCVBUF: %d\n", size);
		}
	}
	return 0;
}

static int send_cmd(int sock, enum proc_cn_mcast_op op)
{
	int ret = -1;
	enum proc_cn_mcast_op *mc_op = NULL;
	struct cn_msg *data;
	char buf[MAX_LEN_BUFFER] = { 0 };

	if (sock < 0 ||
	    (op != PROC_CN_MCAST_LISTEN && op != PROC_CN_MCAST_IGNORE))
		return ret;

	memset(buf, 0, sizeof(buf));
	data = (struct cn_msg *)buf;
	data->id.idx = CN_IDX_EXEC;
	data->id.val = CN_VAL_EXEC;
	data->seq = seq++;
	data->ack = 0;
	data->len = sizeof(enum proc_cn_mcast_op);
	mc_op = (enum proc_cn_mcast_op *)data->data;
	*mc_op = op;
	ret = netlink_send(sock, data);
	if (ret < 0)
		ret = -1;
	else
		ret = 0;

	return ret;
}

static int open_lock_pid(const char *fname)
{
	int fd = -1;

	if (!fname)
		goto end;

	fd = open(fname, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG);
	if (fd < 0)
		goto end;

	errno = 0;
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK)
			ulog("lock file %s fail. check the program is running?\n", fname);
		close(fd);
		fd = -1;
	}

 end:
	return fd;
}

static int write_pid(int fd)
{
	char buf[16] = { 0 };

	if (fd < 0)
		goto err;

	snprintf(buf, sizeof(buf), "%d", getpid());
	if (write(fd, buf, sizeof(buf)) != sizeof(buf))
		goto err;

	fsync(fd);
	return 0;

 err:
	return -1;
}

static int set_max_prio(void)
{
	struct sched_param param;
	int max_prio;
	const int policy = SCHED_FIFO;
	int ret = -1;

	errno = 0;
	max_prio = sched_get_priority_max(policy);
	if (max_prio < 0) {
		ulog("sched_get_priority_max failed: errno=%d (%s)\n",
		     errno, strerror(errno));
		goto end;
	}

	memset(&param, 0, sizeof(param));
	param.sched_priority = max_prio;
	if (sched_setscheduler(getpid(), policy, &param) < 0) {
		ulog("sched_setscheduler failed: errno=%d (%s)\n",
		     errno, strerror(errno));
		goto end;
	}
	ret = 0;

 end:
	return ret;
}

static int do_event_none(FILE * out, struct exec_event *ev)
{

	if (!out || !ev)
		return -1;

	switch (ev->event_data.ack.err){ 
	case EPIPE:
		need_exit = 1;
		fprintf(out,
			"cn_exec will be remove from kernel, the app will exit!\n");
		break;
	case ECONNREFUSED:
		need_exit = 1;
		fprintf(out,
			"unicast netlink socket already used by other program!\n");
		break;
	case EINVAL:
		need_exit = 1;
		fprintf(out,
			"multicast netlink send param error!\n");
		break;
	default:
		break;
	}
	return 0;
}

int main_loop(int s, FILE * out)
{
	int ret = -1;
	//char buf[MAX_LEN_BUFFER] = { 0 };
	int len;
	struct nlmsghdr *reply;
	struct cn_msg *data;
	struct exec_event *ev;
	int i = 0;
	int tlen = 0;

	if (s < 0 || out == NULL)
		return ret;

	while (!need_exit) {

		len = recv(s, g_recv_buf, sizeof(g_recv_buf), 0);
		if (len == -1) {
			perror("recv buf");
			goto end;
		}
		reply = (struct nlmsghdr *)g_recv_buf;

		switch (reply->nlmsg_type) {
		case NLMSG_ERROR:
			fprintf(out, "Error message received.\n");
			fflush(out);
			break;
		case NLMSG_DONE:
			i = 0;
			tlen = 0;
			data = (struct cn_msg *)NLMSG_DATA(reply);
			tlen = data->len;
			while (tlen > 0 && tlen >= sizeof(*ev)) {
				ev = (struct exec_event *)(data->data +
							   i * sizeof(*ev));
				switch (ev->what) {
				case PROC_EVENT_EXEC:
					out_event_exec(out, ev);
					break;
#ifdef EVENT_CONNECT
				case PROC_EVENT_CONNECT:
					out_event_connect(out, ev);
					break;
#endif
#ifdef EVENT_PID_NS
				case PROC_EVENT_SETNS:
					out_event_pid_ns(out, ev);
					break;
#endif
#ifdef EVENT_MMAP
				case PROC_EVENT_MMAP:
					out_event_mmap(out, ev);
					break;
#endif
#ifdef EVENT_KMOD
				case PROC_EVENT_KMOD:
					out_event_kmod(out, ev);
					break;
#endif
				case PROC_EVENT_NONE:
					do_event_none(stderr, ev);
					break;
				default:
					break;
				}
				i++;
				tlen -= sizeof(*ev);
			}
			//fflush(out);
			break;
		default:
			break;
		}
	}
	ret = 0;

 end:
	return ret;
}

void do_signal(int sig)
{
	if (sig == SIGTERM)
		need_exit = 1;
}

int main(int argc, char *argv[])
{
	int s = -1;
	FILE *out = NULL;
	bool send_msgs = true;
	int ret = -1;
	int is_daemon = 0;
	int fd_pid = -1;

	while ((s = getopt(argc, argv, "hsd")) != -1) {
		switch (s) {
		case 's':
			send_msgs = true;
			break;
		case 'd':
			is_daemon = 1;
			break;

		case 'h':
			usage();
			return 0;

		default:
			/* getopt() outputs an error for us */
			usage();
			return 1;
		}
	}

	if (argc != optind) {
		out = fopen(argv[optind], "a+");
		if (!out) {
			ulog("Unable to open %s for writing: %s\n",
			     argv[1], strerror(errno));
			out = stdout;
		}
	} else
		out = stdout;

	fd_pid = open_lock_pid(PATH_PID_FILENAME);
	if (fd_pid < 0)
		goto end;

	if (is_daemon == 1) {
		if (out == stdout) {
			ulog("option -d must specify [output file]\n");
			usage();
			goto end;
		}
		if (daemon(0, 0) != 0)
			goto end;
	}

	if (write_pid(fd_pid) < 0)
		goto end;

	if (set_max_prio() < 0)
		ulog("set max_prio fail\n");

	s = open_netlink();
	if (s < 0)
		goto end;

	set_recv_buf(s);

	if (send_msgs && send_cmd(s, PROC_CN_MCAST_LISTEN) < 0)
		goto end;

	//signal(SIGTERM, do_signal);
	main_loop(s, out);

	if (send_msgs)
		send_cmd(s, PROC_CN_MCAST_IGNORE);

	ret = 0;

 end:
	if (out && out != stdout)
		fclose(out);
	if (s != -1)
		close(s);
	if (fd_pid != -1)
		close(fd_pid);

	return ret;
}
