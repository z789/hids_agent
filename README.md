
1. cn_proc was introduced from kernel v2.6.14, but may be inefficient in HIDS scenarios 

2. cn_exec send EXEC|CONNECT|SETNS| MMAP(PROT_EXEC) events to userspace. 
   Processes are classified into dockers according to PID namespace and hostname.

3. Kernel version less than 3.15.0, send msg by netlink broadcast, or netlink unicast.

3. Only 64 bit systems are supported

4. test ok:
	ubuntu 20.04: v5.4.0 v5.15.0
	ubuntu 22.04: v5.15.30 v5.15.0
	centos7: 3.10.0
	centos8: 4.18.0
