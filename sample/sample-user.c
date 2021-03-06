/*
 * eBPF user space agent part
 *
 * Simple, _self-contained_ user space agent for the eBPF kernel
 * ebpf_prog.c program, which gets all map fds passed from tc via unix
 * domain socket in one transaction and can thus keep referencing
 * them from user space in order to read out (or possibly modify)
 * map data. Here, just as a minimal example to display counters.
 *
 * The agent only uses the bpf(2) syscall API to read or possibly
 * write to eBPF maps, it doesn't need to be aware of the low-level
 * bytecode parts and/or ELF parsing bits.
 *
 * ! For more details, see header comment in bpf_prog.c !
 *
 * gcc bpf_agent.c -o bpf_agent -Wall -O2
 *
 * For example, a more complex user space agent could run on each
 * host, reading and writing into eBPF maps used by tc classifier
 * and actions. It would thus allow for implementing a distributed
 * tc architecture, for example, which would push down central
 * policies into eBPF maps, and thus altering run-time behaviour.
 *
 *   -- Happy eBPF hacking! ;)
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "include/utils.h"
#include "include/bpf_scm.h"
#include "examples/bpf/bpf_shared.h"
#include "examples/bpf/bpf_sys.h"

struct five_tuple {
	unsigned int saddr;
	unsigned int daddr;
	unsigned short sport;
	unsigned short dport;
	unsigned char proto;
} __attribute__ ((packed));

static inline __u64 ptr_to_u64(const void *ptr)
{
		return (__u64) (unsigned long) ptr;
}

static inline int bpf_get_first_key(int fd, void *key, size_t key_size) {
	union bpf_attr attr;
	int i, res;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = 0;
	attr.next_key = ptr_to_u64(key);

	// 4.12 and above kernel supports passing NULL to BPF_MAP_GET_NEXT_KEY
	// to get first key of the map. For older kernels, the call will fail.
	res = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
	if (res < 0 && errno == EFAULT) {
		// Fall back to try to find a non-existing key.
		static unsigned char try_values[3] = {0, 0xff, 0x55};
		attr.key = ptr_to_u64(key);
		for (i = 0; i < 3; i++) {
			memset(key, try_values[i], key_size);
			// We want to check the existence of the key but we don't know the size
			// of map's value. So we pass an invalid pointer for value, expect
			// the call to fail and check if the error is ENOENT indicating the
			// key doesn't exist. If we use NULL for the invalid pointer, it might
			// trigger a page fault in kernel and affect performance. Hence we use
			// ~0 which will fail and return fast.
			// This should fail since we pass an invalid pointer for value.
			if (bpf_lookup_elem(fd, key, (void *)~0) >= 0)
				return -1;
			// This means the key doesn't exist.
			if (errno == ENOENT)
				return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
		}
		return -1;
	} else {
		return res;
	}
}

static inline int bpf_get_next_key(int fd, void *key, void *next_key)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static void bpf_dump_elems(int fd)
{
#if 0
	long proto_array[] = {
		0x0800,
		0x0806,
		0x86DD,
	};
#endif

	struct five_tuple key = {}, next_key;
	int rc = 0;
	while(1) {
		long count = 0;
		int rc = bpf_get_next_key(4, &key, &next_key);
		if (rc) break;
		char saddr[32], daddr[32];
		key = next_key;
		strcpy(saddr, inet_ntoa(*((struct in_addr*)&key.saddr)));
		strcpy(daddr, inet_ntoa(*((struct in_addr*)&key.daddr)));
		bpf_lookup_elem(4, &key, &count);
		printf("\tsaddr %s daddr %s sport %d dport %d proto %x: %5ld\n",
				saddr,
				daddr,
			        key.sport,
			        key.dport,
			        key.proto,	
				count);
	}
}

static void bpf_dump_map_data(int *tfd)
{
	while (1) {
		const int period = 5;

		printf("data, period: %dsec\n", period);

		bpf_dump_elems(tfd[BPF_MAP_ID_DROPS]);

		sleep(period);
	}
}

static void bpf_info_loop(int *fds, struct bpf_map_aux *aux)
{
	int i, tfd[BPF_MAP_ID_MAX];

	printf("ver: %d\nobj: %s\ndev: %lu\nino: %lu\nmaps: %u\n",
	       aux->uds_ver, aux->obj_name, aux->obj_st.st_dev,
	       aux->obj_st.st_ino, aux->num_ent);

	for (i = 0; i < aux->num_ent; i++) {
		printf("map%d:\n", i);
		printf(" `- fd: %u\n", fds[i]);
		printf("  | serial: %u\n", aux->ent[i].id);
		printf("  | type: %u\n", aux->ent[i].type);
		printf("  | max elem: %u\n", aux->ent[i].max_elem);
		printf("  | size key: %u\n", aux->ent[i].size_key);
		printf("  ` size val: %u\n", aux->ent[i].size_value);

		tfd[aux->ent[i].id] = fds[i];
	}

	bpf_dump_map_data(tfd);
}

static void bpf_map_get_from_env(int *tfd)
{
	char key[64], *val;
	int i;

	for (i = 0; i < BPF_MAP_ID_MAX; i++) {
		memset(key, 0, sizeof(key));
		snprintf(key, sizeof(key), "BPF_MAP%d", i);

		val = getenv(key);
		assert(val != NULL);

		tfd[i] = atoi(val);
	}
}

static int bpf_map_set_recv(int fd, int *fds,  struct bpf_map_aux *aux,
			    unsigned int entries)
{
	struct bpf_map_set_msg msg;
	int *cmsg_buf, min_fd, i;
	char *amsg_buf, *mmsg_buf;

	cmsg_buf = bpf_map_set_init(&msg, NULL, 0);
	amsg_buf = (char *)msg.aux.ent;
	mmsg_buf = (char *)&msg.aux;

	for (i = 0; i < entries; i += min_fd) {
		struct cmsghdr *cmsg;
		int ret;

		min_fd = min(BPF_SCM_MAX_FDS * 1U, entries - i);

		bpf_map_set_init_single(&msg, min_fd);

		ret = recvmsg(fd, &msg.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;

		cmsg = CMSG_FIRSTHDR(&msg.hdr);
		if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS)
			return -EINVAL;
		if (msg.hdr.msg_flags & MSG_CTRUNC)
			return -EIO;

		min_fd = (cmsg->cmsg_len - sizeof(*cmsg)) / sizeof(fd);
		if (min_fd > entries || min_fd <= 0)
			return -1;

		memcpy(&fds[i], cmsg_buf, sizeof(fds[0]) * min_fd);
		memcpy(&aux->ent[i], amsg_buf, sizeof(aux->ent[0]) * min_fd);
		memcpy(aux, mmsg_buf, offsetof(struct bpf_map_aux, ent));

		if (i + min_fd == aux->num_ent)
			break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int fds[BPF_SCM_MAX_FDS];
	struct bpf_map_aux aux;
	struct sockaddr_un addr;
	int fd, ret, i;

	/* When arguments are being passed, we take it as a path
	 * to a Unix domain socket, otherwise we grab the fds
	 * from the environment to demonstrate both possibilities.
	 */
	if (argc == 1) {
		int tfd[BPF_MAP_ID_MAX];

		bpf_map_get_from_env(tfd);
		bpf_dump_map_data(tfd);

		return 0;
	}

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot open socket: %s\n",
			strerror(errno));
		exit(1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, argv[argc - 1], sizeof(addr.sun_path));

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		fprintf(stderr, "Cannot bind to socket: %s\n",
			strerror(errno));
		exit(1);
	}

	memset(fds, 0, sizeof(fds));
	memset(&aux, 0, sizeof(aux));

	ret = bpf_map_set_recv(fd, fds, &aux, BPF_SCM_MAX_FDS);
	if (ret >= 0)
		bpf_info_loop(fds, &aux);

	for (i = 0; i < aux.num_ent; i++)
		close(fds[i]);

	close(fd);
	return 0;
}
