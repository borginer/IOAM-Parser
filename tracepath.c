/*
 * tracepath.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#define _GNU_SOURCE

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdbool.h>

/*
 * Keep linux/ includes after standard headers.
 * https://github.com/iputils/iputils/issues/168
 */
#include <linux/errqueue.h>
#include <linux/icmp.h>
//#include <linux/icmpv6.h>
#include <linux/types.h>

#include "iputils_common.h"

#ifdef USE_IDN
# define getnameinfo_flags	NI_IDN
#else
# define getnameinfo_flags	0
#endif
#define RAW_LOG_FILENAME "tracepath_ioam_raw.log"

#define RAWLOG(fmt, ...) do { \
    if (ctl->raw_output) { \
        fprintf(ctl->raw_output, fmt, ##__VA_ARGS__); \
        fflush(ctl->raw_output); \
    } \
} while (0)
#define MAX_IOAM_HOPS 8

enum {
	MAX_PROBES = 10,

	MAX_HOPS_DEFAULT = 30,
	MAX_HOPS_LIMIT = 255,

	HOST_COLUMN_SIZE = 52,

	HIS_ARRAY_SIZE = 64,

	DEFAULT_OVERHEAD_IPV4 = 28,
	DEFAULT_OVERHEAD_IPV6 = 48,

	DEFAULT_MTU_IPV4 = 65535,
	DEFAULT_MTU_IPV6 = 128000,

	DEFAULT_BASEPORT = 44444,

	ANCILLARY_DATA_LEN = 512,
};

struct hhistory {
	int hops;
	struct timespec sendtime;
};

struct probehdr {
	uint32_t ttl;
	struct timespec ts;
};
struct ioam_values {
    uint8_t node_id;
    uint8_t hoplim;  
    uint32_t timestamp;
    uint32_t timestamp_frac;
    float latency_ms;
    uint32_t queue_depth;
    uint16_t ingress_if_short; 
    uint16_t egress_if_short;   
    uint32_t ingress_if_wide;   
    uint32_t egress_if_wide;    
    uint32_t namespace_specific; 
    uint32_t checksum_comp;
};
struct run_state {
	struct hhistory his[HIS_ARRAY_SIZE];
	int hisptr;
	struct sockaddr_storage target;
	struct addrinfo *ai;
	int socket_fd;
	socklen_t targetlen;
	uint16_t base_port;
	uint8_t ttl;
	int max_hops;
	int overhead;
	int mtu;
	void *pktbuf;
	int hops_to;
	int hops_from;
	int icmp6_fd; // raw ICMPv6 socket
	FILE *raw_output;
	struct ioam_values hops[MAX_IOAM_HOPS];
    int count;
    uint32_t trace_type;
	unsigned int
		no_resolve:1,
		show_both:1,
		mapped:1;
};


int recv_icmp6_raw(struct run_state *ctl);
ssize_t receive_raw_packet(int sock_fd, uint8_t *buf, size_t bufsize, struct sockaddr_in6 *addr, socklen_t *addrlen);
void log_raw_packet(struct run_state *ctl, const uint8_t *buf, ssize_t len);
bool is_icmpv6_error(const struct icmp6_hdr *icmp);
void log_icmpv6_header(struct run_state *ctl, const struct icmp6_hdr *icmp);
bool has_valid_embedded_header(const struct ip6_hdr *embedded, const uint8_t *buf_start, ssize_t len);
uint8_t *get_hbh_end(const uint8_t *ptr);
void log_hbh_header_length(struct run_state *ctl, const uint8_t *ptr);
void parse_ioam_option(struct run_state *ctl, uint8_t *opt_ptr, uint8_t opt_len);
void parse_hbh_options(struct run_state *ctl, uint8_t *ptr, uint8_t *end, uint8_t *buf_end);
void print_ioam_hop(struct run_state *ctl,int hop, const char *addr, uint32_t trace_type, struct ioam_values *v);
void print_ioam_hops_for_ttl(struct run_state *ctl);
/* Field bitmask and size definitions (24-bit trace_type) */
struct ioam_field {
    uint32_t bit;
    const char *name;
    size_t size;
};
static const struct ioam_field IOAM_FIELDS[] = {
    { 0x800000, "Node ID",           2 },
    { 0x400000, "Ingress IF",        2 },
    { 0x200000, "Egress IF",         2 },
    { 0x100000, "Timestamp Secs",    4 },
    { 0x080000, "Timestamp Nanos",   4 },
    { 0x040000, "Transit Delay",     4 },
    { 0x020000, "Hop Latency",       4 },
    { 0x010000, "Queue Depth",       2 },
    { 0x008000, "Ingress TS",        4 },
    { 0x004000, "Egress TS",         4 },
    { 0x002000, "Queue Occupancy",   2 },
    { 0x001000, "Congestion Level",  1 },
    { 0x000002, "App Data",          4 },
};
/*
 * All includes, definitions, struct declarations, and global variables are
 * above.  After this comment all you can find is functions.
 */

static void data_wait(struct run_state const *const ctl)
{
	fd_set fds;
	struct timeval tv = {
		.tv_sec = 1,
		.tv_usec = 0
	};

	FD_ZERO(&fds);
	FD_SET(ctl->socket_fd, &fds);
	select(ctl->socket_fd + 1, &fds, NULL, NULL, &tv);
}

static void print_host(struct run_state const *const ctl, char const *const a,
		       char const *const b)
{
	int plen;

	plen = printf("%s", a);
	if (ctl->show_both)
		plen += printf(" (%s)", b);
	if (plen >= HOST_COLUMN_SIZE)
		plen = HOST_COLUMN_SIZE - 1;
	printf("%*s", HOST_COLUMN_SIZE - plen, "");
}

static int recverr(struct run_state *const ctl)
{
	ssize_t recv_size;
	struct probehdr rcvbuf;
	char cbuf[ANCILLARY_DATA_LEN];
	struct cmsghdr *cmsg;
	struct sock_extended_err *e;
	struct sockaddr_storage addr;
	struct timespec ts;
	struct timespec *retts;
	int slot = 0;
	int rethops;
	int sndhops;
	int progress = -1;
	int broken_router;
	char hnamebuf[NI_MAXHOST] = "";
	struct iovec iov = {
		.iov_base = &rcvbuf,
		.iov_len = sizeof(rcvbuf)
	};
	struct msghdr msg;
	const struct msghdr reset = {
		.msg_name = (uint8_t *)&addr,
		.msg_namelen = sizeof(addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
		0
	};

 restart:
	memset(&rcvbuf, -1, sizeof(rcvbuf));
	msg = reset;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	recv_size = recvmsg(ctl->socket_fd, &msg, MSG_ERRQUEUE);
	if (recv_size < 0) {
		if (errno == EAGAIN)
			return progress;
		goto restart;
	}

	progress = ctl->mtu;

	rethops = -1;
	sndhops = -1;
	e = NULL;
	retts = NULL;
	broken_router = 0;

	slot = -ctl->base_port;
	switch (ctl->ai->ai_family) {
	case AF_INET6:
		slot += ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
		break;
	case AF_INET:
		slot += ntohs(((struct sockaddr_in *)&addr)->sin_port);
		break;
	}
	if (slot >= 0 && slot < (HIS_ARRAY_SIZE - 1) && ctl->his[slot].hops) {
		sndhops = ctl->his[slot].hops;
		retts = &ctl->his[slot].sendtime;
		ctl->his[slot].hops = 0;
	}
	if (recv_size == sizeof(rcvbuf)) {
		if (rcvbuf.ttl == 0 || (rcvbuf.ts.tv_sec == 0 && rcvbuf.ts.tv_nsec == 0))
			broken_router = 1;
		else {
			sndhops = rcvbuf.ttl;
			retts = &rcvbuf.ts;
		}
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		switch (cmsg->cmsg_level) {
		case SOL_IPV6:
			//printf("SOL_IPV6\n");
			switch (cmsg->cmsg_level) {
			case IPV6_RECVERR:
				//printf("IPV6_RECVERR\n");

				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
				break;
			case IPV6_HOPLIMIT:
			//printf("IPV6_HOPLIMIT\n");

	#ifdef IPV6_2292HOPLIMIT
			case IPV6_2292HOPLIMIT:
			//printf("IPV6_2292HOPLIMIT\n");

	#endif
				memcpy(&rethops, CMSG_DATA(cmsg), sizeof(rethops));
				break;
			default: {
				unsigned char *data = (unsigned char *)CMSG_DATA(cmsg);
				size_t len = cmsg->cmsg_len - CMSG_LEN(0);
	
				//printf("cmsg6:%d, data length: %zu, first bytes: ", cmsg->cmsg_type, len);
				for (size_t i = 0; i < len && i < 8; ++i) {
					//printf("0x%02x ", data[i]);
				}
				//printf("\n");
				uint8_t *data_start = (uint8_t *)CMSG_DATA(cmsg);
				size_t data_len = cmsg->cmsg_len - CMSG_LEN(0);
			
				if (data_len < sizeof(struct sock_extended_err)) {
					//printf("CMSG too short to contain sock_extended_err\n");
					break;
				}
			
				e = (struct sock_extended_err *)data_start;
				uint8_t *embedded = data_start + sizeof(struct sock_extended_err);
				size_t embedded_len = data_len - sizeof(struct sock_extended_err);
			
				//printf(">>> Embedded ICMP payload (%zu bytes):\n", embedded_len);
				for (size_t i = 0; i < embedded_len && i < 64; i++) {
					//printf("0x%02x ", embedded[i]);
					if (i % 8 == 7) printf("\n");
				}
				//printf("\n");
				if (len > 0 && data[0] == 0x0e) {
					//printf(">> IOAM Option Detected (0x0E) \n");
				}
				break;
			}
			}
			break;
	
		case SOL_IP:
			switch (cmsg->cmsg_type) {
			case IP_RECVERR:
				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
				//printf("IP_RECVERR\n");
				break;
			case IP_TTL:
				rethops = *(uint8_t *)CMSG_DATA(cmsg);
				printf("TTL\n");
				break;
			default: {
				unsigned char *data = (unsigned char *)CMSG_DATA(cmsg);
				size_t len = cmsg->cmsg_len - CMSG_LEN(0);
	
				//printf("cmsg4:%d, data length: %zu, first bytes: ", cmsg->cmsg_type, len);
				for (size_t i = 0; i < len && i < 8; ++i) {
					//printf("0x%02x ", data[i]);
				}
				//printf("\n");
				break;
			}
			}
		}
	}
	if (e == NULL) {
		printf(_("no info\n"));
		return 0;
	}
	if (e->ee_origin == SO_EE_ORIGIN_LOCAL)
		printf("%2d?: %-32s ", ctl->ttl, _("[LOCALHOST]"));
	else if (e->ee_origin == SO_EE_ORIGIN_ICMP6 ||
		 e->ee_origin == SO_EE_ORIGIN_ICMP) {
		char abuf[NI_MAXHOST];
		struct sockaddr *sa = (struct sockaddr *)(e + 1);
		socklen_t salen;

		if (sndhops > 0)
			printf("%2d:  ", sndhops);
		else
			printf("%2d?: ", ctl->ttl);

		switch (sa->sa_family) {
		case AF_INET6:
			salen = sizeof(struct sockaddr_in6);
			break;
		case AF_INET:
			salen = sizeof(struct sockaddr_in);
			break;
		default:
			salen = 0;
		}

		if (ctl->no_resolve || ctl->show_both) {
			if (getnameinfo(sa, salen, abuf, sizeof(abuf), NULL, 0,
					NI_NUMERICHOST))
				strcpy(abuf, "???");
		} else
			abuf[0] = 0;

		if (!ctl->no_resolve || ctl->show_both) {
			fflush(stdout);
			if (getnameinfo(sa, salen, hnamebuf, sizeof hnamebuf, NULL, 0,
					getnameinfo_flags))
				strcpy(hnamebuf, "???");
		} else
			hnamebuf[0] = 0;

		if (ctl->no_resolve)
			print_host(ctl, abuf, hnamebuf);
		else
			print_host(ctl, hnamebuf, abuf);
	}

	if (retts) {
		struct timespec res;

		timespecsub(&ts, retts, &res);
		printf(_("%3lld.%03ldms "), (long long int)res.tv_sec * 1000
			   + res.tv_nsec / 1000000, (res.tv_nsec % 1000000) / 1000);

		if (broken_router)
			printf(_("(This broken router returned corrupted payload) "));
	}

	if (rethops <= 64)
		rethops = 65 - rethops;
	else if (rethops <= 128)
		rethops = 129 - rethops;
	else
		rethops = 256 - rethops;

	switch (e->ee_errno) {
	case ETIMEDOUT:
		printf("\n");
		break;
	case EMSGSIZE:
		printf(_("pmtu %d\n"), e->ee_info);
		ctl->mtu = e->ee_info;
		progress = ctl->mtu;
		break;
	case ECONNREFUSED:
		printf(_("reached\n"));
		ctl->hops_to = sndhops < 0 ? ctl->ttl : sndhops;
		ctl->hops_from = rethops;
		return 0;
	case EPROTO:
		printf("!P\n");
		return 0;
	case EHOSTUNREACH:
		if ((e->ee_origin == SO_EE_ORIGIN_ICMP &&
		     e->ee_type == ICMP_TIME_EXCEEDED &&
		     e->ee_code == ICMP_EXC_TTL) ||
		    (e->ee_origin == SO_EE_ORIGIN_ICMP6 &&
				e->ee_type == ICMP6_TIME_EXCEEDED &&
				e->ee_code == ICMP6_TIME_EXCEED_TRANSIT)) {
			if (rethops >= 0) {
				if ((sndhops >= 0 && rethops != sndhops) ||
					(sndhops < 0 && rethops != ctl->ttl))
					printf(_("asymm %2d "), rethops);
			}
			printf("\n");
			print_ioam_hops_for_ttl(ctl);
			break;
		}
		printf("!H\n");
		return 0;
	case ENETUNREACH:
		printf("!N\n");
		return 0;
	case EACCES:
		printf("!A\n");
		return 0;
	default:
		printf("\n");
		error(0, e->ee_errno, _("NET ERROR"));
		return 0;
	}
	goto restart;
}

static int probe_ttl(struct run_state *const ctl)
{
	int i;
	struct probehdr *hdr = ctl->pktbuf;

	memset(ctl->pktbuf, 0, ctl->mtu);
 restart:
	for (i = 0; i < MAX_PROBES; i++) {
		int res;

		hdr->ttl = ctl->ttl;
		switch (ctl->ai->ai_family) {
		case AF_INET6:
			((struct sockaddr_in6 *)&ctl->target)->sin6_port =
			    htons(ctl->base_port + ctl->hisptr);
			break;
		case AF_INET:
			((struct sockaddr_in *)&ctl->target)->sin_port =
			    htons(ctl->base_port + ctl->hisptr);
			break;
		}
		clock_gettime(CLOCK_MONOTONIC, &hdr->ts);
		ctl->his[ctl->hisptr].hops = ctl->ttl;
		ctl->his[ctl->hisptr].sendtime = hdr->ts;
		//TEST IOAM SUPPORT
		if (sendto(ctl->socket_fd, ctl->pktbuf, ctl->mtu - ctl->overhead, 0,
           (struct sockaddr *)&ctl->target, ctl->targetlen) > 0)
		{
			if (ctl->icmp6_fd > 0) {
				int ret_raw = recv_icmp6_raw(ctl);
				if (ret_raw == 0) {
					// IOAM HBH successfully parsed
				}
			}
			break;
		}
		res = recverr(ctl);

		ctl->his[ctl->hisptr].hops = 0;
		if (res == 0)
			return 0;
		if (res > 0)
			goto restart;
		

	}
	ctl->hisptr = (ctl->hisptr + 1) & (HIS_ARRAY_SIZE - 1);

	if (i < MAX_PROBES) {
		data_wait(ctl);
		if (recv(ctl->socket_fd, ctl->pktbuf, ctl->mtu, MSG_DONTWAIT) > 0) {
			printf(_("%2d?: reply received 8)\n"), ctl->ttl);
			return 0;
		}
		return recverr(ctl);
	}

	printf(_("%2d:  send failed\n"), ctl->ttl);
	return 0;
}

static void usage(void)
{
	fprintf(stderr, _(
		"\nUsage\n"
		"  tracepath [options] <destination>\n"
		"\nOptions:\n"
		"  -4             use IPv4\n"
		"  -6             use IPv6\n"
		"  -b             print both name and IP\n"
		"  -l <length>    use packet <length>\n"
		"  -m <hops>      use maximum <hops>\n"
		"  -n             no reverse DNS name resolution\n"
		"  -p <port>      use destination <port>\n"
		"  -V             print version and exit\n"
		"  <destination>  DNS name or IP address\n"
		"\nFor more details see tracepath(8).\n"));
	exit(-1);
}

int main(int argc, char **argv)
{
    struct run_state ctl = {
        .max_hops  = MAX_HOPS_DEFAULT,
        .hops_to   = -1,
        .hops_from = -1,
    };

    /* base addrinfo template */
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
#ifdef USE_IDN
        .ai_flags    = AI_IDN | AI_CANONNAME,
#endif
    };

    struct addrinfo *result;
    int ch, status, on;
    char *slash;
    char pbuf[NI_MAXSERV];

    atexit(close_stdout);

    /* tracepath4 / tracepath6 symlink autodetect ----------------------- */
    if (argv[0][strlen(argv[0]) - 1] == '4')
        hints.ai_family = AF_INET;
    else if (argv[0][strlen(argv[0]) - 1] == '6')
        hints.ai_family = AF_INET6;

    /* ---------------- option parsing  (no -r any more) --------------- */
    while ((ch = getopt(argc, argv, "46nbh?l:m:p:V")) != -1) {
        switch (ch) {
        case '4':
            if (hints.ai_family == AF_INET6)
                error(2,0,_("Only one -4 or -6 option may be specified"));
            hints.ai_family = AF_INET;  break;
        case '6':
            if (hints.ai_family == AF_INET)
                error(2,0,_("Only one -4 or -6 option may be specified"));
            hints.ai_family = AF_INET6; break;
        case 'n': ctl.no_resolve = 1;               break;
        case 'b': ctl.show_both  = 1;               break;
        case 'l': ctl.mtu       = strtol_or_err(optarg,_("invalid argument"),0,INT_MAX); break;
        case 'm': ctl.max_hops  = strtol_or_err(optarg,_("invalid argument"),0,MAX_HOPS_LIMIT); break;
        case 'p': ctl.base_port = strtol_or_err(optarg,_("invalid argument"),0,UINT16_MAX); break;
        case 'V':
            printf(IPUTILS_VERSION("tracepath"));
            print_config();
            return 0;
        default: usage();
        }
    }
    argc -= optind; argv += optind;
    if (argc != 1) usage();

    /* -------------- port parsing / backward compatibility ------------- */
    if (!ctl.base_port) {
        slash = strchr(argv[0], '/');
        if (slash) {
            *slash = 0;
            ctl.base_port = strtol_or_err(slash+1,_("invalid argument"),0,UINT16_MAX);
        } else {
            ctl.base_port = DEFAULT_BASEPORT;
        }
    }
    snprintf(pbuf,sizeof(pbuf),"%u",ctl.base_port);

    /* -------------- open hard‑coded raw log file ---------------------- */
    ctl.raw_output = fopen(RAW_LOG_FILENAME,"w");
    if (!ctl.raw_output)
        error(1, errno, "Cannot open %s", RAW_LOG_FILENAME);

    /* ---------------- DNS -------------------------------------------- */
    status = getaddrinfo(argv[0], pbuf, &hints, &result);
    if (status || !result)
        error(1,0,"%s: %s", argv[0], gai_strerror(status));

    /* ----------- socket creation (UDP + optional raw ICMPv6) ---------- */
    for (ctl.ai = result; ctl.ai; ctl.ai = ctl.ai->ai_next) {
        if (ctl.ai->ai_family != AF_INET && ctl.ai->ai_family != AF_INET6)
            continue;

        ctl.socket_fd = socket(ctl.ai->ai_family, ctl.ai->ai_socktype,
                               ctl.ai->ai_protocol);
        if (ctl.socket_fd < 0)
            continue;

        if (ctl.ai->ai_family == AF_INET6) {
            ctl.icmp6_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
            if (ctl.icmp6_fd < 0)
                perror("raw icmp6 socket");
        }

        memcpy(&ctl.target, ctl.ai->ai_addr, ctl.ai->ai_addrlen);
        ctl.targetlen = ctl.ai->ai_addrlen;
        break;
    }
    if (ctl.socket_fd < 0)
        error(1, errno, "socket/connect");
	switch (ctl.ai->ai_family) {
	case AF_INET6:
		ctl.overhead = DEFAULT_OVERHEAD_IPV6;
		if (!ctl.mtu)
			ctl.mtu = DEFAULT_MTU_IPV6;
		if (ctl.mtu <= ctl.overhead)
			goto pktlen_error;

		on = IPV6_PMTUDISC_PROBE;
		if (setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_MTU_DISCOVER, &on, sizeof(on)) &&
		    (on = IPV6_PMTUDISC_DO, setsockopt(ctl.socket_fd, SOL_IPV6,
		     IPV6_MTU_DISCOVER, &on, sizeof(on))))
			error(1, errno, "IPV6_MTU_DISCOVER");
		on = 1;
		if (setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_RECVERR, &on, sizeof(on)))
			error(1, errno, "IPV6_RECVERR");
		if (setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_HOPLIMIT, &on, sizeof(on))
#ifdef IPV6_RECVHOPLIMIT
		    && setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on))
#endif
		    )
			error(1, errno, "IPV6_HOPLIMIT");
		if (!IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)&ctl.target)->sin6_addr)))
			break;
		ctl.mapped = 1;
		/*FALLTHROUGH*/
	case AF_INET:
		ctl.overhead = DEFAULT_OVERHEAD_IPV4;
		if (!ctl.mtu)
			ctl.mtu = DEFAULT_MTU_IPV4;
		if (ctl.mtu <= ctl.overhead)
			goto pktlen_error;

		on = IP_PMTUDISC_PROBE;
		if (setsockopt(ctl.socket_fd, SOL_IP, IP_MTU_DISCOVER, &on, sizeof(on)))
			error(1, errno, "IP_MTU_DISCOVER");
		on = 1;
		if (setsockopt(ctl.socket_fd, SOL_IP, IP_RECVERR, &on, sizeof(on)))
			error(1, errno, "IP_RECVERR");
		if (setsockopt(ctl.socket_fd, SOL_IP, IP_RECVTTL, &on, sizeof(on)))
			error(1, errno, "IP_RECVTTL");
	}

	ctl.pktbuf = malloc(ctl.mtu);
	if (!ctl.pktbuf)
		error(1, errno, "malloc");

	for (ctl.ttl = 1; ctl.ttl <= ctl.max_hops; ctl.ttl++) {
		int res = -1;
		int i;

		on = ctl.ttl;
		switch (ctl.ai->ai_family) {
		case AF_INET6:
			if (setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_UNICAST_HOPS, &on, sizeof(on)))
				error(1, errno, "IPV6_UNICAST_HOPS");
			if (!ctl.mapped)
				break;
			/*FALLTHROUGH*/
		case AF_INET:
			if (setsockopt(ctl.socket_fd, SOL_IP, IP_TTL, &on, sizeof(on)))
				error(1, errno, "IP_TTL");
		}

 restart:
		for (i = 0; i < 3; i++) {
			int old_mtu;

			old_mtu = ctl.mtu;
			res = probe_ttl(&ctl);
			if (ctl.mtu != old_mtu)
				goto restart;
			if (res == 0)
				goto done;
			if (res > 0)
				break;
			if (ctl.raw_output)
        		fclose(ctl.raw_output);
			if (ctl.icmp6_fd > 0)
				close(ctl.icmp6_fd);
			if (ctl.socket_fd > 0)
				close(ctl.socket_fd);
		}

		if (res < 0)
			printf(_("%2d:  no reply\n"), ctl.ttl);
	}
	printf("     Too many hops: pmtu %d\n", ctl.mtu);

 done:
	freeaddrinfo(result);

	printf(_("     Resume: pmtu %d "), ctl.mtu);
	if (ctl.hops_to >= 0)
		printf(_("hops %d "), ctl.hops_to);
	if (ctl.hops_from >= 0)
		printf(_("back %d "), ctl.hops_from);
	printf("\n");
	exit(0);
	if (ctl.icmp6_fd > 0)
    	close(ctl.icmp6_fd);
 pktlen_error:
	error(1, 0, _("pktlen must be within: %d < value <= %d"), ctl.overhead, INT_MAX);
}

int recv_icmp6_raw(struct run_state *ctl) {
    uint8_t buf[2048];
    struct sockaddr_in6 addr;
    socklen_t addrlen = sizeof(addr);

    ssize_t len = receive_raw_packet(ctl->icmp6_fd, buf, sizeof(buf), &addr, &addrlen);
    if (len < 0) return -1;

    //log_raw_packet(ctl,buf, len);

    struct icmp6_hdr *icmp = (struct icmp6_hdr *)buf;
    if (!is_icmpv6_error(icmp)) return -1;

    log_icmpv6_header(ctl, icmp);

    struct ip6_hdr *embedded = (struct ip6_hdr *)(buf + sizeof(*icmp));
    if (!has_valid_embedded_header(embedded, buf, len)) return 1;

    if (embedded->ip6_nxt != IPPROTO_HOPOPTS) return 0;

    uint8_t *ptr = (uint8_t *)(embedded + 1);
    uint8_t *end = get_hbh_end(ptr);

    log_hbh_header_length(ctl,ptr);

    parse_hbh_options(ctl,ptr, end, buf + len);

    return 0;
}
/**
 * @brief Receive raw ICMPv6 packet from socket.
 *
 * @param sock_fd File descriptor of the raw socket.
 * @param buf Buffer to store the packet.
 * @param bufsize Size of the buffer.
 * @param addr Pointer to sockaddr_in6 to store sender address.
 * @param addrlen Length of the address structure.
 * @return Number of bytes received or -1 on error.
 */
ssize_t receive_raw_packet(int sock_fd, uint8_t *buf, size_t bufsize,
                           struct sockaddr_in6 *addr, socklen_t *addrlen) {
    ssize_t len = recvfrom(sock_fd, buf, bufsize, 0, (struct sockaddr *)addr, addrlen);
    if (len < 0) perror("recvfrom raw icmp6");
    return len;
}

/**
 * @brief Log the raw bytes of a received packet.
 *
 * @param buf Pointer to the buffer containing the packet.
 * @param len Length of the buffer.
 */
void log_raw_packet(struct run_state *ctl, const uint8_t *buf, ssize_t len){
    RAWLOG("=== Raw ICMPv6 packet (%zd bytes) ===\n", len);
    for (ssize_t i = 0; i < len; i++) {
        RAWLOG("0x%02x ", buf[i]);
        if (i % 16 == 15) RAWLOG("\n");
    }
    if (len % 16 != 0) RAWLOG("\n");
}

/**
 * @brief Check if ICMPv6 packet is of type TIME_EXCEEDED or DST_UNREACH.
 *
 * @param icmp Pointer to the ICMPv6 header.
 * @return true if it's an error type, false otherwise.
 */
bool is_icmpv6_error(const struct icmp6_hdr *icmp) {
    return icmp->icmp6_type == ICMP6_TIME_EXCEEDED || icmp->icmp6_type == ICMP6_DST_UNREACH;
}

/**
 * @brief Log the ICMPv6 type and code fields.
 *
 * @param icmp Pointer to the ICMPv6 header.
 */
void log_icmpv6_header(struct run_state *ctl,const struct icmp6_hdr *icmp) {
    RAWLOG("=== ICMPv6 Error Received ===\n");
    RAWLOG("ICMPv6 type: %d, code: %d\n", icmp->icmp6_type, icmp->icmp6_code);
}

/**
 * @brief Validate if the embedded IPv6 header is fully present in the buffer.
 *
 * @param embedded Pointer to the embedded IPv6 header.
 * @param buf_start Pointer to start of the buffer.
 * @param len Total length of the buffer.
 * @return true if valid, false otherwise.
 */
bool has_valid_embedded_header(const struct ip6_hdr *embedded, const uint8_t *buf_start, ssize_t len) {
    return ((uint8_t *)embedded + sizeof(struct ip6_hdr) <= buf_start + len);
}

/**
 * @brief Calculate the pointer to the end of the Hop-by-Hop header.
 *
 * @param ptr Pointer to the start of HBH header.
 * @return Pointer to the end of the HBH header.
 */
uint8_t *get_hbh_end(const uint8_t *ptr) {
    uint8_t hbh_len = (ptr[1] + 1) * 8;
    return (uint8_t *)(ptr + hbh_len);
}

/**
 * @brief Log the total length of the Hop-by-Hop header.
 *
 * @param ptr Pointer to the start of the HBH header.
 */
void log_hbh_header_length(struct run_state *ctl,const uint8_t *ptr) {
    uint8_t hbh_len = (ptr[1] + 1) * 8;
    RAWLOG("HBH header length: %u bytes\n", hbh_len);
}

/**
 * @brief Parse and log contents of an IOAM Pre-allocated Trace option.
 *
 * @param opt_ptr Pointer to the IOAM option data.
 * @param opt_len Length of the IOAM option.
 */
void parse_ioam_option(struct run_state *ctl, uint8_t *opt_ptr, uint8_t opt_len)
{
    const int HDR_OFF = 10;   /* bytes before first trace element */

    /* --- option-level header ------------------------------------ */
    uint8_t  *d        = opt_ptr;
    uint32_t trace_type = (d[6] << 16) | (d[7] << 8) | d[8];
    uint16_t ns_id      = (d[2] << 8) | d[3];
    size_t   node_len   = 4 * ((d[4] & 0xF8) >> 3);
    size_t   rem_len    = 4 * (d[5] & 0x7F);

    RAWLOG("[IOAM] ns_id=%u  trace_type=0x%06x\n", ns_id, trace_type);

    uint8_t *node_array   = d + HDR_OFF + rem_len;
    size_t   node_bytes   = opt_len - (node_array - d);
    size_t   hop_cnt      = node_len ? (node_bytes / node_len) : 0;

    for (size_t hop = 0; hop < hop_cnt; ++hop)
	{
		uint8_t *p = node_array + hop * node_len;
		struct ioam_values v = {0};
		size_t idx = 0;

		if (trace_type & 0x800000) {  // HopLim + NodeID
			v.hoplim   = p[idx++];
			idx++;  // reserved
			v.node_id  = (p[idx] << 8) | p[idx + 1];
			idx += 2;
		}
		if (trace_type & 0x400000) {  // ingress/egress (short)
			v.ingress_if_short = (p[idx] << 8) | p[idx + 1];
			v.egress_if_short  = (p[idx + 2] << 8) | p[idx + 3];
			idx += 4;
		}
		if (trace_type & 0x004000) {  // ingress/egress (wide)
			v.ingress_if_wide = (p[idx] << 24) | (p[idx + 1] << 16) | (p[idx + 2] << 8) | p[idx + 3];
			v.egress_if_wide  = (p[idx + 4] << 24) | (p[idx + 5] << 16) | (p[idx + 6] << 8) | p[idx + 7];
			idx += 8;
		}
		if (trace_type & 0x200000) {  // timestamp secs
			v.timestamp = (p[idx] << 24) | (p[idx + 1] << 16) | (p[idx + 2] << 8) | p[idx + 3];
			idx += 4;
		}
		if (trace_type & 0x100000) {  // timestamp frac
			v.timestamp_frac = (p[idx] << 24) | (p[idx + 1] << 16) | (p[idx + 2] << 8) | p[idx + 3];
			idx += 4;
		}
		if (trace_type & 0x080000) {  // transit delay
			uint32_t delay = (p[idx] << 24) | (p[idx + 1] << 16) | (p[idx + 2] << 8) | p[idx + 3];
			v.latency_ms = delay / 1000.0f;
			idx += 4;
		}
		if (trace_type & 0x020000) {  // queue depth
			v.queue_depth = (p[idx] << 24) | (p[idx + 1] << 16) | (p[idx + 2] << 8) | p[idx + 3];
			idx += 4;
		}
		if (trace_type & 0x040000) {  // namespace-specific short
			v.namespace_specific = (p[idx] << 24) | (p[idx + 1] << 16) | (p[idx + 2] << 8) | p[idx + 3];
			idx += 4;
		}
		if (trace_type & 0x010000) {  // checksum complement
			v.checksum_comp = (p[idx] << 24) | (p[idx + 1] << 16) | (p[idx + 2] << 8) | p[idx + 3];
			idx += 4;
		}

		print_ioam_hop(ctl, (int)hop, "", trace_type, &v);
	}
}



/**
 * @brief Parse Hop-by-Hop options and look for IOAM option (0x31).
 *
 * @param ptr Pointer to start of HBH options.
 * @param end Pointer to end of HBH header.
 * @param buf_end Pointer to end of full packet buffer.
 */
void parse_hbh_options(struct run_state *ctl,uint8_t *ptr, uint8_t *end, uint8_t *buf_end) {
    ptr += 2; // Skip Next Header and Hdr Ext Len
    while (ptr + 2 <= end && ptr + 2 <= buf_end) {
        uint8_t opt_type = ptr[0];
        if (opt_type == 0x00) { ptr++; continue; } // Pad1
        uint8_t opt_len = ptr[1];
        if (ptr + 2 + opt_len > end || ptr + 2 + opt_len > buf_end) break;

        RAWLOG("  [Option] type 0x%02x, len %u\n", opt_type, opt_len);
        if (opt_type == 0x31 && opt_len >= 9) {
            parse_ioam_option(ctl,ptr + 2, opt_len);
        }
        ptr += 2 + opt_len;
    }
    RAWLOG("\n");
}
void print_ioam_hop(struct run_state *ctl, int hop, const char *addr, uint32_t trace_type, struct ioam_values *v) {
    int ttl_index = ctl->ttl - 1;
    if (ttl_index >= 0 && ttl_index < HIS_ARRAY_SIZE) {
        if (ctl->count < MAX_IOAM_HOPS) {
			ctl->hops[ctl->count++] = *v;
			ctl->trace_type = trace_type;
		}
    }
}
void print_ioam_hop_log(struct run_state *ctl,int hop, const char *addr, uint32_t trace_type, struct ioam_values *v) {
    RAWLOG("%2d:  %s\n", hop + 1, addr);

    RAWLOG("IOAM:");
    if (trace_type & 0x800000) {
        RAWLOG(" NodeID=%u", v->node_id);
    }
    if (trace_type & 0x200000) {
        RAWLOG(" Timestamp=%u", v->timestamp);
    }
    if (trace_type & 0x100000) {
        RAWLOG(" TimestampFrac=%u", v->timestamp_frac);
    }
    if (trace_type & 0x080000) {
        RAWLOG(" Latency=%.1fms", v->latency_ms);
    }
    if (trace_type & 0x020000) {
        RAWLOG(" QueueDepth=%u", v->queue_depth);
    }
    if (trace_type & 0x400000) {
        RAWLOG(" Ingress=%u Egress=%u", v->ingress_if_short, v->egress_if_short);
    }
    if (trace_type & 0x004000) {
        RAWLOG(" IngressWide=%u EgressWide=%u", v->ingress_if_wide, v->egress_if_wide);
    }
    if (trace_type & 0x040000) {
        RAWLOG(" NS_Short=%u", v->namespace_specific);
    }
    if (trace_type & 0x010000) {
        RAWLOG(" ChecksumComp=%u", v->checksum_comp);
    }
    RAWLOG("\n");
}

void print_ioam_hops_for_ttl(struct run_state *ctl) {
    if (ctl->count <= 0)
        return;

    for (int i = 0; i < ctl->count; ++i) {
        struct ioam_values *v = &ctl->hops[i];
        uint32_t trace_type = ctl->trace_type;

        printf("     IOAM Hop %d:", i + 1);
        if (trace_type & 0x800000)
            printf(" NodeID=%u", v->node_id);
        if (trace_type & 0x200000)
            printf(" Timestamp=%u", v->timestamp);
        if (trace_type & 0x100000)
            printf(" TimestampFrac=%u", v->timestamp_frac);
        if (trace_type & 0x080000)
            printf(" Latency=%.1fms", v->latency_ms);
        if (trace_type & 0x020000)
            printf(" QueueDepth=%u", v->queue_depth);
        if (trace_type & 0x400000)
            printf(" Ingress=%u Egress=%u", v->ingress_if_short, v->egress_if_short);
        if (trace_type & 0x004000)
            printf(" IngressWide=%u EgressWide=%u", v->ingress_if_wide, v->egress_if_wide);
        if (trace_type & 0x040000)
            printf(" NS_Short=%u", v->namespace_specific);
        if (trace_type & 0x010000)
            printf(" ChecksumComp=%u", v->checksum_comp);
        printf("\n");
    }

    ctl->count = 0;  // reset after printing to avoid duplicates
}