// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause

// Copyright (c) 2024, Jan Kucera <kucera@highpps.net>

// Based on implementation created by Maxim Mikityanskiy <maximmi@nvidia.com>
// Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "vmlinux.h"
#include "xdpcookie.h"

#include <asm/errno.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define NSEC_PER_SEC 1000000000L

#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define tcp_flag_word(tp) (((union tcp_word_hdr *)(tp))->words[3])

#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

#define NEXTHDR_TCP 6

#define TCPOPT_NOP 1
#define TCPOPT_EOL 0
#define TCPOPT_MSS 2
#define TCPOPT_WINDOW 3
#define TCPOPT_SACK_PERM 4
#define TCPOPT_TIMESTAMP 8

#define TCPOLEN_MSS 4
#define TCPOLEN_WINDOW 3
#define TCPOLEN_SACK_PERM 2
#define TCPOLEN_TIMESTAMP 10

#define TCP_TS_HZ 1000
#define TS_OPT_WSCALE_MASK 0xf
#define TS_OPT_SACK (1 << 4)
#define TS_OPT_ECN (1 << 5)
#define TSBITS 6
#define TSMASK (((__u32)1 << TSBITS) - 1)
#define TCP_MAX_WSCALE 14U

#define IPV4_MAXLEN 60
#define TCP_MAXLEN 60

#define MAX_PACKET_OFF 0xffff

const volatile struct xdpcookie_conf conf = {
	.vlans = {},
	.ports = {},
	.opts = {
		.mss4 = DEFAULT_MSS4,
		.mss6 = DEFAULT_MSS6,
		.wscale = DEFAULT_WSCALE,
		.ttl = DEFAULT_TTL,
	},
};

#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define __get_unaligned_t(type, ptr) ({						\
	const struct { type x; } __attribute__((__packed__)) *__pptr = (typeof(__pptr))(ptr); \
	__pptr->x;								\
})

#define get_unaligned(ptr) __get_unaligned_t(typeof(*(ptr)), (ptr))

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} values SEC(".maps");

/* Some symbols defined in net/netfilter/nf_conntrack_bpf.c are unavailable in
 * vmlinux.h if CONFIG_NF_CONNTRACK=m, so they are redefined locally.
 */

struct bpf_ct_opts___local {
	s32 netns_id;
	s32 error;
	u8 l4proto;
	u8 dir;
	u8 reserved[2];
} __attribute__((preserve_access_index));

#define BPF_F_CURRENT_NETNS (-1)

extern struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *xdp_ctx,
					 struct bpf_sock_tuple *bpf_tuple,
					 __u32 len_tuple,
					 struct bpf_ct_opts___local *opts,
					 __u32 len_opts) __ksym;

extern void bpf_ct_release(struct nf_conn *ct) __ksym;

static __always_inline void swap_eth_addr(__u8 *a, __u8 *b)
{
	__u8 tmp[ETH_ALEN];

	__builtin_memcpy(tmp, a, ETH_ALEN);
	__builtin_memcpy(a, b, ETH_ALEN);
	__builtin_memcpy(b, tmp, ETH_ALEN);
}

static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);

	return (__u16) ~csum;
}

static __always_inline __u16 csum_ipv4_magic(
	__be32 saddr,
	__be32 daddr,
	__u32 len,
	__u8 proto,
    __u32 csum)
{
	__u64 sum = csum;

	sum += (__u32) saddr;
	sum += (__u32) daddr;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	sum += proto + len;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	sum += (proto + len) << 8;
#else
	#error Unknown endian
#endif

	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);

	return csum_fold((__u32) sum);
}

static __always_inline __u16 csum_ipv6_magic(
	const struct in6_addr *saddr,
	const struct in6_addr *daddr,
	__u32 len,
	__u8 proto,
	__u32 csum)
{
	__u64 sum = csum;

#pragma unroll
	for (int i = 0; i < 4; i++)
		sum += (__u32) saddr->in6_u.u6_addr32[i];

#pragma unroll
	for (int i = 0; i < 4; i++)
		sum += (__u32) daddr->in6_u.u6_addr32[i];

	// Don't combine additions to avoid 32-bit overflow.
	sum += bpf_htonl(len);
	sum += bpf_htonl(proto);

	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);

	return csum_fold((__u32) sum);
}

static __always_inline __u64 tcp_clock_ns()
{
	return bpf_ktime_get_ns();
}

static __always_inline __u32 tcp_ns_to_ts(__u64 ns)
{
	return ns / (NSEC_PER_SEC / TCP_TS_HZ);
}

static __always_inline __u32 tcp_clock_ms()
{
	return tcp_ns_to_ts(tcp_clock_ns());
}

struct tcpopt_context {
	void *data;
	void *data_end;
	__be32 *tsecr;
	__u8 wscale;
	bool option_timestamp;
	bool option_sack;
	__u32 off;
};

static __always_inline u8 *next(struct tcpopt_context *ctx, __u32 sz)
{
	__u64 off = ctx->off;
	__u8 *data;

	/* Verifier forbids access to packet when offset exceeds MAX_PACKET_OFF */
	if (off > MAX_PACKET_OFF - sz)
		return NULL;

	data = ctx->data + off;
	barrier_var(data);
	if (data + sz >= ctx->data_end)
		return NULL;

	ctx->off += sz;
	return data;
}

static int tscookie_tcpopt_parse(struct tcpopt_context *ctx)
{
	__u8 *opcode, *opsize, *wscale, *tsecr;
	__u32 off = ctx->off;

	opcode = next(ctx, 1);
	if (!opcode)
		return 1;

	if (*opcode == TCPOPT_EOL)
		return 1;
	if (*opcode == TCPOPT_NOP)
		return 0;

	opsize = next(ctx, 1);
	if (!opsize || *opsize < 2)
		return 1;

	switch (*opcode) {
	case TCPOPT_WINDOW:
		wscale = next(ctx, 1);
		if (!wscale)
			return 1;
		if (*opsize == TCPOLEN_WINDOW)
			ctx->wscale = *wscale < TCP_MAX_WSCALE ? *wscale : TCP_MAX_WSCALE;
		break;
	case TCPOPT_TIMESTAMP:
		tsecr = next(ctx, 4);
		if (!tsecr)
			return 1;
		if (*opsize == TCPOLEN_TIMESTAMP) {
			ctx->option_timestamp = true;
			/* Client's tsval becomes our tsecr. */
			*ctx->tsecr = get_unaligned((__be32 *)tsecr);
		}
		break;
	case TCPOPT_SACK_PERM:
		if (*opsize == TCPOLEN_SACK_PERM)
			ctx->option_sack = true;
		break;
	}

	ctx->off = off + *opsize;

	return 0;
}

static int tscookie_tcpopt_parse_batch(__u32 index, void *context)
{
	for (int i = 0; i < 7; i++)
		if (tscookie_tcpopt_parse(context))
			return 1;
	return 0;
}

static __always_inline bool tscookie_init(
	struct tcphdr *tcp_header,
	__u16 tcp_len,
	__be32 *tsval,
	__be32 *tsecr,
	void *data,
	void *data_end)
{
	struct tcpopt_context loop_ctx = {
		.data = data,
		.data_end = data_end,
		.tsecr = tsecr,
		.wscale = TS_OPT_WSCALE_MASK,
		.option_timestamp = false,
		.option_sack = false,
		/* Note: currently verifier would track .off as unbound scalar.
		 *       In case if verifier would at some point get smarter and
		 *       compute bounded value for this var, beware that it might
		 *       hinder bpf_loop() convergence validation.
		 */
		.off = (__u8 *)(tcp_header + 1) - (__u8 *)data,
	};
	u32 cookie;

	bpf_loop(6, tscookie_tcpopt_parse_batch, &loop_ctx, 0);

	if (!loop_ctx.option_timestamp)
		return false;

	cookie = tcp_clock_ms() & ~TSMASK;
	cookie |= loop_ctx.wscale & TS_OPT_WSCALE_MASK;
	if (loop_ctx.option_sack)
		cookie |= TS_OPT_SACK;
	if (tcp_header->ece && tcp_header->cwr)
		cookie |= TS_OPT_ECN;
	*tsval = bpf_htonl(cookie);

	return true;
}

static __always_inline void values_get_tcpipopts(
	__u16 *mss,
	__u8 *wscale,
	__u8 *ttl,
	bool ipv6)
{
	*mss = ipv6 ? conf.opts.mss6 : conf.opts.mss4;
	*wscale = conf.opts.wscale;
	*ttl = conf.opts.ttl;
}

static __always_inline void increment_counter(enum xdpcookie_cntr cntr)
{
	__u32 key = cntr;
	__u64 *value;

	value = bpf_map_lookup_elem(&values, &key);
	if (value)
		*value = *value + 1;
}

struct hdr_cursor {
    void *pos;
    unsigned off;
};

static __always_inline int parse_ethhdr(
	struct hdr_cursor *nh,
	void *data_end,
	struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    __u16 proto;

    if (eth + 1 > data_end)
        return -1;

    nh->pos = eth + 1;
    nh->off += sizeof(*eth);

    proto = eth->h_proto;
    *ethhdr = eth;

    return proto;
}

static __always_inline int parse_iphdr(
	struct hdr_cursor *nh,
    void *data_end,
    struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;

    // Variable-length IPv4 header
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    nh->off += hdrsize;

    *iphdr = iph;

    return iph->protocol;
}

static __always_inline int parse_ip6hdr(
	struct hdr_cursor *nh,
    void *data_end,
    struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;

    if (ip6h + 1 > data_end)
        return -1;

    nh->pos = ip6h + 1;
    nh->off += sizeof(*ip6h);

    *ip6hdr = ip6h;

    return ip6h->nexthdr;
}

static __always_inline int parse_tcphdr(
	struct hdr_cursor *nh,
    void *data_end,
    struct tcphdr **tcphdr)
{
    int len;
    struct tcphdr *tcp = nh->pos;

    if (tcp + 1 > data_end)
        return -1;

    len = tcp->doff * 4;
    if ((void *) tcp + len > data_end)
        return -1;

    nh->pos = tcp + 1;
    nh->off += sizeof(*tcp);

    *tcphdr = tcp;

    return len;
}

struct header_pointers {
	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct ipv6hdr *ipv6;
	__u16 ipvx_off;
	__u16 ipvx_len;
	struct tcphdr *tcp;
	__u16 tcp_len;
	__u16 tcp_off;
};

static __always_inline int parse_headers(
	struct xdp_md *ctx,
	struct header_pointers *hdr)
{
	void *data_end = (void *)(long) ctx->data_end;
	void *data = (void *)(long) ctx->data;

	struct hdr_cursor nh = {
		.pos = data,
		.off = 0,
	};

	int eth_type;
	int ip_type;
	int tcp_len;

	hdr->eth = NULL;

	hdr->ipv4 = NULL;
	hdr->ipv6 = NULL;
	hdr->ipvx_off = 0;
	hdr->ipvx_len = 0;

	hdr->tcp = NULL;
	hdr->tcp_len = 0;
	hdr->tcp_off = 0;

	eth_type = parse_ethhdr(&nh, data_end, &hdr->eth);
	if (eth_type < 0)
		return XDP_DROP;

	hdr->ipvx_off = nh.off;

	switch (eth_type) {
	case bpf_htons(ETH_P_IP):
		ip_type = parse_iphdr(&nh, data_end, &hdr->ipv4);

		if (ip_type < 0)
			return XDP_DROP;

		if (hdr->ipv4->ihl * 4 < sizeof(*hdr->ipv4))
			return XDP_DROP;

		if (hdr->ipv4->version != 4)
			return XDP_DROP;

		hdr->ipvx_len = hdr->ipv4->ihl * 4;

		break;

	case bpf_htons(ETH_P_IPV6):
		ip_type = parse_ip6hdr(&nh, data_end, &hdr->ipv6);

		if (ip_type < 0)
			return XDP_DROP;

		if (hdr->ipv6->version != 6)
			return XDP_DROP;

		hdr->ipvx_len = sizeof(*hdr->ipv6);

		break;

	default:
		return XDP_PASS;
	}

	if (ip_type != NEXTHDR_TCP)
		return XDP_PASS;

	hdr->tcp_off = nh.off;

	tcp_len = parse_tcphdr(&nh, data_end, &hdr->tcp);
	if (tcp_len < 0)
		return XDP_DROP;

	if (tcp_len < sizeof(*hdr->tcp))
		return XDP_DROP;

	hdr->tcp_len = tcp_len;

	return XDP_TX;
}

static __always_inline int tcp_lookup(void *ctx, struct header_pointers *hdr)
{
	struct bpf_ct_opts___local ct_lookup_opts = {
		.netns_id = BPF_F_CURRENT_NETNS,
		.l4proto = IPPROTO_TCP,
	};
	struct bpf_sock_tuple tup = {};
	struct nf_conn *ct;
	__u32 tup_size;

	if (hdr->ipv4) {
		// TCP doesn't normally use fragments, and XDP can't reassemble them.
		if ((hdr->ipv4->frag_off & bpf_htons(IP_DF | IP_MF | IP_OFFSET)) != bpf_htons(IP_DF))
			return XDP_DROP;

		tup.ipv4.saddr = hdr->ipv4->saddr;
		tup.ipv4.daddr = hdr->ipv4->daddr;
		tup.ipv4.sport = hdr->tcp->source;
		tup.ipv4.dport = hdr->tcp->dest;
		tup_size = sizeof(tup.ipv4);
	} else if (hdr->ipv6) {
		__builtin_memcpy(tup.ipv6.saddr, &hdr->ipv6->saddr, sizeof(tup.ipv6.saddr));
		__builtin_memcpy(tup.ipv6.daddr, &hdr->ipv6->daddr, sizeof(tup.ipv6.daddr));
		tup.ipv6.sport = hdr->tcp->source;
		tup.ipv6.dport = hdr->tcp->dest;
		tup_size = sizeof(tup.ipv6);
	} else {
		// The verifier can't track that either ipv4 or ipv6 is not NULL.
		return XDP_ABORTED;
	}

	ct = bpf_xdp_ct_lookup(ctx, &tup, tup_size, &ct_lookup_opts, sizeof(ct_lookup_opts));
	if (ct) {
		unsigned long status = ct->status;

		bpf_ct_release(ct);
		if (status & IPS_CONFIRMED)
			return XDP_PASS;
	} else if (ct_lookup_opts.error != -ENOENT) {
		return XDP_ABORTED;
	}

	/* error == -ENOENT || !(status & IPS_CONFIRMED) */
	return XDP_TX;
}

static __always_inline __u8 tcp_mkoptions(
	__be32 *buf,
	__be32 *tsopt,
	__u16 mss,
	__u8 wscale)
{
	__be32 *start = buf;

	*buf++ = bpf_htonl((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | mss);

	if (!tsopt)
		return buf - start;

	if (tsopt[0] & bpf_htonl(1 << 4))
		*buf++ = bpf_htonl((TCPOPT_SACK_PERM << 24) |
				   (TCPOLEN_SACK_PERM << 16) |
				   (TCPOPT_TIMESTAMP << 8) |
				   TCPOLEN_TIMESTAMP);
	else
		*buf++ = bpf_htonl((TCPOPT_NOP << 24) |
				   (TCPOPT_NOP << 16) |
				   (TCPOPT_TIMESTAMP << 8) |
				   TCPOLEN_TIMESTAMP);
	*buf++ = tsopt[0];
	*buf++ = tsopt[1];

	if ((tsopt[0] & bpf_htonl(0xf)) != bpf_htonl(0xf))
		*buf++ = bpf_htonl((TCPOPT_NOP << 24) |
				   (TCPOPT_WINDOW << 16) |
				   (TCPOLEN_WINDOW << 8) |
				   wscale);

	return buf - start;
}

static __always_inline void tcp_gen_synack(
	struct tcphdr *tcp_header,
	__u32 cookie,
	__be32 *tsopt,
	__u16 mss,
	__u8 wscale)
{
	void *tcp_options;

	tcp_flag_word(tcp_header) = TCP_FLAG_SYN | TCP_FLAG_ACK;
	if (tsopt && (tsopt[0] & bpf_htonl(1 << 5)))
		tcp_flag_word(tcp_header) |= TCP_FLAG_ECE;
	tcp_header->doff = 5; /* doff is part of tcp_flag_word. */
	swap(tcp_header->source, tcp_header->dest);
	tcp_header->ack_seq = bpf_htonl(bpf_ntohl(tcp_header->seq) + 1);
	tcp_header->seq = bpf_htonl(cookie);
	tcp_header->window = 0;
	tcp_header->urg_ptr = 0;
	tcp_header->check = 0; // Calculate checksum later

	tcp_options = (void *)(tcp_header + 1);
	tcp_header->doff += tcp_mkoptions(tcp_options, tsopt, mss, wscale);
}

static __always_inline void tcpv4_gen_synack(
	struct header_pointers *hdr,
	__u32 cookie,
	__be32 *tsopt)
{
	__u8 wscale;
	__u16 mss;
	__u8 ttl;

	values_get_tcpipopts(&mss, &wscale, &ttl, false);

	swap_eth_addr(hdr->eth->h_source, hdr->eth->h_dest);

	swap(hdr->ipv4->saddr, hdr->ipv4->daddr);
	hdr->ipv4->check = 0; // Calculate checksum later
	hdr->ipv4->tos = 0;
	hdr->ipv4->id = 0;
	hdr->ipv4->ttl = ttl;

	tcp_gen_synack(hdr->tcp, cookie, tsopt, mss, wscale);

	hdr->tcp_len = hdr->tcp->doff * 4;
	hdr->ipv4->tot_len = bpf_htons(sizeof(*hdr->ipv4) + hdr->tcp_len);
}

static __always_inline void tcpv6_gen_synack(
	struct header_pointers *hdr,
	__u32 cookie,
	__be32 *tsopt)
{
	__u8 wscale;
	__u16 mss;
	__u8 ttl;

	values_get_tcpipopts(&mss, &wscale, &ttl, true);

	swap_eth_addr(hdr->eth->h_source, hdr->eth->h_dest);

	swap(hdr->ipv6->saddr, hdr->ipv6->daddr);
	*(__be32 *)hdr->ipv6 = bpf_htonl(0x60000000);
	hdr->ipv6->hop_limit = ttl;

	tcp_gen_synack(hdr->tcp, cookie, tsopt, mss, wscale);

	hdr->tcp_len = hdr->tcp->doff * 4;
	hdr->ipv6->payload_len = bpf_htons(hdr->tcp_len);
}

static __always_inline int xdpcookie_gen_synack(
	struct xdp_md *ctx,
	struct header_pointers *hdr)
{
	void *data_end = (void *)(long) ctx->data_end;
	void *data = (void *)(long) ctx->data;

	/* Unlike clang 10, clang 11 and 12 generate code that doesn't pass the
	 * BPF verifier if tsopt is not volatile. Volatile forces it to store
	 * the pointer value and use it directly, otherwise tcp_mkoptions is
	 * (mis)compiled like this:
	 *   if (!tsopt)
	 *       return buf - start;
	 *   reg = stored_return_value_of_tscookie_init;
	 *   if (reg)
	 *       tsopt = tsopt_buf;
	 *   else
	 *       tsopt = NULL;
	 *   ...
	 *   *buf++ = tsopt[1];
	 * It creates a dead branch where tsopt is assigned NULL, but the
	 * verifier can't prove it's dead and blocks the program.
	 */
	__be32 * volatile tsopt = NULL;
	__be32 tsopt_buf[2] = {};
	__u16 ip_len;
	__u32 cookie;
	__s64 value;

	if ((void *) hdr->tcp + TCP_MAXLEN > data_end)
		return XDP_ABORTED;

	if (hdr->ipv4) {
		ip_len = sizeof(*hdr->ipv4);

		if (hdr->ipv4 + 1 > data_end)
			return XDP_ABORTED;

		value = bpf_tcp_raw_gen_syncookie_ipv4(hdr->ipv4, hdr->tcp, hdr->tcp_len);
	} else if (hdr->ipv6) {
		ip_len = sizeof(*hdr->ipv6);

		if (hdr->ipv6 + 1 > data_end)
			return XDP_ABORTED;

		value = bpf_tcp_raw_gen_syncookie_ipv6(hdr->ipv6, hdr->tcp, hdr->tcp_len);
	} else {
		return XDP_ABORTED;
	}

	if (value < 0)
		return XDP_ABORTED;

	cookie = (__u32) value;

	if (tscookie_init((void *)hdr->tcp, hdr->tcp_len,
			  &tsopt_buf[0], &tsopt_buf[1], data, data_end))
		tsopt = tsopt_buf;

	/* Check that there is enough space for a SYNACK. It also covers
	 * the check that the destination of the __builtin_memmove below
	 * doesn't overflow.
	 */
	if (data + sizeof(*hdr->eth) + ip_len + TCP_MAXLEN > data_end)
		return XDP_ABORTED;

	if (hdr->ipv4) {
		if (hdr->ipv4->ihl * 4 > sizeof(*hdr->ipv4)) {
			struct tcphdr *new_tcp_header;

			new_tcp_header = data + sizeof(*hdr->eth) + sizeof(*hdr->ipv4);
			__builtin_memmove(new_tcp_header, hdr->tcp, sizeof(*hdr->tcp));
			hdr->tcp = new_tcp_header;

			hdr->ipv4->ihl = sizeof(*hdr->ipv4) / 4;
			hdr->ipvx_len = sizeof(*hdr->ipv4);
		}

		tcpv4_gen_synack(hdr, cookie, tsopt);
	} else if (hdr->ipv6) {
		tcpv6_gen_synack(hdr, cookie, tsopt);
	} else {
		return XDP_ABORTED;
	}

	return XDP_TX;
}

static __always_inline int xdpcookie_check_sums(
	struct xdp_md *ctx,
	struct header_pointers *hdr)
{
	void *end = (void *)(long) ctx->data_end;

	__s64 value;
	__u16 sum;

	if (hdr->ipv4) {

		// Check that the IP header has at most IPV4_MAXLEN and there
		// is enough data in the buffer to pass it to bpf_csum_diff()
		// and pass the verifier.

		if ((void *) hdr->ipv4 + IPV4_MAXLEN > end)
			return XDP_ABORTED;

		value = bpf_csum_diff(0, 0, (void *) hdr->ipv4, hdr->ipv4->ihl * 4, 0);
		if (value < 0)
			return XDP_ABORTED;

		sum = csum_fold(value);
		if (sum != 0)
			return XDP_DROP; // Bad IPv4 checksum
	}

	// Check that the TCP header has at most TCP_MAXLEN and there
	// is enough data in the buffer to pass it to bpf_csum_diff()
	// and pass the verifier.

	if ((void *) hdr->tcp + TCP_MAXLEN > end)
		return XDP_ABORTED;

	value = bpf_csum_diff(0, 0, (void *) hdr->tcp, hdr->tcp_len, 0);
	if (value < 0)
		return XDP_ABORTED;

	if (hdr->ipv4) {
		if (hdr->ipv4 + 1 > end)
			return XDP_ABORTED;

		sum = csum_ipv4_magic(hdr->ipv4->saddr, hdr->ipv4->daddr, hdr->tcp_len, IPPROTO_TCP, value);
	} else if (hdr->ipv6) {
		if (hdr->ipv6 + 1 > end)
			return XDP_ABORTED;

		sum = csum_ipv6_magic(&hdr->ipv6->saddr, &hdr->ipv6->daddr, hdr->tcp_len, IPPROTO_TCP, value);
	} else {
		return XDP_ABORTED;
	}

	if (sum != 0)
		return XDP_DROP; // Bad TCP checksum

	return XDP_TX;
}

static __always_inline int xdpcookie_calc_sums(
	struct xdp_md *ctx,
	struct header_pointers *hdr)
{
	__s64 value;
	__u16 sum;

	hdr->tcp->check = 0;

	value = bpf_csum_diff(0, 0, (void *) hdr->tcp, hdr->tcp_len, 0);
	if (value < 0)
		return XDP_ABORTED;

	if (hdr->ipv4)
		sum = csum_ipv4_magic(hdr->ipv4->saddr, hdr->ipv4->daddr, hdr->tcp_len, IPPROTO_TCP, value);
	else if (hdr->ipv6)
		sum = csum_ipv6_magic(&hdr->ipv6->saddr, &hdr->ipv6->daddr, hdr->tcp_len, IPPROTO_TCP, value);
	else
		return XDP_ABORTED;

	hdr->tcp->check	= sum;

	if (hdr->ipv4) {
		hdr->ipv4->check = 0;

		value = bpf_csum_diff(0, 0, (void *) hdr->ipv4, hdr->ipvx_len, 0);
		if (value < 0)
			return XDP_ABORTED;

		sum = csum_fold(value);
		hdr->ipv4->check = sum;
	}

	return XDP_TX;
}

static __always_inline int xdpcookie_grow_buffer(
	struct xdp_md *ctx,
	struct header_pointers *hdr)
{
	void *data;

	// Find out buffer capacity behind TCP offset
	__u64 tcp_buff_cap = bpf_xdp_get_buff_len(ctx) - hdr->tcp_off;

	// Grow the buffer to TCP_MAXLEN to be able to pass any
	// hdr->tcp_len value to bpf_tcp_raw_gen_syncookie_ipv4/6()
	// and pass the verifier.

	int ret = bpf_xdp_adjust_tail(ctx, TCP_MAXLEN - tcp_buff_cap);
	if (ret)
		return XDP_ABORTED;

	// Re-evaluate pointers after tail adjustment as the
	// underlying packet buffer may changed and the checks
	// on pointers by the verifier were invalidated.

	data = (void *)(long) ctx->data;

	hdr->eth = data;

	if (hdr->ipv4)
		hdr->ipv4 = data + hdr->ipvx_off;
	else if (hdr->ipv6)
		hdr->ipv6 = data + hdr->ipvx_off;
	else
		return XDP_ABORTED;

	hdr->tcp = data + hdr->tcp_off;

	return XDP_TX;
}

static __always_inline int xdpcookie_shrink_buffer(
	struct xdp_md *ctx,
	struct header_pointers *hdr)
{
	__u32 old_ipbuf_len = hdr->tcp_off - hdr->ipvx_off + TCP_MAXLEN;
	__u32 new_ipbuf_len = hdr->ipvx_len + hdr->tcp_len;

	if (bpf_xdp_adjust_tail(ctx, new_ipbuf_len - old_ipbuf_len))
		return XDP_ABORTED;

	return XDP_TX;
}

static __always_inline int xdpcookie_handle_syn(
	struct xdp_md *ctx,
	struct header_pointers *hdr)
{
	int ret;

	if (hdr->tcp->fin || hdr->tcp->rst)
		return XDP_DROP;

	ret = xdpcookie_grow_buffer(ctx, hdr);
	if (ret != XDP_TX)
		return ret;

	if (conf.check_sums) {
		ret = xdpcookie_check_sums(ctx, hdr);
		if (ret != XDP_TX)
			return ret;
	}

	ret = xdpcookie_gen_synack(ctx, hdr);
	if (ret != XDP_TX)
		return ret;

	if (conf.calc_sums) {
		ret = xdpcookie_calc_sums(ctx, hdr);
		if (ret != XDP_TX)
			return ret;
	}

	ret = xdpcookie_shrink_buffer(ctx, hdr);
	if (ret != XDP_TX)
		return ret;

	increment_counter(COUNTER_SYNACK);

	return XDP_TX;
}

static __always_inline int xdpcookie_handle_ack(
	struct xdp_md *ctx,
	struct header_pointers *hdr)
{
	int ret;

	// Established connection?
	ret = tcp_lookup(ctx, hdr);
	if (ret != XDP_TX)
		return ret;

	if (hdr->tcp->rst)
		return XDP_DROP;

	if (hdr->ipv4)
		ret = bpf_tcp_raw_check_syncookie_ipv4(hdr->ipv4, hdr->tcp);
	else if (hdr->ipv6)
		ret = bpf_tcp_raw_check_syncookie_ipv6(hdr->ipv6, hdr->tcp);
	else
		return XDP_ABORTED;

	if (ret)
		return XDP_DROP;

	return XDP_PASS;
}

static __always_inline bool check_port_allowed(__u16 port)
{
	#pragma unroll
	for (__u32 i = 0; i < MAX_PORTS_ALLOWED; i++) {

		if (conf.ports[i] == 0)
			break;

		if (conf.ports[i] == port)
			return true;
	}

	return false;
}

int xdpcookie_core(struct xdp_md *ctx)
{
	struct header_pointers hdr;
	int ret;

	// Parse & check packet is TCP
	ret = parse_headers(ctx, &hdr);
	if (ret != XDP_TX)
		return ret;

	// SYN packet on other than allowed port?
	if (!check_port_allowed(bpf_ntohs(hdr.tcp->dest)))
		return XDP_PASS;

	// SYN / ACK mutually non exclusive
	if ((hdr.tcp->syn ^ hdr.tcp->ack) != 1)
		return XDP_DROP;

	if (hdr.tcp->syn)
		return xdpcookie_handle_syn(ctx, &hdr);

	if (conf.check_acks)
		return xdpcookie_handle_ack(ctx, &hdr);

	return XDP_PASS;
}

extern int bpf_xdp_metadata_rx_vlan_tag(
	const struct xdp_md *ctx,
	__be16 *vlan_proto,
	__u16 *vlan_tci) __ksym;

static __always_inline void vlan_tag_read(
	struct xdp_md *ctx,
	__be16 *vlan_proto,
	__u16 *vlan_tci)
{
	int ret;

	ret = bpf_xdp_metadata_rx_vlan_tag(ctx, vlan_proto, vlan_tci);
	if (ret < 0) {
		*vlan_proto = 0;
		*vlan_tci = 0;
	}
}

static __always_inline int vlan_tag_push(
	struct xdp_md *ctx,
	__be16 vlan_proto,
	__u16 vlan_tci)
{
	struct ethhdr eth_copy;
	struct vlan_hdr *vlan;
	struct ethhdr *eth;
	void *end;

	// Nothing to push
	if (vlan_proto == 0)
		return XDP_TX;

	eth = (void *)(long) ctx->data;
	end = (void *)(long) ctx->data_end;
	if (eth + 1 > end)
		return XDP_ABORTED;

	// Copy the original Ethernet header
	__builtin_memcpy(&eth_copy, eth, sizeof(eth_copy));

	// Create space in front of the packet
	if (bpf_xdp_adjust_head(ctx, 0 - (int) sizeof(*vlan)))
		return XDP_ABORTED;

	// Re-evaluate end and eth after head adjustment as the
	// underlying packet buffer may changed and the checks
	// on pointers by the verifier were invalidated.

	eth = (void *)(long) ctx->data;
	end = (void *)(long) ctx->data_end;
	if (eth + 1 > end)
		return XDP_ABORTED;

	// Copy back the Ethernet header in the right place
	__builtin_memcpy(eth, &eth_copy, sizeof(eth_copy));

	vlan = (void *)(eth + 1);
	if (vlan + 1 > end)
		return XDP_ABORTED;

	// Populate VLAN tag with ID and proto
	vlan->h_vlan_TCI = bpf_htons(vlan_tci);
	vlan->h_vlan_encapsulated_proto = eth->h_proto;

	// Set Ethernet header type to VLAN
	eth->h_proto = vlan_proto;

	return XDP_TX;
}

static __always_inline bool check_vlan_allowed(__u16 vlan)
{
	// Allow packets without VLAN if no VLAN specified
	if (conf.vlans[0] == 0 && vlan == 0)
		return true;

	#pragma unroll
	for (__u32 i = 0; i < MAX_VLANS_ALLOWED; i++) {

		if (conf.vlans[i] == 0)
			break;

		if (conf.vlans[i] == vlan)
			return true;
	}

	return false;
}

SEC("xdp.frags")
int xdpcookie(struct xdp_md *ctx)
{
	__be16 vlan_proto;
	__u16 vlan_tci;
	int ret;

	// Read VLAN tag from metadata
	vlan_tag_read(ctx, &vlan_proto, &vlan_tci);

	// Packet in other than allowed VLAN?
	if (!check_vlan_allowed(vlan_tci))
		return XDP_PASS;

	// Evaluate the packet
	ret = xdpcookie_core(ctx);
	if (ret != XDP_TX)
		return ret;

	// Push the VLAN tag back, for TX responses
	ret = vlan_tag_push(ctx, vlan_proto, vlan_tci);
	if (ret != XDP_TX)
		return ret;

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
