// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause

#define DEFAULT_MSS4 1460
#define DEFAULT_MSS6 1440
#define DEFAULT_WSCALE 7
#define DEFAULT_TTL 64

#define MAX_VLANS_ALLOWED 4
#define MAX_PORTS_ALLOWED 8

struct xdpcookie_opts {
	__u16 mss4;
	__u16 mss6;
	__u8 wscale;
	__u8 ttl;
};

struct xdpcookie_conf {
	__u16 vlans[MAX_VLANS_ALLOWED];
	__u16 ports[MAX_PORTS_ALLOWED];
	struct xdpcookie_opts opts;
};
