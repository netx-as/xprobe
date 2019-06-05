/**
 * Zero Copy Packet Processing
 * xProbe IPFIX exporter
 *
 * MASTER'S THESIS
 * FIT VUT BRNO 2019
 * @author Bc. Ondrej Ploteny <xplote01@stud.fit.vutbr.cz>
 *
 * @file: pkt_proc.h
 * @brief This file contains source code of packet parsing.
 * Flow cache mainatains an aggregated information about flows, called flow record. It is implemented as hash table,
 * where index is given by hash value of flow key and flow records are stored in list.
 *
 * The source code is inspired by ipt_NETFLOW linux kernel module and Cisco joy
 * https://github.com/aabc/ipt-netflow
 * https://github.com/cisco/joy
 *
 * created on 2.3.2019
 */

#ifndef HASH_TABLE_PKT_PROC_H
#define HASH_TABLE_PKT_PROC_H

#include "hash.h"

#include <netinet/in.h>
#include <endian.h>
#include <sys/time.h>

#include <linux/types.h>

#include <linux/if_ether.h>
#include <linux/if_arp.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/igmp.h>



/**
 * from net/ipv6.h
 * NextHeader field of IPv6 header
 */

#define NEXTHDR_HOP		0	/* Hop-by-hop option header. */
#define NEXTHDR_TCP		6	/* TCP segment. */
#define NEXTHDR_UDP		17	/* UDP message. */
#define NEXTHDR_IPV6		41	/* IPv6 in IPv6 */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define NEXTHDR_GRE		47	/* GRE header. */
#define NEXTHDR_ESP		50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH		51	/* Authentication header. */
#define NEXTHDR_ICMP		58	/* ICMP for IPv6. */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header. */
#define NEXTHDR_SCTP		132	/* SCTP message. */
#define NEXTHDR_MOBILITY	135	/* Mobility header. */


struct frag_hdr {
    __u8	nexthdr;
    __u8	reserved;
    __be16	frag_off;
    __be32	identification;
};


#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define DOT1Q_HDR_LEN 4

/** ethernet header */
#define ETHERNET_HDR_LEN 14
#define ETHERNET_ADR_LEN  6

/* IPv4 Header Length */
#define IPV4_HDR_LENGTH    20
#define IPV4_HDR_MAX_LENGTH (4 * 15)


/* IPv6 Header Length */
#define IPV6_HDR_LENGTH    40
#define IPV6_EXT_HDR_LEN    8

/** TCP Header Length */
#define TCP_HDR_MIN_LENGTH    20

#define CPU_IS_BIG_ENDIAN (__BYTE_ORDER == __BIG_ENDIAN)


/** Internet Protocol (IP) version four header */
#if CPU_IS_BIG_ENDIAN
#define IP_RF    0x8000 /* Reserved           */
#define IP_DF    0x4000 /* Don't Fragment     */
#define IP_MF    0x2000 /* More Fragments     */
#define IP_FOFF  0x1fff /* Fragment Offset    */

#define ip_is_fragment(ip) (htons((ip)->ip_flgoff) & (IP_MF | IP_FOFF))
#define ip_fragment_offset(ip) (htons((ip)->ip_flgoff) & IP_FOFF)

#define ip_hdr_length(ip) ((((ip)->ihl) & 0x0f)*4)
#define ip_version(ip)    (((ip)->version))

#else

#define IP_RF    0x0080 /* Reserved           */
#define IP_DF    0x0040 /* Don't Fragment     */
#define IP_MF    0x0020 /* More Fragments     */
#define IP_FOFF  0xff1f /* Fragment Offset    */

#define ip_is_fragment(ip) (((ip)->frag_off) & (IP_MF | IP_FOFF))
#define ip_fragment_offset(ip) ((ip)->frag_off & IP_FOFF)

#define ip_hdr_length(ip) (((ip)->ihl)* (uint16_t)4)
#define ip_version(ip)    ((ip)->version)
#endif

#define is_ipv4(r) (r == ETH_P_IP)
#define is_ipv6(r) (r == ETH_P_IPV6)

#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)

/** Transmission Control Protocol (TCP) header */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TCP_FLAGS   (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
#define tcp_hdr_length(h) (((h)->doff) * (uint16_t)4)

#define TCPHDR_MAXSIZE (4 * 15)


void frame_parser(hash_table_t *ctx, const uint8_t *frame, uint64_t frame_len, flow_key_t *key);


#endif //HASH_TABLE_PKT_PROC_H
