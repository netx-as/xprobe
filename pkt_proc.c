/**
 * Zero Copy Packet Processing
 * xProbe IPFIX exporter
 *
 * MASTER'S THESIS
 * FIT VUT BRNO 2019
 * @author Bc. Ondrej Ploteny <xplote01@stud.fit.vutbr.cz>
 *
 * @file: pkt_proc.c
 * @brief This file contains source code of packet parsing.
 * Packet data are given by socket and packet parsing extract flow key and flow record attributes
 *
 * The source code is inspired by ipt_NETFLOW linux kernel module and Cisco joy, taken section are signed
 * https://github.com/aabc/ipt-netflow
 * https://github.com/cisco/joy
 *
 * created on 2.3.2019
 */


#include <stdio.h>
#include <sys/time.h>
#include "pkt_proc.h"
//#include <linux/types.h>



/**
 * @brief Find out if nexthdr is a well-known extension header or a protocol
 * @param nexthdr Next header field value
 * @return true if nexhdr value coresponds to well-known extension, false otherwise
 */
bool ipv6_ext_hdr(uint8_t nexthdr) {
    /*
     * find out if nexthdr is an extension header or a protocol
     */
    return (nexthdr == NEXTHDR_HOP) ||
           (nexthdr == NEXTHDR_ROUTING) ||
           (nexthdr == NEXTHDR_FRAGMENT) ||
           (nexthdr == NEXTHDR_AUTH) ||
           (nexthdr == NEXTHDR_NONE) ||
           (nexthdr == NEXTHDR_DEST);
}


/**
 * @brief This function return size of ether header.
 * It is used as IP header offset.
 *
 * @param[in] frame Pointer to ether frame begin
 * @param[out] real_ip_type fill IPv4 or IPv address family
 * @return size of ethernet header in B
 */
static uint16_t get_eth_hdr_len(const uint8_t *frame, uint16_t *real_ip_type) {
    uint16_t ether_type = 0;
    uint16_t vlan_ether_type = 0;
    uint16_t vlan2_ether_type = 0;
    uint16_t eth_hdr_len = ETHERNET_HDR_LEN;


    ether_type = ntohs(*(const uint16_t *) (frame + 12));

    switch (ether_type) {
        case ETH_P_IP:
        case ETH_P_IPV6:
            *real_ip_type = ether_type;
            break;

        case ETH_P_8021Q:
        case ETH_P_8021AD:
            //Offset to get VLAN_TYPE
            vlan_ether_type = ntohs(*(const uint16_t *) (frame + ETHERNET_HDR_LEN + 2));
            switch (vlan_ether_type) {
                case ETH_P_IP:
                case ETH_P_IPV6:
                    eth_hdr_len = ETHERNET_HDR_LEN + DOT1Q_HDR_LEN;
                    *real_ip_type = vlan_ether_type;
                    break;
                case ETH_P_8021Q:
                case ETH_P_8021AD:
                    //Offset to get VLAN_TYPE
                    vlan2_ether_type = ntohs(*(const uint16_t *) (frame + ETHERNET_HDR_LEN + DOT1Q_HDR_LEN + 2));
                    switch (vlan2_ether_type) {
                        case ETH_P_IP:
                        case ETH_P_IPV6:

                            eth_hdr_len = ETHERNET_HDR_LEN + DOT1Q_HDR_LEN + DOT1Q_HDR_LEN;
                            *real_ip_type = vlan2_ether_type;
                            break;
                        default :
                            return eth_hdr_len + (uint16_t) 2;
                    }
                    break;
                default :
                    return eth_hdr_len + (uint16_t) 2;
            }
            break;
        default:
            return eth_hdr_len;
    }

    return eth_hdr_len; /** ETHERNET_HDR_LEN **/
}

/**
 * @brief Compare two 8bit value, if x is smaller than min, the x is new min
 * @param[in,out] min
 * @param[in] x
 * @return none
 */
static inline void update_minimum(uint8_t *min, const uint8_t *x) {
    if (*min > *x)
        *min = *x;
}

/**
 * this section is taken from ipt_NETFLOW linux kernel module
 * https://github.com/aabc/ipt-netflow
 */

#define SetXBit(x) (0x8000 >> (x))

static inline uint16_t observed_hdrs(const uint8_t currenthdr) {
    switch (currenthdr) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            /* For speed, in case switch is not optimized. */
            return 0;
        case IPPROTO_DSTOPTS:
            return SetXBit(0);
        case IPPROTO_HOPOPTS:
            return SetXBit(1);
        case IPPROTO_ROUTING:
            return SetXBit(5);
        case IPPROTO_MH:
            return SetXBit(12);
        case IPPROTO_ESP:
            return SetXBit(13);
        case IPPROTO_AH:
            return SetXBit(14);
        case IPPROTO_COMP:
            return SetXBit(15);
        case IPPROTO_FRAGMENT: /* Handled elsewhere. */
            /* Next is known headers. */
        case IPPROTO_ICMPV6:
        case IPPROTO_UDPLITE:
        case IPPROTO_IPIP:
        case IPPROTO_PIM:
        case IPPROTO_GRE:
        case IPPROTO_SCTP:
        case IPPROTO_DCCP:
            return 0;
    }
    return SetXBit(3); /* Unknown header. */
}

/* http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml */
static const uint8_t ip4_opt_table[] = {
        [7]    = 0,    /* RR */ /* parsed manually because of 0 */
        [134]    = 1,    /* CIPSO */
        [133]    = 2,    /* E-SEC */
        [68]    = 3,    /* TS */
        [131]    = 4,    /* LSR */
        [130]    = 5,    /* SEC */
        [1]    = 6,    /* NOP */
        [0]    = 7,    /* EOOL */
        [15]    = 8,    /* ENCODE */
        [142]    = 9,    /* VISA */
        [205]    = 10,    /* FINN */
        [12]    = 11,    /* MTUR */
        [11]    = 12,    /* MTUP */
        [10]    = 13,    /* ZSU */
        [137]    = 14,    /* SSR */
        [136]    = 15,    /* SID */
        [151]    = 16,    /* DPS */
        [150]    = 17,    /* NSAPA */
        [149]    = 18,    /* SDB */
        [147]    = 19,    /* ADDEXT */
        [148]    = 20,    /* RTRALT */
        [82]    = 21,    /* TR */
        [145]    = 22,    /* EIP */
        [144]    = 23,    /* IMITD */
        [30]    = 25,    /* EXP */
        [94]    = 25,    /* EXP */
        [158]    = 25,    /* EXP */
        [222]    = 25,    /* EXP */
        [25]    = 30,    /* QS */
        [152]    = 31,    /* UMP */
};

static inline uint32_t ip4_options(const u_int8_t *p, const unsigned int optsize) {
    uint32_t ret = 0;
    unsigned int i;

    for (i = 0; likely(i < optsize);) {
        u_int8_t op = p[i++];

        if (op == 7) /* RR: bit 0 */
            ret |= 1;
        else if (likely(op < ARRAY_SIZE(ip4_opt_table))) {
            /* Btw, IANA doc is messed up in a crazy way:
             *   http://www.ietf.org/mail-archive/web/ipfix/current/msg06008.html (2011)
             * I decided to follow IANA _text_ description from
             *   http://www.iana.org/assignments/ipfix/ipfix.xhtml (2013-09-18)
             *
             * Set proper bit for htonl later. */
            if (ip4_opt_table[op])
                ret |= 1 << (32 - ip4_opt_table[op]);
        }
        if (likely(i >= optsize || op == 0))
            break;
        else if (unlikely(op == 1))
            continue;
        else if (unlikely(p[i] < 2))
            break;
        else
            i += p[i] - 1;
    }
    return ret;
}


/* List of options: http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml */
static inline uint32_t get_tcp_options(const uint8_t *tcp_start, const uint16_t tcp_hdr_len) {
    const uint8_t *p;
    uint32_t ret;
    unsigned int i;

    const uint16_t optsize = tcp_hdr_len - TCP_HDR_MIN_LENGTH;


    p = tcp_start + TCP_HDR_MIN_LENGTH;
    if (unlikely(!p))
        return 0;
    ret = 0;
    for (i = 0; likely(i < optsize);) {
        u_int8_t opt = p[i++];

        if (likely(opt < 32)) {
            /* IANA doc is messed up, see above. */
            ret |= 1 << (32 - opt);
        }
        if (likely(i >= optsize || opt == 0))
            break;
        else if (unlikely(opt == 1))
            continue;
        else if (unlikely(p[i] < 2)) /* "silly options" */
            break;
        else
            i += p[i] - 1;
    }
    return ret;
}

/**
 * END OF TAKEN SECTION
 **/

/**
 * @brief This function parses raw packet, decapsulates all headers and fill in flow key
 * @param[in,out] ctx Context of hash table
 * @param[in] frame Pointer to raw packet data
 * @param frame_len Raw data length
 * @param[in,out] key Flow key, where key will be stored after parse
 */
void frame_parser(hash_table_t *ctx, const uint8_t *frame, const uint64_t frame_len, flow_key_t *key) {
    /** L2 variables **/
    uint16_t eth_hdr_len = 0;
    uint16_t ether_type = 0;

    /** L3 variables **/
    uint16_t ip_len = 0;
    uint16_t ip_hdr_len = 0;
    struct iphdr *ip = NULL;
    struct ipv6hdr *ipv6 = NULL;
    uint8_t curr_TTL = 0;
    uint16_t curr_ip_id = 0;
    int options = 0;

    uint8_t ipv6_ext_hdrs = 0;
    unsigned int fragment = 0;

    /** L4 variables **/
    uint8_t *transport_start = NULL;
    uint16_t transport_len = 0;
    uint16_t transport_hdr_len = 0;
    uint8_t tcp_flags = 0;
    uint32_t tcp_options = 0;

    /** Payload **/
    uint16_t payload_len = 0;
    uint8_t *payload_start = NULL;


    flow_record_t *record = NULL;


    if (unlikely(!ctx)) {
        NETFLOW_STAT_INC(ctx, malloc_fail);
        return;
    }

    if (unlikely(!frame)) {
        NETFLOW_STAT_INC(ctx, malloc_fail);
        return;
    }

    if (unlikely(!key)) {
        NETFLOW_STAT_INC(ctx, malloc_fail);
        return;
    }

    pthread_spin_lock(&ctx->rwlock);
    NETFLOW_STAT_INC(ctx, num_packets);
    NETFLOW_STAT_ADD(ctx, num_bytes, frame_len);


    struct timeval now;
    gettimeofday(&now, NULL);

    /** reset key */
    memset(key, 0, sizeof(flow_key_t));

    /**
     * Parsing L2 header
     */
    eth_hdr_len = get_eth_hdr_len(frame, &ether_type);


    /**
     * Parsing L3 header
     * expecting parsing ipv4 header rather than ipv6
     */
    if (likely(is_ipv4(ether_type))) {
        /**
         * IPV4 packet processing
         */
        ctx->l3proto = ETH_P_IP;

        ip = (struct iphdr *) (frame + eth_hdr_len);
        ip_hdr_len = ip_hdr_length(ip);
        ip_len = ntohs(ip->tot_len);
        curr_TTL = ip->ttl;
        curr_ip_id = ntohs(ip->id);

        transport_len = ip_len - ip_hdr_len;
        transport_start = (uint8_t *) ip + ip_hdr_len;

        if (ntohs(ip->tot_len) < IPV4_HDR_LENGTH) {
            fprintf(stderr, "Malformed IP packet");
            NETFLOW_STAT_INC(ctx, num_drop);
            pthread_spin_unlock(&ctx->rwlock);
            return;
        }

        memcpy(&key->sa.v4_sa, &ip->saddr, sizeof(uint32_t));
        memcpy(&key->da.v4_da, &ip->daddr, sizeof(uint32_t));


        if (unlikely(ip_hdr_len > IPV4_HDR_LENGTH)) {
            const uint8_t *op;
            unsigned int optsize = ip_hdr_len - IPV4_HDR_LENGTH;

            op = (uint8_t *) ip + IPV4_HDR_LENGTH;
            if (likely(op))
                options = ip4_options(op, optsize);
        }

        if (ip_fragment_offset(ip) == 0) {
            /* fill out IP-specific fields of flow key, plus proto selector */
            key->prot = ip->protocol; /** UDP, TCP or ICMP **/

        } else {
            /*
             * select IP processing, since we don't have a TCP or UDP header
             */
            key->prot = IPPROTO_IP;
        }
    } else if (is_ipv6(ether_type)) {

        /**
         * IPV6 packet processing
         */
        ctx->l3proto = ETH_P_IPV6;

        ipv6 = (struct ipv6hdr *) (frame + eth_hdr_len);
        ip_len = ntohs(ipv6->payload_len);
        curr_TTL = ipv6->hop_limit;

        if (frame_len < IPV6_HDR_LENGTH) {
            NETFLOW_STAT_INC(ctx, num_drop);
            pthread_spin_unlock(&ctx->rwlock);
            return;
        }

        memcpy(&key->sa.v6_sa, &ipv6->saddr, sizeof(uint32_t) * 4);
        memcpy(&key->da.v6_da, &ipv6->daddr, sizeof(uint32_t) * 4);

        unsigned int offset = IPV6_HDR_LENGTH;

        uint8_t currenthdr = ipv6->nexthdr;


        while (currenthdr != NEXTHDR_NONE && ipv6_ext_hdr(currenthdr)) {
            const struct ipv6_opt_hdr *hp;
            unsigned int hdrlen = 0;

            options |= observed_hdrs(currenthdr);

            hp = (struct ipv6_opt_hdr *) ((uint8_t *) ipv6 + offset);

            if (hp == NULL) {
                /* We have src/dst, so must account something. */
                key->prot = currenthdr;
                fragment = 3;
                break;
            }

            switch (currenthdr) {
                case IPPROTO_FRAGMENT: {
                    const struct frag_hdr *fh;
                    fh = (struct frag_hdr *) (((uint8_t *) ipv6) + offset);
                    if (fh == NULL) {
                        key->prot = currenthdr;
                        fragment = 2;
                        break;
                    }
                    fragment = 1;
#define FRA0 SetXBit(4) /* Fragment header - first fragment */
#define FRA1 SetXBit(6) /* Fragmentation header - not first fragment */
                    options |= (ntohs(fh->frag_off) & 0xFFF8) ? FRA1 : FRA0;
                    hdrlen = 8;
                    break;
                }
                case IPPROTO_AH: {
                    struct ip_auth_hdr _ahdr, *ap;
                    ap = (struct ip_auth_hdr *) (((uint8_t *) ipv6) + offset);
                    hdrlen = (ap->hdrlen + 2) << 2;
                    break;
                }
                case IPPROTO_ESP:
                    /* After this header everything is encrypted. */
                    key->prot = currenthdr;
                    break;
                default:
                    hdrlen = ipv6_optlen(hp);
            }
            currenthdr = hp->nexthdr;
            offset += hdrlen;
        }

        transport_start = ((uint8_t *) ipv6) + offset;
        transport_len = ip_len;
        key->prot = ipv6->nexthdr;
    } else {
        NETFLOW_STAT_INC(ctx, l3_proto_unknwn);
        NETFLOW_STAT_INC(ctx, num_drop);
        pthread_spin_unlock(&ctx->rwlock);
        return;
    }


    switch (key->prot) {
        case IPPROTO_TCP: {
            struct tcphdr *hp;


            if (likely(hp = (struct tcphdr *) transport_start)) {
                key->sp = hp->source;
                key->dp = hp->dest;

                tcp_flags = (u_int8_t) (ntohl(tcp_flag_word(hp)) >> 16);


                transport_hdr_len = tcp_hdr_length(hp);
                payload_len = transport_len - transport_hdr_len;
                payload_start = transport_start + transport_hdr_len;



                /** check if some TCP option has been set **/
                if (unlikely(transport_hdr_len > 20)) {
                    tcp_options = get_tcp_options((uint8_t *) hp, transport_hdr_len);
                }

                record = get_record_by_flow_key(ctx, key);
                if (unlikely(!record)) {
                    fprintf(stderr, "Couldn't allocate a new record structure!");
                    NETFLOW_STAT_INC(ctx, malloc_fail);
                    NETFLOW_STAT_INC(ctx, num_drop);
                    return;
                }
                record->tcp_flags |= tcp_flags;
                record->tcp_options |= tcp_options;
            }
            break;
        }
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
        case IPPROTO_SCTP: {
            struct udphdr *hp;

            if (likely(hp = (struct udphdr *) transport_start)) {
                key->sp = hp->source;
                key->dp = hp->dest;
            }

            transport_hdr_len = 8;
            payload_len = transport_len - transport_hdr_len;
            payload_start = transport_start + transport_hdr_len;


            record = get_record_by_flow_key(ctx, key);
            if (unlikely(!record)) {
                fprintf(stderr, "Couldn't allocate a new record structure!");
                NETFLOW_STAT_INC(ctx, malloc_fail);
                NETFLOW_STAT_INC(ctx, num_drop);
                pthread_spin_unlock(&ctx->rwlock);
                return;
            }

            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr *ic;
            if (likely(ic = (struct icmphdr *) transport_start)) {
                key->dp = htons((ic->type << 8) | ic->code);
            }

            record = get_record_by_flow_key(ctx, key);
            if (unlikely(!record)) {
                fprintf(stderr, "Couldn't allocate a new record structure!");
                NETFLOW_STAT_INC(ctx, malloc_fail);
                NETFLOW_STAT_INC(ctx, num_drop);
                pthread_spin_unlock(&ctx->rwlock);
                return;
            }
            transport_hdr_len = 8;

            payload_len = transport_len - transport_hdr_len;
            payload_start = transport_start + transport_hdr_len;

//                if (record->op < MAX_NUM_PKT_LEN) {
//
//                    record->pkt_len[record->op] = payload_len;
//                    memcpy(&record->pkt_time[record->op], &now, sizeof(struct timeval));
//                    record->op++;
//                }
//                record->ob += payload_len;
//                record->num_pkts++;

            break;
        }
        case IPPROTO_ICMPV6: {
            struct icmp6hdr *ic;
            transport_hdr_len = 4;

            if (likely(ic = (struct icmp6hdr *) transport_start)) {
                key->dp = htons((ic->icmp6_type << 8) | ic->icmp6_code);
            }

            record = get_record_by_flow_key(ctx, key);
            if (unlikely(!record)) {
                fprintf(stderr, "Couldn't allocate a new record structure!");
                NETFLOW_STAT_INC(ctx, malloc_fail);
                NETFLOW_STAT_INC(ctx, num_drop);
                pthread_spin_unlock(&ctx->rwlock);
                return;
            }

            payload_len = transport_len - transport_hdr_len;

            payload_start = transport_start + transport_hdr_len;

            break;
        }
        case IPPROTO_IGMP: {
            struct igmphdr *hp;

            if (likely(hp = (struct igmphdr *) transport_start)) {
                key->dp = htons((hp->type << 8) | hp->code);
            }
            payload_len = transport_len - transport_hdr_len;
            payload_start = transport_start + transport_hdr_len;

            break;
        }
        default: {
            NETFLOW_STAT_INC(ctx, l4_proto_unknwn);
            break;
        }
    }

    if (unlikely(!record)) {
        NETFLOW_STAT_INC(ctx, malloc_fail);
        NETFLOW_STAT_INC(ctx, num_drop);
        pthread_spin_unlock(&ctx->rwlock);
        return;
    }

    /** 256 packets payload can be stored */
    uint8_t curr_pkt = record->op;

    if (curr_pkt < MAX_NUM_PKT_LEN) {
        record->payload[curr_pkt].data_len = payload_len;
        memcpy(&record->payload[curr_pkt].pkt_time, &now, sizeof(struct timeval));
        RECORD_STAT_INC(record, op);
        flow_record_update_byte_histogram(record, payload_start, payload_len);
        RECORD_STAT_ADD(record, num_payload_bytes, payload_len);
    }

    if (key->prot == IPPROTO_TCP)
        record->tcp_options |= tcp_options;

    /** update flow record timestamps */
    if (timerisset(&record->start)) {
        /** start is set */
        memcpy(&record->end, &now, sizeof(struct timeval));
    } else {
        memcpy(&record->end, &now, sizeof(struct timeval));
        memcpy(&record->start, &now, sizeof(struct timeval));
    }

    record->options |= options;
    update_minimum(&record->ip.ttl, &curr_TTL);


    if (is_ipv4(record->ip_type) && record->ip.num_id < MAX_NUM_IP_ID) {
        record->ip.id[record->ip.num_id] = curr_ip_id;
        RECORD_STAT_INC(record, ip.num_id);
    }

    RECORD_STAT_OR(record, options, options);
    RECORD_STAT_INC(record, num_pkts);
    RECORD_STAT_ADD(record, num_bytes, frame_len);

    pthread_spin_unlock(&ctx->rwlock);

}
