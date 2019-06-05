/**
 * Zero Copy Packet Processing
 * xProbe IPFIX exporter
 *
 * MASTER'S THESIS
 * FIT VUT BRNO 2019
 * @author Bc. Ondrej Ploteny <xplote01@stud.fit.vutbr.cz>
 *
 * @file: hash.c
 * @brief This file contains source code of flow cache.
 * Flow cache mainatains an aggregated information about flows, called flow record. It is implemented as hash table,
 * where index is given by hash value of flow key and flow records are stored in list.
 *
 * The source code is inspired by ipt_NETFLOW linux kernel module and Cisco joy
 * https://github.com/aabc/ipt-netflow
 * https://github.com/cisco/joy
 *
 * created on 2.3.2019
 */



#ifndef HASH_H
#define HASH_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>


/**
 *
 * Constants
 *
 */
#define MAX_TTL 255

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#define NETFLOW_STAT_INC(c, counter) (c->stats.counter++)
#define NETFLOW_STAT_DEC(c, counter) (c->stats.counter--)
#define NETFLOW_STAT_ADD(c, counter, x) (c->stats.counter += (x))

#define RECORD_STAT_INC(r, counter) (r->counter++)
#define RECORD_STAT_ADD(r, counter, x) (r->counter += (x))
#define RECORD_STAT_OR(r, counter, x) (r->counter += (x))

/**
 * from linux/if_ether.h
 */
#define ETH_P_IP    0x0800        /* Internet Protocol packet	*/
#define ETH_P_IPV6    0x86DD        /* IPv6 		*/


#define flow_key_hash_mask (1<<16)
#define FLOW_RECORD_LIST_LEN (flow_key_hash_mask - 1)

/*
 * default and maximum number of packets on which to report
 * lengths/times (actual value configurable on command line)
 */
#define MAX_NUM_PKT_LEN 200


/** ETTA Spec defiintions for feature readiness */
#define ETTA_MIN_OCTETS 4000

/**
 * The maximum number of IP ID fields that will be
 * reported for a single flow.
 */
#define MAX_NUM_IP_ID 50


/**
 * 
 * Flow key is 5tuple represents a flow identification.
 * This id includes Source and Destination addresses, port numbers and L4 protocol that have been used
 * 
 */
typedef struct _flow_key {
    union {
        struct in_addr v4_sa;
        struct in6_addr v6_sa;
    } sa;
    union {
        struct in_addr v4_da;
        struct in6_addr v6_da;
    } da;
    uint16_t sp;
    uint16_t dp;
    uint8_t prot;
} flow_key_t;

/**
 *
 * flocap_stats holds high-level statistics about packets and flow
 * records, for use in accounting and troubleshooting
 *
 */
typedef struct _flocap_stats {
    uint32_t num_packets;          /**<< number of process packets within hash table **/
    uint32_t num_bytes;            /**<< number of bytes of process frames **/
    uint32_t num_records_in_table; /**<< current number of records in table **/
    uint32_t num_records_output;   /**<< total number of flow records have been written to output **/
    uint32_t malloc_fail;          /**<< record malloc fail **/
    uint32_t l3_proto_unknwn;      /**<< unknown ethernet frame type, only IPv4, IPv6, Dot1Q support **/
    uint32_t l4_proto_unknwn;      /**<< unknown ethernet frame type, only IPv4, IPv6, Dot1Q support **/
    uint32_t num_drop;             /**<< number of dropped packet, parsing failed **/
    uint32_t htable_search;        /**<< number of searches performed = found + nonfound **/
    uint32_t htable_found;         /**<< number of htable matches **/
    uint32_t htable_notfound;      /**<< number of htable misses, new records must be create **/
} flocap_stats_t;


typedef struct _ip_info {
    uint8_t ttl;              /**<< Smallest IP TTL in flow */
    uint8_t num_id;           /**<< Number of IP ids */
    uint16_t id[MAX_NUM_IP_ID];     /**<< Array of IP ids in flow */
} ip_info_t;


typedef uint16_t histogram_t[256];

typedef struct _payload_stats {
    uint64_t data_len;    /**<< packet data length*/
    struct timeval pkt_time;
} payload_stats_t;


typedef struct _flow_record {
    flow_key_t key;               /**<< identifies flow by 5-tuple          */
    uint32_t key_hash;            /**<< hash of the 5-tuple key             */

    uint32_t ip_type;             /**<< IPv4 or IPv6 encoding type          */
    uint64_t num_pkts;            /**<< number of packets                   */
    uint64_t num_bytes;           /**<< number of bytes in frames, including all headers (L2, L3, L4) */

    uint64_t num_payload_bytes;   /**<< number of bytes of application data */

    uint8_t op;                  /**<< number of packets (w/nonzero data), index to payload array  */
    payload_stats_t payload[MAX_NUM_PKT_LEN]; /**<< Info about payload **/

    histogram_t byte_count;             /**<< number of occurences of each byte   */

    uint8_t tcp_flags;              /**<< all TCP flags within communication, OR function */
    uint32_t tcp_options;           /**<< all TCP options within communication */

    struct timeval start;                 /**<< communication start time  */
    struct timeval end;                   /**<< communication end time */

    uint32_t options;                /**<< IPv4(16) and IPv6(32) Options, OR function*/
    ip_info_t ip;

    struct _flow_record *next;             /**<< next record in flow_record_list     */
    struct _flow_record *prev;             /**<< previous record in flow_record_list */
    struct _flow_record *time_prev;        /**<< previous record in chronological list */
    struct _flow_record *time_next;        /**<< next record in chronological list     */

} flow_record_t;


/**
 * A flow_record_list is a handle for a linked list of flow_records;
 * an array of such lists is used as a flow cache
 */

typedef flow_record_t *flow_record_list;
typedef flow_record_t *flow_record_chrono_list;

typedef struct _hash_table {

    unsigned int ctx_id;            /**<< context identificator a.k.a hash table id */

    struct timeval last_stats_output_time;

    pthread_spinlock_t rwlock;

    flocap_stats_t stats;
    flocap_stats_t last_stats;

    uint32_t l3proto; /**<< IPv4 or IPv6 family **/

    flow_record_chrono_list first_flow_record;
    flow_record_chrono_list last_flow_record;
    flow_record_list flow_cache_array[FLOW_RECORD_LIST_LEN];

} hash_table_t;


/**
 *
 * Function declaration
 *
 */
void hash_table_init(hash_table_t *ctx, unsigned int table_id);

void hash_table_destroy(hash_table_t *ctx);


flow_record_t *get_record_by_flow_key(hash_table_t *ctx, const flow_key_t *key);

void flow_record_delete(hash_table_t *ctx, flow_record_t *r);

void print_htable_info(hash_table_t *ctx);

void print_flow_key(flow_key_t *k);

void print_flow_record(flow_record_t *r);

void flow_record_update_byte_histogram(flow_record_t *f, const void *x, uint16_t len);

void export_all_tables(hash_table_t **tables, uint32_t len);


#endif /* HASH_H */