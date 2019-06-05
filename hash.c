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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include <limits.h>
#include <math.h>
#include <errno.h>
#include <sys/time.h>
#include <netinet/in.h>
#include "murmur3.h"


static uint32_t hash_seed;
FILE *fp;


static inline uint32_t __hash_netflow(const flow_key_t *key) {
    return murmur3(key, sizeof(flow_key_t), hash_seed);
}

/**
 * @brief Compute a hash from flow_key
 * @param[in] key Flow key to hash
 * @return 32-bits hash value
 */
static inline uint32_t flow_key_hash(const flow_key_t *key) {
    return (__hash_netflow(key) % FLOW_RECORD_LIST_LEN);
}


/**
 * @brief Initialize the flow capture statistics timer.
 * @param[out] ctx Context of hash table
 * @return none
 */
void flocap_stats_timer_init(hash_table_t *ctx) {
    struct timeval now;
    gettimeofday(&now, NULL);
    ctx->last_stats_output_time = now;
}


/**
 * @brief Initialize the flow_record_list.
 * @param[in,out] ctx Context of hash table
 * @return none
 */
void flow_record_list_init(hash_table_t *ctx) {
    ctx->first_flow_record = ctx->last_flow_record = NULL;
    memset(ctx->flow_cache_array, 0x00, sizeof(ctx->flow_cache_array));
}


/**
 * @brief Update the byte count for the flow record.
 * @param[out] f Flow record
 * @param[in] x pointer to data
 * @param[in] len Length of the data (in bytes)
 * @return none
 */
void flow_record_update_byte_histogram(flow_record_t *f, const void *x, const uint16_t len) {
    const uint8_t *data = x;
    uint32_t current_count = f->num_payload_bytes;
    uint16_t i;
    uint16_t *bytes = &f->byte_count[0];


    if (unlikely(data == NULL))
        return;

    if (current_count < ETTA_MIN_OCTETS) {
        for (i = 0; i < len; ++i) {
            bytes[data[i]]++;
            current_count++;
            if (current_count >= ETTA_MIN_OCTETS) {
                break;
            }
        }
    }
}

void hash_table_init(hash_table_t *ctx, unsigned int table_id) {

    ctx->ctx_id = table_id;

    memset(&ctx->stats, 0, sizeof(flocap_stats_t));
    memset(&ctx->last_stats, 0, sizeof(flocap_stats_t));

    ctx->l3proto = 0;

    if (table_id == 0) {
        srand(time(0));
        hash_seed = (uint32_t) rand();

    }

    pthread_spin_init(&ctx->rwlock, PTHREAD_PROCESS_SHARED);

    flow_record_list_init(ctx);
    flocap_stats_timer_init(ctx);
}


/**
 * @brief Destroy all records in flow cache
 * @param[in,out] ctx Context of hash table
 * @return none
 */
void flow_record_list_free(hash_table_t *ctx) {
    flow_record_t *record = NULL;
    flow_record_t *tmp = NULL;
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < FLOW_RECORD_LIST_LEN; ++i) {
        record = ctx->flow_cache_array[i];
        while (record != NULL) {
            tmp = record->next;
            flow_record_delete(ctx, record);
            record = tmp;
            count++;
        }
        ctx->flow_cache_array[i] = NULL;
    }
    ctx->first_flow_record = NULL;
    ctx->last_flow_record = NULL;
}


void hash_table_destroy(hash_table_t *ctx) {
    flow_record_list_free(ctx);

    pthread_spin_destroy(&ctx->rwlock);
}

/**
 * @brief Initialize a flow_record
 * @param[in,out] ctx Contex of hash flow
 * @param[out] record Flow record
 * @param[in] key Flow key to be used for identifying the record
 * @return none
 */
static void flow_record_init(hash_table_t *ctx, flow_record_t *record, const flow_key_t *key, const uint32_t key_hash) {

    /* Increment the stats flow record count */
    NETFLOW_STAT_INC(ctx, num_records_in_table);

    /* Zero out the flow_record structure */
    memset(record, 0, sizeof(flow_record_t));

    /* Set the flow_key and TTL */
    record->ip.ttl = MAX_TTL;
    record->ip_type = ctx->l3proto;
    record->key_hash = key_hash;
    memcpy(&record->key, key, sizeof(flow_key_t));
}


/**
 * @brief Remove a flow record from the list
 * @param[in,out] head The list of records
 * @param r The flow_record that will be removed from the \p list
 * @return none
 */
static bool flow_record_remove_from_list(flow_record_list *head, flow_record_t *r) {

    if (unlikely(r == NULL)) {
        return false;
    }

    if (likely(r->prev != NULL)) {
        /** r is not first, it has some  predecessor
         *  r is pop out */
        r->prev->next = r->next;
        if (likely(r->next != NULL)) {
            /** r is not last, r has some successor
             *  r has to be skipped, r's predecessor is now a predecessor of r->next */
            r->next->prev = r->prev;
        }
    } else {

        /**
         * r is the first (or only) record within its flow_record_list, so
         * the head of the list must be set
         */
        if (unlikely(*head != r)) {
            fprintf(stderr, "error, the first record is not head\n");
            return false;
        }

        if (r->next == NULL) {
            /** the list is empty now */
            *head = NULL;
        } else {
            /** r has some successor, it is head of list now */
            *head = r->next;
            r->next->prev = NULL;
        }
    }

    return true;
}


/**
 * @brief Remove a flow record from the time list
 * @param[in,out] ctx Contex of hash flow
 * @param[in,out] record The pop Flow record
 * @return none
 */
static void flow_record_chrono_list_remove(hash_table_t *ctx, flow_record_t *record) {

    if (unlikely(record == NULL) || unlikely(ctx == NULL))
        return;

    if (record == ctx->first_flow_record) {
        ctx->first_flow_record = record->time_next;
    }
    if (record == ctx->last_flow_record) {
        ctx->last_flow_record = record->time_prev;
    }

    if (record->time_prev) {
        record->time_prev->time_next = record->time_next;
    }
    if (record->time_next) {
        record->time_next->time_prev = record->time_prev;
    }
}


/**
 * @brief Destroy a flow record
 * @param[in,out] ctx Contex of hash flow
 * @param[in,out] record The flow_record to delete
 * @return none
 */
void flow_record_delete(hash_table_t *ctx, flow_record_t *record) {
    if (unlikely(!record) || unlikely(!ctx))
        return;


    if (unlikely(!flow_record_remove_from_list(&ctx->flow_cache_array[record->key_hash], record))) {
        fprintf(stderr, "Record remove has failed\n", record);
        return;
    }

    NETFLOW_STAT_DEC(ctx, num_records_in_table);

    memset(record, 0, sizeof(flow_record_t));
    free(record);
    record = NULL;
}

/**
 * @brief Insert Flow record into time list
 * @param[in,out] ctx Contex of hash flow
 * @param[in] record The flow_record that will be appended to the list
 * @return none
 */
static void flow_record_append_chrono(hash_table_t *ctx, flow_record_t *record) {
    flow_record_t *last = ctx->last_flow_record;
    flow_record_t *first = ctx->first_flow_record;

    ctx->last_flow_record = record;

    if (first == NULL) {
        ctx->first_flow_record = record;
    } else {
        last->time_next = record;
        record->time_prev = last;
    }
}

/**
 * @brief Push given record before head, record is new head
 * @param[in,out] head The list of flow records
 * @param[in] record The flow_record that will be prepended to the list
 * @return none
 */
static void flow_record_list_prepend(flow_record_list *head,
                                     flow_record_t *record) {
    flow_record_t *tmp = *head;

    if (unlikely(tmp != NULL)) {
        tmp->prev = record;
        record->next = tmp;
    }
    *head = record;
}

/**
 * @brief Compare two flow_keys
 * @param[in] a The first flow_key
 * @param[in] b The second flow_key
 * @return 1 for equality, 0 for not
 */
static inline bool flow_key_is_eq(const flow_key_t *a, const flow_key_t *b) {
    return (!memcmp(a, b, sizeof(flow_key_t)));
}

/**
 * @brief Check if the flow record is in time chart
 * @param[in] ctx Context of hash table
 * @param[in] record Flow_record
 * @return true if record is in chronology list, false if not
 */
static inline bool flow_record_is_in_chrono_list(hash_table_t *ctx, const flow_record_t *record) {
    if (likely(record->time_next) || likely(record->time_prev) || unlikely(record == ctx->first_flow_record)) {
        return true;
    }
    return false;
}


/**
 * @brief Find the flow record in list, if it exists
 * @param[in] list The list of flow_records to search
 * @param[in] key The flow_key used to identify the flow_record
 * @return Valid flow_record or NULL
 */
static flow_record_t *flow_record_list_find_record_by_key(const flow_record_list *list,
                                                          const flow_key_t *key) {
    flow_record_t *record = *list;
    if (unlikely(!key))
        return NULL;

    /* Find a record matching the flow key, if it exists */
    while (record != NULL && !flow_key_is_eq(key, &record->key)) {
        record = record->next;
    }
    return record;
}

/**
 * @brief Compute hash and lookup in flow cache, return flow record if found
 * @param[in,out] ctx Context of hash table
 * @param[in] key The flow_key to use for lookup of flow record
 * @return NULL if expired or could not create or retrieve record
 */
flow_record_t *get_record_by_flow_key(hash_table_t *ctx, const flow_key_t *key) {
    flow_record_t *record;
    uint32_t hash_key;

    /** Make a hash from key and search in flow cache */
    hash_key = flow_key_hash(key);
    NETFLOW_STAT_INC(ctx, htable_search);
    record = flow_record_list_find_record_by_key(&ctx->flow_cache_array[hash_key], key);

    if (record != NULL) {
        NETFLOW_STAT_INC(ctx, htable_found);
        return record;
    } else {
        NETFLOW_STAT_INC(ctx, htable_notfound);
    }

    /** allocate and initialize a new flow record */
    record = calloc(1, sizeof(flow_record_t));

    if (unlikely(!record)) {
        fprintf(stderr, "Allocation memory for flow record failed");
        NETFLOW_STAT_INC(ctx, malloc_fail);
        return NULL;
    }

    flow_record_init(ctx, record, key, hash_key);

    /** enter record into flow cache */
    flow_record_list_prepend(&ctx->flow_cache_array[hash_key], record);
    flow_record_append_chrono(ctx, record);

    return record;
}

void print_flow_record(flow_record_t *r)
{
    int i,j;
    fprintf(fp, "========================================================================\n");

    print_flow_key(&r->key);
    /*fprintf(fp, "%20s: %u\n", "key_hash", r->key_hash);

    if (r->ip_type == ETH_P_IP)
        fprintf(fp, "%20s: IPv4\n", "ip_type");
    else if (r->ip_type == ETH_P_IPV6)
        fprintf(fp, "%20s: IPv6\n", "ip_type");

    fprintf(fp, "%20s: %u\n", "num_pkts", r->num_pkts);
    fprintf(fp, "%20s: %u\n", "num_bytes", r->num_bytes);
    fprintf(fp, "%20s: %u\n", "num_app_bytes", r->num_payload_bytes);

    fprintf(fp, "%20s: %ld.%06ld\n", "time start", r->start.tv_sec, r->start.tv_usec);
    fprintf(fp, "%20s: %ld.%06ld\n\n", "time end", r->end.tv_sec, r->end.tv_usec);


    payload_stats_t *payload = r->payload;
    for (i = 0; i < r->op; ++i) {
        fprintf(fp, "%18s %d: %u    %ld.%06ld\n", "data len ", i, payload->data_len, payload->pkt_time.tv_sec,
                payload->pkt_time.tv_usec);
        payload++;
    }

    fprintf(fp, "\n%20s: %u\n", "data_sum", r->num_payload_bytes);


    if (r->ip_type == ETH_P_IP) {
        fprintf(fp, "%20s: %u\n", "ip.num_id", r->ip.num_id);
        fprintf(fp, "%20s: %u\n", "min_ttl", r->ip.ttl);

        int num_id = r->ip.num_id;
        for (i = 0; i < num_id; ++i) {
            fprintf(fp, "%18s %d: %u\n", "id", i, r->ip.id[i]);


        }
    }

    fprintf(fp, "---------------------------Histogram------------------------------\n");
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 8; j++) {
            fprintf(fp, " %2x = %.1u  ", (i * 8) + j, r->byte_count[(i * 8) + j]);
        }
        fprintf(fp, "\n");                      // New line printed every 10th element
    }


    fprintf(fp, "========================================================================\n");
*/
}


void print_flow_key(flow_key_t *k) {
    char ipAddress[INET6_ADDRSTRLEN];

    uint64_t test = 0;

    fprintf(fp, "-----------------KEY-----------------\n");

    if (memcmp(&test, &k->sa.v6_sa.__in6_u.__u6_addr32[2], sizeof(uint64_t))) {
        inet_ntop(AF_INET6, &k->sa, ipAddress, INET6_ADDRSTRLEN);
        fprintf(fp, "%15s: %s\n", "SA", ipAddress);
        inet_ntop(AF_INET6, &k->da, ipAddress, INET6_ADDRSTRLEN);
        fprintf(fp, "%15s: %s\n", "DA", ipAddress);
    } else {
        inet_ntop(AF_INET, &k->sa.v4_sa, ipAddress, INET_ADDRSTRLEN);
        fprintf(fp, "%15s: %s\n", "SA", ipAddress);
        inet_ntop(AF_INET, &k->da.v4_da, ipAddress, INET_ADDRSTRLEN);
        fprintf(fp, "%15s: %s\n", "DA", ipAddress);
    }

    fprintf(fp, "%15s: %d\n", "source port", ntohs(k->sp));
    fprintf(fp, "%15s: %d\n", "desti port", ntohs(k->dp));
    fprintf(fp, "%15s: %d\n", "protocol", k->prot);
    fprintf(fp, "----------------------------------\n");

}

static void print_flow_cap_stats(flocap_stats_t *flocap) {
    fprintf(fp, "  %-22s %d\n", "num_packets:", flocap->num_packets);
    fprintf(fp, "  %-22s %d\n", "num_bytes:", flocap->num_bytes);
    fprintf(fp, "  %-22s %d\n", "num_records_in_table:", flocap->num_records_in_table);
    fprintf(fp, "  %-22s %d\n", "num_records_output:", flocap->num_records_output);
    fprintf(fp, "  %-22s %d\n", "malloc_fail:", flocap->malloc_fail);
    fprintf(fp, "  %-22s %d\n", "l3_proto_unknwn:", flocap->l3_proto_unknwn);
    fprintf(fp, "  %-22s %d\n", "l4_proto_unknwn:", flocap->l4_proto_unknwn);
    fprintf(fp, "  %-22s %d\n", "num_drop:", flocap->num_drop);
    fprintf(fp, "  %-22s %d\n", "htable_search:", flocap->htable_search);
    fprintf(fp, "  %-22s %d\n", "htable_found:", flocap->htable_found);
    fprintf(fp, "  %-22s %d\n", "htable_notfound:", flocap->htable_notfound);

}


void print_htable_info(hash_table_t *ctx) {
    fprintf(fp, "------------------------------\n");
    fprintf(fp, "Hash table %d\n", ctx->ctx_id);
    print_flow_cap_stats(&ctx->stats);
    fprintf(fp, "  %-22s %p\n", "first record:", ctx->first_flow_record);
    fprintf(fp, "  %-22s %ld.%06ld\n", "last exported:", ctx->last_stats_output_time.tv_sec,
            ctx->last_stats_output_time.tv_usec);

    fprintf(fp, "------------------------------\n");

}


void export_chrono_list(hash_table_t *ctx) {
    flow_record_t *r = ctx->first_flow_record;
    flow_record_t *tmp = NULL;

    while (r != NULL) {
        tmp = r->time_next;

        print_flow_record(r);
        flow_record_chrono_list_remove(ctx, r);
        flow_record_delete(ctx, r);
        r = tmp;
    }


}

void reset_stat(hash_table_t *ctx) {
    ctx->last_stats = ctx->stats;
    memset(&ctx->stats, 0, sizeof(ctx->stats));


}


void export_all_tables(hash_table_t **tables, uint32_t len) {
    uint64_t num_pkts = 0;
    uint32_t i;


    for (i = 0; i < len; ++i) {
        fprintf(fp, "===================================================\n");
        pthread_spin_lock(&(*tables)->rwlock);

        print_htable_info(*tables);

        num_pkts += (*tables)->stats.num_packets;

        export_chrono_list((*tables));

//        print_htable_info(*tables);

        reset_stat(*tables);
        flocap_stats_timer_init(*tables);

        pthread_spin_unlock(&(*tables)->rwlock);

        *tables++;
    }

    fprintf(fp, "---------------------------------------------------\n");
    fprintf(fp, "packet sum in tables: %lu\n", num_pkts);
    fprintf(fp, "===================================================\n");

}
