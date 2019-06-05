/**
 * Zero-copy packet processing
 * @file main.c
 * @author Ondřej Plotěný, VUT BRNO, <xplote01@stud.fit.vutbr.cz>
 * @date 22 May 2019
 * @brief This application capturing pacekts from interface via multiple AF_XDP sockets
 * Source code based on sample/bpf/xdpsock_user.c from vanilla kernel from Intel Corporation
 *
 */


#define _GNU_SOURCE


#include <asm/barrier.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/compiler.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "bpf/libbpf.h"
#include "bpf/xsk.h"
#include <bpf/bpf.h>

#include "hash.h"
//#include "pkt_proc.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define NUM_FRAMES (512 * 1024)
#define BATCH_SIZE 128


#define DEBUG_HEXDUMP 0
#define MAX_SOCKS 32

#define MAX_THREADS MAX_SOCKS

#define RX_RING_SIZE 8192
#define TX_RING_SIZE 256
#define FILL_RING_SIZE 8192
#define COMP_RING_SIZE 8192

#define is_first_thread(tid) (tid == 0)


typedef __u64 u64;
typedef __u32 u32;

static unsigned long prev_time;

static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static const char *opt_if = "";
static const char *opt_out = "test.txt";
static int opt_ifindex = 0;
static int opt_queue = 0;	/**<< index of NIC's queue **/
static int opt_poll = 1;	/**<< poll flag **/
static int opt_interval = 1;    /** stdout interval **/
static u32 opt_xdp_bind_flags = 0;
static uint32_t prog_id = 0;
static unsigned long long int rx_Gnpkts = 0;		/**<< Global RX packet counter **/
static int opt_nsocket = 1;


static int num_socks = 0;
struct xsk_socket_info *xsks[MAX_SOCKS];	/**<< XDP socket set */
extern FILE *fp;


pthread_barrier_t xdp_ready;	/**<< wait until all UMEMs and queues not ready **/
pthread_barrier_t xsks_ready;	/**<< wait until all sockets are not ready **/
pthread_mutex_t xsk_creation_mtx; /**<< used for sockets creation critical section, the first create eBPF **/

struct xsk_umem_info {
    struct xsk_ring_prod fq;    /**<< Filling queue **/
    struct xsk_ring_cons cq;    /**<< Completion queue **/
    struct xsk_umem *umem;      /**<< userspace memory **/
    void *buffer;
    u64 umem_size;	/**<< UMEM size in B **/
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;	/**<< RX buffer ring **/
    struct xsk_ring_prod tx;	/**<< TX buffer ring **/
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    unsigned long rx_npkts;    /**<< number of received packets, actual interval **/
    unsigned long tx_npkts;    /**<< number of send packets, actual interval **/
    unsigned long prev_rx_npkts;    /**<< number of received packets, before actual interval **/
    unsigned long prev_tx_npkts;    /**<< number of send packets, before actual interval **/
    unsigned long if_queue;     /**<< the id of queue **/
    hash_table_t *htable;
};

struct xProbe_info {
    pthread_t pt;
    pthread_t XDP_workers[MAX_SOCKS];
};


/**
 * @brief Input arguments of threads
 * Input arguments, represent input data of each threads
 *
 */
typedef struct _thread_input_t {
    uint32_t tid;
    unsigned int if_queue;
    struct xsk_socket_info **xsk;
} thread_input_t;

static unsigned long get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static void print_benchmark(bool running)
{
    const char *bench_str = "xprobe";

    printf("%s:%d %s ", opt_if, opt_queue, bench_str);
    if (opt_xdp_flags & XDP_FLAGS_SKB_MODE)
        printf("xdp-skb ");
    else if (opt_xdp_flags & XDP_FLAGS_DRV_MODE)
        printf("xdp-drv ");
    if (opt_xdp_flags & XDP_ZEROCOPY)
	printf("ZC ");
    else
        printf("	");

    if (opt_poll)
        printf("poll() ");

    if (running) {
        printf("running...");
        fflush(stdout);
    }
}

static void dump_stats(void)
{
    unsigned long long rx_pps_sum = 0;
    unsigned long now = get_nsecs();
    long dt = now - prev_time;
    int i;

    prev_time = now;
    printf("--------------------------\n");

    for (i = 0; i < num_socks && xsks[i]; i++)
    {
        char *fmt = "%-15s %'-11.0f %'-11lu\n";
        double rx_pps, tx_pps;

        rx_pps = (xsks[i]->rx_npkts - xsks[i]->prev_rx_npkts) *
                 1000000000. / dt;
        tx_pps = (xsks[i]->tx_npkts - xsks[i]->prev_tx_npkts) *
                 1000000000. / dt;

        printf("\n sock%d@", xsks[i]->if_queue);
        print_benchmark(false);
        printf("\n");

        printf("%-15s %-11s %-11s %-11.2f\n", "", "pps", "pkts",
               dt / 1000000000.);
        printf(fmt, "rx", rx_pps, xsks[i]->rx_npkts);
        printf(fmt, "tx", tx_pps, xsks[i]->tx_npkts);

        xsks[i]->prev_rx_npkts = xsks[i]->rx_npkts;
        xsks[i]->prev_tx_npkts = xsks[i]->tx_npkts;
        rx_pps_sum += rx_pps;
    }
    rx_Gnpkts += rx_pps_sum;

    printf("\t GLOBAL: rx_pps: %llu\t %llu\n", rx_pps_sum, rx_Gnpkts);
}


static void *poller(void *arg)
{
    (void)arg;

    fp=fopen(opt_out, "w");
    if(fp == NULL)
        exit(-1);

    hash_table_t *tables[MAX_SOCKS] = {0};

	int i; 
    for (i = 0; i < num_socks; ++i) {
        tables[i] = xsks[i]->htable;
    }

    for (;;) {
        sleep(opt_interval);

        export_all_tables(tables, num_socks);


        dump_stats();
    }
    fclose(fp);

    return NULL;
}

/**
 * This function unattache and remove eBPF from interface
 *
 * @return void
 */
static void remove_xdp_program(void)
{
    uint32_t curr_prog_id = 0;

    if (bpf_get_link_xdp_id(opt_ifindex, &curr_prog_id, opt_xdp_flags)) {
        printf("bpf_get_link_xdp_id failed\n");
        exit(EXIT_FAILURE);
    }
    if (prog_id == curr_prog_id)
        bpf_set_link_xdp_fd(opt_ifindex, -1, opt_xdp_flags);
    else if (!curr_prog_id)
        printf("couldn't find a prog id on a given interface\n");
    else
        printf("program on interface changed, not removing\n");
}
/**
 * This function destroy all alloc memory
 * @return none
 */
static void clean_memory()
{
    int i;
    struct xsk_umem *umem;
    hash_table_t *tab;

    for (i = 0; i < num_socks; ++i)
    {
        tab = xsks[i]->htable;

        if(tab)
        {
            hash_table_destroy(tab);
            free(tab);
        }

        umem = xsks[i]->umem->umem;

        if(xsks[i]->xsk)
            xsk_socket__delete(xsks[i]->xsk);

        if(umem)
            (void)xsk_umem__delete(umem);
    }

    if(fp)
        fclose(fp);

}


static void int_exit(int sig)
{
    (void)sig;
    dump_stats();
    clean_memory();
    remove_xdp_program();

    exit(EXIT_SUCCESS);
}

static void __exit_with_error(int error, const char *file, const char *func,
                              int line)
{
    fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
            line, error, strerror(error));
    dump_stats();

    clean_memory();

    remove_xdp_program();
    exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, \
						 __LINE__)


static void hex_dump(void *pkt, size_t length, u64 addr)
{
    const unsigned char *address = (unsigned char *)pkt;
    const unsigned char *line = address;
    size_t line_size = 32;
    unsigned char c;
    char buf[32];
    int i = 0;

    if (!DEBUG_HEXDUMP)
        return;

    sprintf(buf, "addr=%llu", addr);
    printf("length = %zu\n", length);
    printf("%s | ", buf);
    while (length-- > 0) {
        printf("%02X ", *address++);
        if (!(++i % line_size) || (length == 0 && i % line_size)) {
            if (length == 0) {
                while (i++ % line_size)
                    printf("__ ");
            }
            printf(" | ");	/* right close */
            while (line < address) {
                c = *line++;
                printf("%c", (c < 33 || c == 255) ? 0x2E : c);
            }
            printf("\n");
            if (length > 0)
                printf("%s | ", buf);
        }
    }
    printf("\n");
}

/**
 * This function create UMEM
 *
 * @param buffer, pointer to contiguous memory begin, where umem will be placed
 * @param size, buffer size (umem size)
 * @return pointer to xsk_umem_info represent UMEM
 */
static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size)
{
    struct xsk_umem_info *umem;	/**<< user-space memory array consist of frames **/
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
        exit_with_error(errno);

    struct xsk_umem_config usr_umem_config;
    usr_umem_config.comp_size = COMP_RING_SIZE;			/** size of Compl. ring, Not used **/
    usr_umem_config.fill_size = FILL_RING_SIZE;
    usr_umem_config.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;	/** packet buffer header size **/
    usr_umem_config.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;			/** packet buffer size **/

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &usr_umem_config);
    if (ret)
        exit_with_error(-ret);

    umem->buffer = buffer;
    umem->umem_size = size;
    return umem;
}

/**
 *
 * This function create a new socket with given configure
 *
 * @param umem	structure represent UMEM with fill and comp rings
 * @param if_queue_num interface queue descriptor
 * @return XDP socket
 */

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem, const unsigned int if_queue_num, const unsigned int tid)
{
    struct xsk_socket_config cfg;	/**<< socket configuration, ZC flag,... */
    struct xsk_socket_info *xsk;	/**<< pointer to new XDP socket */
    int ret = 0;
    uint32_t idx = 0; /**<< Fill queue iterator, [0-2047]*/
    int i = 0;

    xsk = calloc(1, sizeof(*xsk));
    if (!xsk)
        exit_with_error(errno);

    xsk->umem = umem;
    xsk->if_queue = if_queue_num;
    cfg.rx_size = RX_RING_SIZE;
    cfg.tx_size = TX_RING_SIZE;
    cfg.libbpf_flags = 0;
    cfg.xdp_flags = opt_xdp_flags;
    cfg.bind_flags = opt_xdp_bind_flags;

    /** Socket creation, first thread needs to load eBPF program so mutex is necessary to avoid attach fail  **/
    pthread_mutex_lock(&xsk_creation_mtx);
    ret = xsk_socket__create(&xsk->xsk, opt_if, xsk->if_queue, umem->umem, &xsk->rx, &xsk->tx, &cfg);
    if (ret)
        exit_with_error(-ret);
    pthread_mutex_unlock(&xsk_creation_mtx);

    /** first thread will register a eBPF identificator to global variable **/
    if(is_first_thread(tid))
    {
        /** Get eBPF program descriptor **/
        ret = bpf_get_link_xdp_id(opt_ifindex, &prog_id, opt_xdp_flags); /** default BPF program **/
        if (ret)
            exit_with_error(-ret);
    }


    /** wait for everyone **/
    pthread_barrier_wait(&xdp_ready);


    /** give all Fill desriptors **/
    ret = xsk_ring_prod__reserve(&xsk->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
        exit_with_error(-ret);

    for (i = 0;i < XSK_RING_PROD__DEFAULT_NUM_DESCS * XSK_UMEM__DEFAULT_FRAME_SIZE; i += XSK_UMEM__DEFAULT_FRAME_SIZE)
    {
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = i;
    }


    xsk_ring_prod__submit(&xsk->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);


    return xsk;
}

static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"queue", required_argument, 0, 'q'},
        {"poll", no_argument, 0, 'p'},
        {"xdp-skb", no_argument, 0, 'S'},
        {"xdp-native", no_argument, 0, 'N'},
        {"interval", required_argument, 0, 'n'},
        {"zero-copy", no_argument, 0, 'z'},
        {"copy", no_argument, 0, 'c'},
        {"thread", required_argument, 0, 't'},
        {"output", required_argument, 0, 'o'},
        {0, 0, 0, 0}
};

static void usage(const char *prog)
{
    const char *str =
            "  Usage: %s [OPTIONS]\n"
            "  Options:\n"
            "  -i, --interface=n	Run on interface n\n"
            "  -q, --queue=n	    Use queue n (default 0)\n"
            "  -p, --poll		    Use poll syscall\n"
            "  -S, --xdp-skb=n	    Use XDP skb-mod\n"
            "  -N, --xdp-native=n	Enfore XDP native mode\n"
            "  -n, --interval=n	    Specify statistics update interval (default 1 sec).\n"
            "  -z, --zero-copy      Force zero-copy mode.\n"
            "  -c, --copy           Force copy mode.\n"
            "  -t, --thread         Number of open queues. default 1\n"
            "  -o, --output         Output file name\n"
            "\n";
    fprintf(stderr, str, prog);
    exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
    int option_index, c;

    opterr = 0;

    for (;;) {
        c = getopt_long(argc, argv, "Fi:q:psSNn:czt:o:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'i':
                opt_if = optarg;
                break;
            case 'q':
                opt_queue = atoi(optarg);
                break;
            case 'p':
                opt_poll = 1;
                break;
            case 'S':
                opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
                opt_xdp_bind_flags |= XDP_COPY;
                break;
            case 'N':
                opt_xdp_flags |= XDP_FLAGS_DRV_MODE;
                break;
            case 'n':
                opt_interval = atoi(optarg);
                break;
            case 'z':
                opt_xdp_flags &= ~XDP_COPY;
                opt_xdp_bind_flags |= XDP_ZEROCOPY;
                break;
            case 'c':
                opt_xdp_bind_flags |= XDP_COPY;
                break;
            case 't':
                opt_nsocket = atoi(optarg);
                break;
            case 'F':
                opt_xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
                break;
            case 'o':
                opt_out = optarg;
                break;
            default:
                usage(basename(argv[0]));
        }
    }

    opt_ifindex = if_nametoindex(opt_if);
    if (!opt_ifindex) {
        fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
                opt_if);
        usage(basename(argv[0]));
    }

}


static void rx_processing(struct xsk_socket_info *xsk)
{
    unsigned int rcvd, i;
    u32 idx_rx = 0;
    u32 idx_fq = 0;
    int ret;
    flow_key_t key;


    rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
    if (!rcvd)
        return;

    ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);

    while (ret != rcvd) {
        if (ret < 0)
            exit_with_error(-ret);
        ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
    }


    for (i = 0; i < rcvd; i++)
    {
        u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
        uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

        frame_parser(xsk->htable, pkt, len, &key);

        //hex_dump(pkt, len, addr);
        /** return the chunk to kernel */
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = addr;
    }

    xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
    /** drop the packet */
    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk->rx_npkts += rcvd;
}

static void rx_sniff(struct xsk_socket_info *xsk)
{
    int ret, timeout, nfds = 1;
    struct pollfd fds[nfds + 1];

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk->xsk);
    fds[0].events = POLLIN;
    timeout = 1000;

    while(1)
    {
        if (opt_poll)
        {
            ret = poll(fds, nfds, timeout);
            if (ret <= 0)
                continue;
        }
        rx_processing(xsk);
    }
}

/**
 *
 * This function creates a new AF_XDP socket with zero copy, socket will be bind to particular queue of interface
 *
 * @param if_queue interface queue desriptor
 * @return
 */

void *XDProbe_thread(void *args)
{
    int ret = 0;
    unsigned int tid = 0; 			/**<< thread id */
    unsigned int if_queue = 0;
    void *buffer = NULL;
    struct xsk_umem_info *umem = NULL;  /**<< UMEM, fill, comp rings, buffer */
    struct xsk_socket_info **xsk = NULL; /**<< XDP socket **/

    thread_input_t *thr_input = (thread_input_t *) args; /**< threads input variable */

    if_queue = thr_input->if_queue;
    xsk = thr_input->xsk;
    tid = thr_input->tid;

    const pthread_t pid = pthread_self();

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(tid + 5, &cpuset);

    const int set_result = pthread_setaffinity_np(pid, sizeof(cpu_set_t), &cpuset);
    if (set_result != 0) {
        perror("pthread_setaffinity_np");
        exit(EXIT_FAILURE);
    }


    hash_table_t *Table;

    Table = malloc(sizeof(struct _hash_table));
	if(!Table)
	{
	    fprintf(stderr, "malloc error\n");
	    return NULL;
	}
    hash_table_init(Table, tid);

    size_t umem_size = NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE;


    /** create contiguous, page aligned memory, where UMEM will be placed **/
    ret = posix_memalign(&buffer, getpagesize(), umem_size);
    if (ret)
        exit_with_error(ret);

    /** create UMEM from buffer, alloc FILL and COMP rings **/
    umem = xsk_configure_umem(buffer, (u64) umem_size);

    /** create socket assign to particular queue of interface **/
    *xsk = xsk_configure_socket(umem, if_queue, tid);
    (*xsk)->htable = Table;
    pthread_barrier_wait(&xsks_ready);

    rx_sniff(*xsk);
}


void socket_info_print(struct xsk_socket_info *xsk)
{
    printf("\t socket  %d@%s\n",  xsk->if_queue, opt_if);
    printf("\t\t UMEM size:   %lu\n", xsk->umem->umem_size);
    printf("\t\t FILL queue size: %d\n", xsk->umem->fq.size);
    printf("\t\t COMP queue size: %d\n", xsk->umem->cq.size);
    printf("\t\t RX   queue size: %d\n", xsk->rx.size);
    printf("\t\t TX   queue size: %d\n", xsk->tx.size);
}

int xProbe_configure_and_run(struct xProbe_info *xprobe, const int usr_nsocket)
{
    int ret = 0;
    uint32_t tid = 0;
    thread_input_t socket_config_input[MAX_THREADS] = {0};

    /** Create sockets, number defined by user  **/
    for (num_socks = 0; num_socks < usr_nsocket; ++num_socks)
    {
        //printf("socket %d\n", num_socks);
        if(num_socks == MAX_THREADS)
        {
            printf("Max number of sockets is 32!\n");
            break;
        }

        socket_config_input[num_socks].if_queue = num_socks;
        socket_config_input[num_socks].xsk = &xsks[num_socks];
        socket_config_input[num_socks].tid = tid++;


        ret = pthread_create(&xprobe->XDP_workers[num_socks], NULL, &XDProbe_thread, (void *)&socket_config_input[num_socks]);
        if (ret)
            exit_with_error(ret);

        //socket_info_print(xsks[num_socks]);

    }
    printf("Main thread is ready to process");

    pthread_barrier_wait(&xsks_ready);


    return 0;
}

/**
 * Print information about sockets
 *
 * @param[in] xprobe pointer to probe info to print
 */
void xProbe_info_print(struct xProbe_info *xprobe)
{
    struct xsk_socket_info *xsk; /**<< current XDP socket **/
    int i;

    printf("----------------------------------------------------\n");
    printf("xProbe created with %d sockets:\n\n", num_socks);
    for (i = 0; i < num_socks; ++i)
    {
        socket_info_print(xsks[i]);

    }
    printf("----------------------------------------------------\n");
}

void xProbe_timer_run(struct xProbe_info *xprobe)
{
    int ret = 0;

    ret = pthread_create(&xprobe->pt, NULL, poller, NULL);
    if (ret)
        exit_with_error(ret);
}

/**
 *
 * @param xprobe context of probe
 * @return 1 if thread join fail
 */

int xProbe_wait_to_end(struct xProbe_info *xprobe)
{
    int i = 0;
    int ret = 0;

    if ((ret = pthread_join(xprobe->pt, NULL))) {
        fprintf(stderr, "error: pthread_join, err: %d\n", ret);
        return EXIT_FAILURE;
    }

    for (i = 0; i < num_socks; ++i)
    {
        if ((ret = pthread_join(xprobe->XDP_workers[i], NULL)))
        {
            fprintf(stderr, "error: pthread_join, err: %d\n", ret);
            return EXIT_FAILURE;
        }
        printf("thread no. %d successfully joined\n", i);
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; /** No limit, neccessary fo lockmem **/
    struct xProbe_info xProbeInfo;

    parse_command_line(argc, argv);

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    signal(SIGABRT, int_exit);
    setlocale(LC_ALL, "");

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    prev_time = get_nsecs();

    if (pthread_barrier_init(&xdp_ready, NULL, opt_nsocket) != 0) {
        fprintf(stderr, "\n barrier init failed\n");
        exit(EXIT_FAILURE);
    }


    if (pthread_barrier_init(&xsks_ready, NULL, opt_nsocket + 1) != 0) {
        fprintf(stderr, "\n barrier init failed\n");
        exit(EXIT_FAILURE);
    }


    if (pthread_mutex_init(&xsk_creation_mtx, NULL) != 0) {
        fprintf(stderr, "\n mutex init failed\n");
        exit(EXIT_FAILURE);
    }


    /** Create capturing threads **/
    xProbe_configure_and_run(&xProbeInfo, opt_nsocket);
    //xProbe_info_print(&xProbeInfo);


    /** Create controling thread **/
    xProbe_timer_run(&xProbeInfo);

    /** waint until all thread finished **/
    xProbe_wait_to_end(&xProbeInfo);



    if (pthread_barrier_destroy(&xdp_ready) != 0) {
        fprintf(stderr, "\n barrier init failed\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_barrier_destroy(&xsks_ready) != 0) {
        fprintf(stderr, "\n barrier init failed\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_mutex_destroy(&xsk_creation_mtx) != 0) {
        fprintf(stderr, "\n mutex init failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
