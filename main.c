/***********************************************/
/*          Jakub Pastuszek - xpastu00         */
/*               VUT FIT Brno                  */
/*      		    xprobe	                   */
/*                March 2017                   */
/*                  main.c                     */
/***********************************************/

/*
In the AF_PACKET fanout mode, packet reception can be load balanced among
processes. This also works in combination with mmap(2) on packet sockets.

Currently implemented fanout policies are:

  - PACKET_FANOUT_HASH: schedule to socket by skb's packet hash
  - PACKET_FANOUT_LB: schedule to socket by round-robin
  - PACKET_FANOUT_CPU: schedule to socket by CPU packet arrives on
  - PACKET_FANOUT_RND: schedule to socket by random selection
  - PACKET_FANOUT_ROLLOVER: if one socket is full, rollover to another
  - PACKET_FANOUT_QM: schedule to socket by skbs recorded queue_mapping
*/

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <net/if.h>

static const char *device_name;
static int fanout_type;
static int fanout_id;

#ifndef PACKET_FANOUT
# define PACKET_FANOUT			18
# define PACKET_FANOUT_HASH		0
# define PACKET_FANOUT_LB		1
#endif

static int setup_socket(void)
{
	int err, fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	struct sockaddr_ll ll;
	struct ifreq ifr;
	int fanout_arg;

	if (fd < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device_name);
	err = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (err < 0) {
		perror("SIOCGIFINDEX");
		return EXIT_FAILURE;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	err = bind(fd, (struct sockaddr *) &ll, sizeof(ll));
	if (err < 0) {
		perror("bind");
		return EXIT_FAILURE;
	}

	fanout_arg = (fanout_id | (fanout_type << 16));
	err = setsockopt(fd, SOL_PACKET, PACKET_FANOUT,
			 &fanout_arg, sizeof(fanout_arg));
	if (err) {
		perror("setsockopt");
		return EXIT_FAILURE;
	}

	return fd;
}

static void fanout_thread(void)
{
	int fd = setup_socket();
	//int limit = 100000;
	int count = 0;

	if (fd < 0)
		exit(fd);

	while (1){//limit-- > 0) {
		char buf[1600];
		int err;

		err = read(fd, buf, sizeof(buf));
		if (err < 0) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		count++;

		if (count && (count % 100000) == 0)
			fprintf(stdout, "(%d) - %d\n", getpid(), count);
	//	if ((limit % 20000) == 0)
	//		fprintf(stdout, "(%d) - %d\n", getpid(), 100000-limit);
	}

	//fprintf(stdout, "%d: Received 100000 packets\n", getpid());

	close(fd);
	exit(0);
}

int main(int argc, char **argp)
{
	int fd, err;
	int i;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s INTERFACE\n", argp[0]);
		return EXIT_FAILURE;
	}

	fanout_type = PACKET_FANOUT_HASH;
	device_name = argp[1];
	fanout_id = getpid() & 0xffff;

	for (i = 0; i < 4; i++) {
		pid_t pid = fork();

		switch (pid) {
		case 0:
			fanout_thread();

		case -1:
			perror("fork");
			exit(EXIT_FAILURE);
		}
	}

	for (i = 0; i < 4; i++) {
		int status;

		wait(&status);
	}

	return 0;
}
