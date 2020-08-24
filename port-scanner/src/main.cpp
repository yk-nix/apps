
#include <iostream>
#include <vector>

using namespace std;

#include <sys/types.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>

#include "yk_lib.h"
#include "yk_utils.h"
#include "yk_net.h"

enum StartToken {
	RECVER_START,
	SENDER_START,
};

struct PortEntry {
	u_int16_t	port;
	struct timespec tstamp;
};
struct ScanList {
	vector<PortEntry>  list;
	pthread_mutex_t    mutex;
	u_int16_t	   min;
	u_int16_t          max;
	ScanList() {
		pthread_mutex_init(&mutex, NULL);
		min = 1;
		max = 65534;
	}
	ScanList(u_int16_t _min, u_int16_t _max) {
		pthread_mutex_init(&mutex, NULL);
		min = _min;
		max = _max;
	}
};

static ScanList  g_PortList;
static bool      g_Working   = true;
static string    g_DestHost;;
static string    g_LocalHost;
static string    g_LocalIface;
static int       g_Timeout = 2;
static int       g_Token = 0;

void print_timestamp() {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	printf("%ld.%ld\n", t.tv_sec, t.tv_nsec);
}

void start_sync(StartToken t) {
	while(g_Token < t)
		usleep(100000);
	g_Token++;
}

void *tcp_sender(void *arg) {
	int sock;
	u_int16_t port = g_PortList.min;
	u_int32_t src, dst;
	struct sockaddr_in addr;

	dst = inet_addr(g_DestHost.c_str());
	src = inet_addr(g_LocalHost.c_str());
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = dst;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(sock < 0)
		goto err0;
	start_sync(SENDER_START);
	while(port <= g_PortList.max) {
		PortEntry e;
		struct tcp_datagram *tcp = yk_tcp_make_datagram(src, dst,
				rand(), port, rand(), 0, YK_TCP_SYN, 8192, 0, NULL, 0, NULL, 0);
		if(tcp == NULL)
			continue;
		e.port = port;
		clock_gettime(CLOCK_MONOTONIC, &e.tstamp);
		pthread_mutex_lock(&g_PortList.mutex);
		g_PortList.list.push_back(e);
		pthread_mutex_unlock(&g_PortList.mutex);
		sendto(sock, tcp->data, tcp->len, 0, (struct sockaddr *)&addr, sizeof(addr));
		yk_tcp_free_datagram(tcp);
		usleep(1000);
		port++;
	}
	close(sock);
	g_Working = false;
err0:
	return NULL;
}


void *tcp_recver(void *arg) {
	char cache[2048];
	int bytes = 0;
	struct iphdr *ip = (struct iphdr*)cache;
	int sock  = 0;
	struct tcphdr *tcp = NULL;
	struct sockaddr_ll addr;
	int port;
	sock = socket(AF_PACKET, SOCK_DGRAM, ETH_P_IP);
	if(sock < 0)
		goto err0;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_IP);
	addr.sll_pkttype = PACKET_HOST;
	addr.sll_ifindex = if_nametoindex(g_LocalIface.c_str());
	if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
		goto err1;
	start_sync(RECVER_START);
	while(g_PortList.list.size() > 0 || g_Working) {
		memset(cache, 0, sizeof(cache));
		bytes = recv(sock, cache, sizeof(cache), 0);
		if(bytes > 0 && ip->saddr == inet_addr(g_DestHost.c_str())) {
			tcp = (struct tcphdr*)(cache + (ip->ihl * 4));
			port = ntohs(tcp->source);
//printf("------- port %d --------(%d)\n", port, g_PortList.list.size());
//yk_hexdump(cache, bytes);
			pthread_mutex_lock(&g_PortList.mutex);
			for(vector<PortEntry>::iterator it = g_PortList.list.begin();
					it != g_PortList.list.end(); ) {
				if(it->port == port) {
					it = g_PortList.list.erase(it);
					if(tcp->ack && tcp->syn)
						printf("%d: open\n", port);
					break;
				}
				else {
					it++;
				}
			}
			pthread_mutex_unlock(&g_PortList.mutex);
		}
	}
err1:
	close(sock);
err0:
	return NULL;

}


void usage(int ecode) {
	printf( "usage: pscan [-p <port_min-port_max>] <dest_host>\n"
		"	-p <port_min-port_max>       port-range would be scanned\n"
		"          --port <port_min-port_max>\n"
		"	-h/H  --help                 display this help message\n");
	exit(ecode);
}

void get_port_range(const char *s) {
	int min = -1, max = -1;
	int tmp;
	sscanf(s, "%d-%d", &min, &max);
	if(max < 0)
		max = min;
	if(min > 0) {
		if(max > min) {
			g_PortList.min = min;
			g_PortList.max = max;
		}
		else {
			g_PortList.min = max;
			g_PortList.max = min;
		}
	}
}

void init(int argc, char *argv[]) {
	char opt;
	struct option opts[] = {
		{"port", required_argument, NULL, 'p'},
		{"help", no_argument, NULL, 'h'},
	};
	while((opt = getopt_long(argc, argv, "p:h", opts, NULL)) != -1) {
		switch(opt) {
		case 'p':
			get_port_range(optarg);
			break;
		case 'h':
		case 'H':
			usage(0);
		}
	}
	if(argv[optind] == NULL)
		usage(1);
	
	struct hostent *hostent = gethostbyname(argv[optind]);
	if(hostent == NULL) {
		fprintf(stderr, "unable to resolve the hostname: %s\n",
			argv[optind]);
		exit(1);
	}
	g_DestHost = inet_ntoa(*((struct in_addr *)hostent->h_addr));
	
	
}

int check_route_reachable() {
	struct rtentry *rt, *p;
	int count, i;
	int ret = 0;
	if(g_DestHost.empty())
		goto err0;
	count = yk_route_get(CENTOS, &rt);
//printf("route table count: %d\n", count);
	p = rt;
	for(i = 0; i < count; i++) {
		if((inet_addr(g_DestHost.c_str()) & *((u_int32_t *)p->rt_genmask.sa_data)) == 
			*((u_int32_t *)p->rt_dst.sa_data)) {
			g_LocalIface = p->rt_dev;
			g_LocalHost  = yk_if_getaddr(p->rt_dev);
			ret = 1;
			break;
		}
		p++;
	}
	yk_route_free(&rt, count);
	return ret;
err0:
	return ret;
}

int main(int argc, char *argv[]) {
	g_LocalIface = "lo";
	g_LocalHost  = "127.0.0.1";
	g_Token      = RECVER_START;
	
	init(argc, argv);
	
	if(getuid() != 0) {
		fprintf(stderr, "only root could run this app.\n");
		return 1;
	}
	
	check_route_reachable();

//printf("g_LocalIface = %s\n", g_LocalIface.c_str());
//printf("g_LocalHoste = %s\n", g_LocalHost.c_str());
//printf("g_DestHoste  = %s\n", g_DestHost.c_str());
	
	printf(" start scanning....[%s : %d-%d]\n", g_DestHost.c_str(), 
		g_PortList.min, g_PortList.max);
	
	pthread_t sender, recver;
	pthread_create(&recver, NULL, tcp_recver, NULL);
	pthread_create(&sender, NULL, tcp_sender, NULL);
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while(g_Working || g_PortList.list.size() > 0) {
		struct timespec now;
		pthread_mutex_lock(&g_PortList.mutex);
		for(vector<PortEntry>::iterator it = g_PortList.list.begin();
				it != g_PortList.list.end(); ) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			if(now.tv_sec - it->tstamp.tv_sec > g_Timeout)
				it = g_PortList.list.erase(it);
			else
				it++;
		}
		pthread_mutex_unlock(&g_PortList.mutex);
		usleep(100000);
	}
	pthread_join(sender, NULL);
	pthread_join(recver, NULL);
	clock_gettime(CLOCK_MONOTONIC, &end);
	if(end.tv_nsec >= start.tv_nsec)
		printf("comsumed time: %d.%-0.3ds\n", end.tv_sec - start.tv_sec, 
			(end.tv_nsec - start.tv_nsec)/1000000);
	else 
		printf("comsumed time: %d.%ds\n", end.tv_sec - start.tv_sec - 1,
			 (1000000000 + end.tv_nsec - start.tv_nsec)/1000000);
}
