
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <list>

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
#include <netinet/if_ether.h>
#include <netinet/ether.h>

#include "yk_lib.h"
#include "yk_utils.h"
#include "yk_net.h"

#include "main.h"

struct Host {
	string			ip;
	string			name;
	string			mac;
	list<string>		aliases;
	list<u_int16_t>		tcpPorts;
	list<u_int16_t>		udpPorts;
	struct timespec		tstmp;
};

struct ScanList {
	list<Host>	 	ents;
	mutex			mtx;
};

		int		g_Token		= TKN_NONE;
static		bool		g_Working	= true;
static		u_int32_t	g_MinIP		= 0;
static		u_int32_t	g_MaxIP		= 0xffffffff;
static		ScanList	ScannedList;

void recver(const char *_name) {
	string name = _name;
	int sock = 0;
	struct sockaddr_ll addr;
	int bytes = 0;
	char buf[2048];
	struct ether_arp *arp;
	
	sock = socket(AF_PACKET, SOCK_DGRAM, 0);
	if(sock < 0)
		goto err0;
	addr.sll_family   = AF_PACKET;
	addr.sll_protocol = htons(ETHERTYPE_ARP);
	addr.sll_ifindex  = if_nametoindex("enp3s0");
	addr.sll_pkttype  = PACKET_HOST;
	addr.sll_hatype   = htons(ARPHRD_ETHER);
	if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
		goto err1;
	
	threadGetToken(TKN_RECVER);
	cout << name + " : started" << endl;
	threadPutToken();
	
	memset(buf, 0, sizeof(buf));
	
	while(g_Working || ScannedList.ents.size() > 0) {
		memset(buf, 0, sizeof(buf));
		bytes = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
		if(bytes < 0)
			continue;
		arp = (struct ether_arp *)buf;
		if(ntohs(arp->arp_op) == ARPOP_REPLY) {
			ScannedList.mtx.lock();
			for(list<Host>::iterator it = ScannedList.ents.begin();
				it != ScannedList.ents.end(); it++) {
				struct in_addr _ip;
				_ip.s_addr = *((u_int32_t*)arp->arp_spa);
				string ip  = inet_ntoa(_ip);
				struct ether_addr _mac;
				memcpy(_mac.ether_addr_octet, arp->arp_sha, 6);
				string mac = ether_ntoa(&_mac);
				if(ip == it->ip) {
					cout << ip + "[" + mac + "] : " + "online" << endl; 
					ScannedList.ents.erase(it);
					break;
				}
			}
			ScannedList.mtx.unlock();
		}
	}
err1:
	close(sock);
err0:
	return;
}

void sender(const char *_name) {
	u_int32_t ip = g_MinIP;
	int sock;
	struct sockaddr_ll addr;
	struct ether_addr * _mac;
	
	threadGetToken(TKN_SENDER);
	string name = _name;
	cout << name + " : started" << endl;
	threadPutToken();
	
	sock = socket(AF_PACKET, SOCK_DGRAM, 0);
	if(sock < 0)
		goto err0;
	
	_mac = ether_aton("ff:ff:ff:ff:ff:ff");
	addr.sll_family   = AF_PACKET;
	addr.sll_protocol = htons(ETHERTYPE_ARP);
	addr.sll_ifindex  = if_nametoindex("enp3s0");
	addr.sll_pkttype  = PACKET_BROADCAST;
	addr.sll_halen    = 6;
	memcpy(addr.sll_addr, _mac->ether_addr_octet, 6);
	
	while(ip < g_MaxIP) {
		if(ip == inet_addr("192.168.2.241"))
			continue;
		struct ether_arp arp;
		memset((void*)&arp, 0, sizeof(arp));
		arp.arp_hrd = htons(ARPHRD_ETHER);
		arp.arp_hln = 6;
		arp.arp_pro = htons(ETHERTYPE_IP);
		arp.arp_pln = 4;
		arp.arp_op  = htons(ARPOP_REQUEST);
		*((u_int32_t *)arp.arp_spa) = inet_addr("192.168.2.241");
		*((u_int32_t *)arp.arp_tpa) = htonl(ip);
		memcpy(arp.arp_sha, _mac->ether_addr_octet, 6);
		if(sendto(sock, (void *)&arp, sizeof(arp), 0, (struct sockaddr *)&addr, sizeof(addr)) > 0) {
			Host host;
			struct in_addr _ip;
			_ip.s_addr = htonl(ip);
			host.ip = inet_ntoa(_ip);
			clock_gettime(CLOCK_MONOTONIC, &host.tstmp);
			ScannedList.mtx.lock();
			ScannedList.ents.push_back(host);
			ScannedList.mtx.unlock();
		}
		usleep(1000);
		ip++;
	}
err1: 
	close(sock);
err0:
	g_Working = false;
	return;
}

int main(int argc, char *argv[]) {
	g_MinIP = ntohl(inet_addr("192.168.2.1"));
	g_MaxIP = ntohl(inet_addr("192.168.2.255"));

	threadPutToken();
	thread rcvr(recver, "recver");
	thread sndr(sender, "sender");
	while(g_Working || ScannedList.ents.size() > 0) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		ScannedList.mtx.lock();
		for(list<Host>::iterator it = ScannedList.ents.begin();
			it != ScannedList.ents.end();) {
			if(now.tv_sec - it->tstmp.tv_sec > 2) {
				it = ScannedList.ents.erase(it);
			}
			else {
				it++;
			}
		}
		ScannedList.mtx.unlock();
	}
	rcvr.join();
	sndr.join();
}


