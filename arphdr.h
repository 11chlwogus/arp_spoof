#pragma once //헤더 파일의 중복 포함을 방지하기 위해 사용하는 전처리 지시문

#include <netinet/in.h>

#pragma pack(push, 1) //1바이트 단위로 정렬 -> 패딩을 제거한다.
typedef struct{
    uint16_t htype; //네트워크 유형 ethernet은 1이다. 나중에 엔디언으로 바꿔주기
    uint16_t ptype; //매핑할 프로토콜 유형 ipv4는 0x0800 나중에 엔디언으로 바꿔주기
    uint8_t hsize; //mac 주소의 길이 ethernet은 6이다.
    uint8_t psize; //ip 주소의 길이 ipv4는 4이다.
    uint16_t opcode; //패킷의 종류 request : 1, reply : 2
    uint8_t smac[6]; //sender의 mac 주소
    uint32_t sip;
    uint8_t tmac[6];
    uint32_t tip;


}arp_hdr;
#pragma pack(pop)
