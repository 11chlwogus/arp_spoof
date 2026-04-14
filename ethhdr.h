#pragma once

#include <netinet/in.h>

typedef struct{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t eth_type;
}eth_hdr;
