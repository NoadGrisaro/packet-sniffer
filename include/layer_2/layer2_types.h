#pragma once
#include <stdint.h>
#include <stdbool.h>

#define ETH_ADDRESS_LENGTH 6
#define ETH_HEADER_LEN 14
#define VLAN_HEADER_LEN 4
#define ARP_HEADER_LEN 28

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86DD

typedef struct {
    uint8_t dst_mac[ETH_ADDRESS_LENGTH];
    uint8_t src_mac[ETH_ADDRESS_LENGTH];
    uint16_t ethertype; //points to the next protocol
} EthernetHeader;//size of 14 bytes

typedef struct {
    uint16_t tpid; // always 0x8100
    uint8_t  priority_code;  //0-lowest 7-highest
    bool drop_eligible_indicator; //if packet will be droped in high trafic
    uint16_t vlan_id;  
}VlanHeader;//size of 6 bytes

typedef struct{
    uint16_t hardware_type;               
    uint16_t protocol_type;             
    uint8_t hardware_len;               
    uint8_t protocol_len;               
    uint16_t opcode;// 1 = Request, 2 = Reply      
    uint8_t sender_mac[ETH_ADDRESS_LENGTH];
    uint8_t sender_ip[4];
    uint8_t target_mac[ETH_ADDRESS_LENGTH];
    uint8_t target_ip[4];
}ARPHeader;//size of 28 bytes


typedef enum {
    layer2_next_none = 0,
    layer2_next_arp,
    layer2_next_ipv4,
    layer2_next_ipv6
}Layer2NextProtocol;

typedef struct {
    EthernetHeader eth;

    bool has_vlan;
    VlanHeader vlan;

    Layer2NextProtocol next_proto;
    union {
        ARPHeader arp;    // active only when arp is the next protocol
    } payload;

} layer2Data;