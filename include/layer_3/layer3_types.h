#pragma once

#include <stdint.h>
#include <stdbool.h>

#define IPV4_MIN_HEADER_LEN 20
#define IPV6_HEADER_LEN 40
#define ICMP_MIN_HEADER_LEN 8
#define ICMPV6_MIN_HEADER_LEN 8

#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16


#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_IPV6_ICMP 58


typedef struct {
    uint8_t version; //always equal to 4           
    uint8_t header_length_bytes; // number of words (value*4=bytes)
    uint8_t type_of_service;     
    uint16_t total_length;        
    uint16_t id;      
    bool flag_reserved;//always zero    
    bool flag_dont_fragments;             
    bool flag_more_fragments;            
    uint16_t fragment_offset;     
    uint8_t time_to_live;                 
    uint8_t protocol;            
    uint16_t checksum;     

    uint8_t src_ip[IPV4_ADDR_LEN];
    uint8_t dst_ip[IPV4_ADDR_LEN];

    bool has_options;         
    uint8_t options_len;         
} IPv4Header;//size of 20. with options field size 60 bytes


typedef struct {
    uint8_t version; //always equal to 6     
    uint8_t traffic_class;     
    uint32_t flow_label;         
    uint16_t payload_len;         
    uint8_t next_header;         
    uint8_t hop_limit;           
    
    uint8_t src_ip[IPV6_ADDR_LEN];
    uint8_t dst_ip[IPV6_ADDR_LEN];
} IPv6Header;


typedef struct {
    uint8_t type;//0 = reply 3 = destanation unreachable 8 = req 11 = time exceeded              
    uint8_t code; // type explain           
    uint16_t checksum;
    uint16_t id;                 
    uint16_t sequence;         
} ICMPHeader;//size of 8 bytes


typedef struct {
    uint8_t type;             
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} ICMPv6Header;//size of 8 bytes


typedef enum {
    layer3_next_none = 0,
    layer3_next_tcp,
    layer3_next_udp,
    layer3_next_icmp,
    layer3_next_icmpv6
} Layer3NextProtocol;

typedef enum {
    layer3_type_none = 0,
    layer3_type_ipv4,
    layer3_type_ipv6
} Layer3IPType;


typedef struct {
    Layer3IPType ip_type;

    union {
        IPv4Header ipv4;
        IPv6Header ipv6;
    } net_hdr;

    Layer3NextProtocol next_proto;

    union {
        ICMPHeader icmp;
        ICMPv6Header icmpv6;
    } control_hdr;
    
} layer3Data;