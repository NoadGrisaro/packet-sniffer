#pragma once

#include <stdint.h>
#include <stdbool.h>

#define TCP_MIN_HEADER_LEN 20
#define UDP_HEADER_LEN 8

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    
    uint8_t data_offset;          
    uint8_t header_length_bytes; 
    
    bool flag_fin;
    bool flag_syn;
    bool flag_rst;
    bool flag_psh;
    bool flag_ack;
    bool flag_urg;
    bool flag_ece;
    bool flag_cwr;
    
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    
    bool has_options;         
    uint8_t options_len;         
} TCPHeader;//size of 40 bytes

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;              
    uint16_t checksum;
} UDPHeader;//size of 8 bytes

typedef enum {
    layer4_type_none = 0,
    layer4_type_tcp,
    layer4_type_udp
} Layer4Type;

typedef enum {
    layer4_next_unknown = 0,
    layer4_next_http,
    layer4_next_https,
    layer4_next_dns,
    layer4_next_dhcp,
    layer4_next_ftp,
    layer4_next_ssh,
    layer4_next_ntp,
    layer4_next_telnet
} Layer4NextProtocol;

typedef struct {
    Layer4Type type;                      
    
    union {
        TCPHeader tcp;
        UDPHeader udp;
    } transport_hdr;

    Layer4NextProtocol next_proto;       
} layer4Data;