#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PORT_FTP_DATA       20
#define PORT_FTP_CONTROL    21
#define PORT_SSH            22
#define PORT_TELNET         23
#define PORT_DNS            53
#define PORT_DHCP_SERVER    67
#define PORT_DHCP_CLIENT    68
#define PORT_HTTP           80
#define PORT_NTP            123
#define PORT_HTTPS          443

#define HTTP_METHOD_MAX_LEN 16
#define HTTP_URI_MAX_LEN    256
#define HTTP_VER_MAX_LEN    16
#define BANNER_MAX_LEN      128


typedef struct {
    bool is_request;                         // true עבור בקשה, false עבור תגובה
    char method[HTTP_METHOD_MAX_LEN];        // GET, POST, PUT וכו'
    char uri[HTTP_URI_MAX_LEN];              // הנתיב המבוקש
    char version[HTTP_VER_MAX_LEN];          // HTTP/1.1, HTTP/1.0
    uint16_t status_code;                    // 200, 404 וכו' (בתגובות)
} HTTPInfo;


typedef struct {
    uint8_t  content_type;                   // 20 = ChangeCipherSpec, 21 = Alert, 22 = Handshake, 23 = AppData
    uint16_t legacy_version;                 // 0x0301 (TLS 1.0), 0x0303 (TLS 1.2)
    uint16_t length;                         // אורך ה-TLS Record
    uint8_t  handshake_type;                 // 1 = Client Hello, 2 = Server Hello (אם רלוונטי)
} HTTPSInfo;


typedef struct {
    uint16_t transaction_id;
    bool     is_response;                    // QR flag: 0 = Query, 1 = Response
    uint8_t  opcode;                         // סוג שאילתה (0 = Standard Query)
    bool     authoritative_answer;           // AA flag
    bool     recursion_desired;              // RD flag
    bool     recursion_available;            // RA flag
    uint8_t  response_code;                  // RCODE (0 = No Error, 3 = NXDomain)
    uint16_t questions_count;
    uint16_t answers_count;
    uint16_t authority_count;
    uint16_t additional_count;
} DNSInfo;


typedef struct {
    uint8_t  op;                             // 1 = BOOTREQUEST, 2 = BOOTREPLY
    uint8_t  htype;                          // 1 = 10Mb Ethernet
    uint8_t  hlen;                           // 6
    uint8_t  hops;
    uint32_t xid;                            // Transaction ID
    uint16_t secs;
    uint16_t flags;                          // Broadcast flag
    uint8_t  ciaddr[4];                      // Client IP
    uint8_t  yiaddr[4];                      // 'Your' IP
    uint8_t  siaddr[4];                      // Server IP
    uint8_t  giaddr[4];                      // Gateway IP
    uint8_t  chaddr[16];                     // Client Hardware (MAC)
    uint32_t magic_cookie;                   // תמיד 0x63825363
    uint8_t  dhcp_msg_type;                  // 1=Discover, 2=Offer, 3=Request, 5=ACK
} DHCPInfo;


typedef struct {
    uint8_t  leap_indicator;                
    uint8_t  version;                        
    uint8_t  mode; // 3 = Client, 4 = Server (3 bits)
    uint8_t  stratum;                       
    uint8_t  poll;
    int8_t   precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t reference_id;
} NTPInfo;


typedef struct {
    char banner[BANNER_MAX_LEN];           
    bool has_banner;
} TextProtocolInfo;


typedef enum {
    layer5_7_proto_none = 0,
    layer5_7_proto_http,
    layer5_7_proto_https,
    layer5_7_proto_dns,
    layer5_7_proto_dhcp,
    layer5_7_proto_ftp,
    layer5_7_proto_ssh,
    layer5_7_proto_ntp,
    layer5_7_proto_telnet,
    layer5_7_proto_raw_payload
} Layer5_7ProtocolType;


typedef struct {
    Layer5_7ProtocolType proto;              

    union {
        HTTPInfo http;
        HTTPSInfo https;
        DNSInfo dns;
        DHCPInfo dhcp;
        NTPInfo ntp;
        TextProtocolInfo ftp;
        TextProtocolInfo ssh;
        TextProtocolInfo telnet;
    } app_header;

    const uint8_t *payload;
    size_t payload_len;
} layer5_7Data;