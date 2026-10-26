#include <stdio.h>

#include "layer_5_7/layer5_7_types.h"

static const char *dhcpMsgTypeToString(uint8_t type) {
    switch (type) {
        case 1: return "DHCP Discover";
        case 2: return "DHCP Offer";
        case 3: return "DHCP Request";
        case 4: return "DHCP Decline";
        case 5: return "DHCP ACK";
        case 6: return "DHCP NAK";
        case 7: return "DHCP Release";
        default: return "Unknown";
    }
}

void printLayer5_7(const layer5_7Data *layer5_7) {
    if (!layer5_7 || layer5_7->proto == layer5_7_proto_none) {
        return;
    }

    printf("--- Layer 5-7 (Application) ---\n");

    switch (layer5_7->proto) {
        case layer5_7_proto_http:
            printf("  Protocol: HTTP\n");
            if (layer5_7->app_header.http.is_request) {
                printf("  Type:     Request\n");
                printf("  Method:   %s\n", layer5_7->app_header.http.method);
                printf("  URI:      %s\n", layer5_7->app_header.http.uri);
                printf("  Version:  %s\n", layer5_7->app_header.http.version);
            } else {
                printf("  Type:     Response\n");
                printf("  Status:   %u\n", layer5_7->app_header.http.status_code);
                printf("  Version:  %s\n", layer5_7->app_header.http.version);
            }
            break;

        case layer5_7_proto_dns:
            printf("  Protocol: DNS\n");
            printf("  Transaction ID: 0x%04x\n", layer5_7->app_header.dns.transaction_id);
            printf("  Message Type:   %s\n", layer5_7->app_header.dns.is_response ? "Response" : "Query");
            printf("  Questions:      %u\n", layer5_7->app_header.dns.questions_count);
            printf("  Answers:        %u\n", layer5_7->app_header.dns.answers_count);
            printf("  Authoritative:  %s\n", layer5_7->app_header.dns.authoritative_answer ? "Yes" : "No");
            break;

        case layer5_7_proto_dhcp:
            printf("  Protocol: DHCP\n");
            printf("  Operation: %s (0x%02x)\n", 
                   layer5_7->app_header.dhcp.op == 1 ? "BOOTREQUEST" : "BOOTREPLY", layer5_7->app_header.dhcp.op);
            printf("  XID:       0x%08x\n", layer5_7->app_header.dhcp.xid);
            if (layer5_7->app_header.dhcp.dhcp_msg_type > 0) {
                printf("  Type:      %s\n", dhcpMsgTypeToString(layer5_7->app_header.dhcp.dhcp_msg_type));
            }
            printf("  Client IP: %u.%u.%u.%u\n",
                   layer5_7->app_header.dhcp.ciaddr[0], layer5_7->app_header.dhcp.ciaddr[1],
                   layer5_7->app_header.dhcp.ciaddr[2], layer5_7->app_header.dhcp.ciaddr[3]);
            printf("  Your IP:   %u.%u.%u.%u\n",
                   layer5_7->app_header.dhcp.yiaddr[0], layer5_7->app_header.dhcp.yiaddr[1],
                   layer5_7->app_header.dhcp.yiaddr[2], layer5_7->app_header.dhcp.yiaddr[3]);
            break;

        case layer5_7_proto_https:
            printf("  Protocol: HTTPS / TLS Record\n");
            printf("  Content Type:   %u\n", layer5_7->app_header.https.content_type);
            printf("  Record Length:  %u bytes\n", layer5_7->app_header.https.length);
            break;

        case layer5_7_proto_ssh:
            printf("  Protocol: SSH\n");
            if (layer5_7->app_header.ssh.has_banner) {
                printf("  Identification: %s\n", layer5_7->app_header.ssh.banner);
            }
            break;

        case layer5_7_proto_ftp:
            printf("  Protocol: FTP\n");
            if (layer5_7->app_header.ftp.has_banner) {
                printf("  Message: %s\n", layer5_7->app_header.ftp.banner);
            }
            break;

        case layer5_7_proto_telnet:
            printf("  Protocol: Telnet\n");
            if (layer5_7->app_header.telnet.has_banner) {
                printf("  Data: %s\n", layer5_7->app_header.telnet.banner);
            }
            break;

        default:
            printf("  Protocol: Raw / Unclassified Payload\n");
            break;
    }
}