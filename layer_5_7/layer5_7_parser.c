#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>

#include "layer_4/layer4_types.h"

#include "layer_5_7/layer5_7_types.h"
#include "layer_5_7/layer5_7_types.h"


static void parseHTTP(const uint8_t *payload, size_t len, HTTPInfo *http) {
    memset(http, 0, sizeof(HTTPInfo));

    // יצירת מחרוזת מוגבלת לבדיקת שורת הפתיחה
    char line[512];
    size_t copy_len = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
    memcpy(line, payload, copy_len);
    line[copy_len] = '\0';

    char *crlf = strstr(line, "\r\n");
    if (crlf) {
        *crlf = '\0';
    }

    if (strncmp(line, "HTTP/", 5) == 0) {
        // HTTP Response (למשל: HTTP/1.1 200 OK)
        http->is_request = false;
        sscanf(line, "%15s %hu", http->version, &http->status_code);
    } else {
        // HTTP Request (למשל: GET /index.html HTTP/1.1)
        http->is_request = true;
        sscanf(line, "%15s %255s %15s", http->method, http->uri, http->version);
    }
}

static void parseDNS(const uint8_t *payload, size_t len, DNSInfo *dns) {
    if (len < 12) {
        return;
    }

    dns->transaction_id = ntohs(*(uint16_t *)(payload + 0));
    uint16_t flags      = ntohs(*(uint16_t *)(payload + 2));

    dns->is_response           = (flags >> 15) & 0x01;
    dns->opcode                = (flags >> 11) & 0x0F;
    dns->authoritative_answer  = (flags >> 10) & 0x01;
    dns->recursion_desired     = (flags >> 8) & 0x01;
    dns->recursion_available   = (flags >> 7) & 0x01;
    dns->response_code         = flags & 0x0F;

    dns->questions_count       = ntohs(*(uint16_t *)(payload + 4));
    dns->answers_count         = ntohs(*(uint16_t *)(payload + 6));
    dns->authority_count       = ntohs(*(uint16_t *)(payload + 8));
    dns->additional_count      = ntohs(*(uint16_t *)(payload + 10));
}

static void parseDHCP(const uint8_t *payload, size_t len, DHCPInfo *dhcp) {
    if (len < 240) {
        return;
    }

    dhcp->op    = payload[0];
    dhcp->htype = payload[1];
    dhcp->hlen  = payload[2];
    dhcp->hops  = payload[3];
    dhcp->xid   = ntohl(*(uint32_t *)(payload + 4));
    dhcp->secs  = ntohs(*(uint16_t *)(payload + 8));
    dhcp->flags = ntohs(*(uint16_t *)(payload + 10));

    memcpy(dhcp->ciaddr, payload + 12, 4);
    memcpy(dhcp->yiaddr, payload + 16, 4);
    memcpy(dhcp->siaddr, payload + 20, 4);
    memcpy(dhcp->giaddr, payload + 24, 4);
    memcpy(dhcp->chaddr, payload + 28, 16);

    dhcp->magic_cookie = ntohl(*(uint32_t *)(payload + 236));

    // שליפת DHCP Message Type (Option 53) אם ה-Magic Cookie תקין
    dhcp->dhcp_msg_type = 0;
    if (dhcp->magic_cookie == 0x63825363 && len > 240) {
        size_t opt_idx = 240;
        while (opt_idx < len) {
            uint8_t opt_code = payload[opt_idx];
            if (opt_code == 255) {
                break; // End Option
            }
            if (opt_code == 0) {
                opt_idx++; // Pad Option
                continue;
            }
            if (opt_idx + 1 >= len) {
                break;
            }
            uint8_t opt_len = payload[opt_idx + 1];
            if (opt_idx + 2 + opt_len > len) {
                break;
            }

            if (opt_code == 53 && opt_len == 1) {
                dhcp->dhcp_msg_type = payload[opt_idx + 2];
                break;
            }
            opt_idx += 2 + opt_len;
        }
    }
}

static void parseTextBanner(const uint8_t *payload, size_t len, TextProtocolInfo *info) {
    memset(info, 0, sizeof(TextProtocolInfo));
    if (len == 0) {
        return;
    }

    size_t copy_len = len < BANNER_MAX_LEN - 1 ? len : BANNER_MAX_LEN - 1;
    size_t out_idx = 0;

    for (size_t i = 0; i < copy_len; i++) {
        if (payload[i] == '\r' || payload[i] == '\n') {
            break;
        }
        if (isprint(payload[i])) {
            info->banner[out_idx++] = (char)payload[i];
        }
    }
    info->banner[out_idx] = '\0';
    info->has_banner = (out_idx > 0);
}

bool parseLayer5_7(const uint8_t *buffer, size_t length, size_t *offset, 
                   Layer4NextProtocol next_proto, layer5_7Data *layer5_7) {
    if (!buffer || !offset || !layer5_7) {
        return false;
    }

    memset(layer5_7, 0, sizeof(layer5_7Data));

    size_t payload_len = length - *offset;
    const uint8_t *payload = buffer + *offset;

    layer5_7->payload = payload;
    layer5_7->payload_len = payload_len;

    if (payload_len == 0) {
        layer5_7->proto = layer5_7_proto_none;
        return true;
    }

    switch (next_proto) {
        case layer4_next_http:
            layer5_7->proto = layer5_7_proto_http;
            parseHTTP(payload, payload_len, &layer5_7->app_header.http);
            break;

        case layer4_next_dns:
            layer5_7->proto = layer5_7_proto_dns;
            parseDNS(payload, payload_len, &layer5_7->app_header.dns);
            break;

        case layer4_next_dhcp:
            layer5_7->proto = layer5_7_proto_dhcp;
            parseDHCP(payload, payload_len, &layer5_7->app_header.dhcp);
            break;

        case layer4_next_ftp:
            layer5_7->proto = layer5_7_proto_ftp;
            parseTextBanner(payload, payload_len, &layer5_7->app_header.ftp);
            break;

        case layer4_next_ssh:
            layer5_7->proto = layer5_7_proto_ssh;
            parseTextBanner(payload, payload_len, &layer5_7->app_header.ssh);
            break;

        case layer4_next_telnet:
            layer5_7->proto = layer5_7_proto_telnet;
            parseTextBanner(payload, payload_len, &layer5_7->app_header.telnet);
            break;

        case layer4_next_https:
            layer5_7->proto = layer5_7_proto_https;
            if (payload_len >= 5) {
                layer5_7->app_header.https.content_type   = payload[0];
                layer5_7->app_header.https.legacy_version = ntohs(*(uint16_t *)(payload + 1));
                layer5_7->app_header.https.length         = ntohs(*(uint16_t *)(payload + 3));
            }
            break;

        default:
            layer5_7->proto = layer5_7_proto_raw_payload;
            break;
    }

    return true;
}