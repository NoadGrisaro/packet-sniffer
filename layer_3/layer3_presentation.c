#include <stdio.h>
#include <arpa/inet.h>

#include "layer_3/layer3_types.h"

static void printIPv4Address(const uint8_t ip[IPV4_ADDR_LEN]) {
    printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static void printIPv6Address(const uint8_t ip[IPV6_ADDR_LEN]) {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, str, sizeof(str));
    printf("%s", str);
}

void printLayer3(const layer3Data *layer3_data) {
    if (!layer3_data || layer3_data->ip_type == layer3_type_none) {
        return;
    }

    printf("--- Layer 3 (Network) ---\n");

    if (layer3_data->ip_type == layer3_type_ipv4) {
        const IPv4Header *v4 = &layer3_data->net_hdr.ipv4;
        printf("  Protocol: IPv4\n");
        printf("  Source IP:      ");
        printIPv4Address(v4->src_ip);
        printf("\n  Destination IP: ");
        printIPv4Address(v4->dst_ip);
        printf("\n  Header Length:  %u bytes (IHL: %u)\n", v4->header_length_bytes, v4->header_length_bytes);
        printf("  Total Length:   %u bytes\n", v4->total_length);
        printf("  Identification: 0x%04x (%u)\n", v4->id, v4->id);
        printf("  Flags:          [DF: %d, MF: %d] | Frag Offset: %u\n", 
               v4->flag_dont_fragments, v4->flag_more_fragments, v4->fragment_offset);
        printf("  TTL:            %u\n", v4->time_to_live);
        printf("  Protocol:       %u\n", v4->protocol);
        printf("  Checksum:       0x%04x\n", v4->checksum);
        if (v4->has_options) {
            printf("  Options:        Present (%u bytes)\n", v4->options_len);
        }
    } else if (layer3_data->ip_type == layer3_type_ipv4) {
        const IPv6Header *v6 = &layer3_data->net_hdr.ipv6;
        printf("  Protocol: IPv6\n");
        printf("  Source IP:      ");
        printIPv6Address(v6->src_ip);
        printf("\n  Destination IP: ");
        printIPv6Address(v6->dst_ip);
        printf("\n  Payload Length: %u bytes\n", v6->payload_len);
        printf("  Next Header:    %u\n", v6->next_header);
        printf("  Hop Limit:      %u\n", v6->hop_limit);
        printf("  Traffic Class:  0x%02x | Flow Label: 0x%05x\n", v6->traffic_class, v6->flow_label);
    }

    if (layer3_data->next_proto == layer3_next_icmp) {
        const ICMPHeader *icmp = &layer3_data->control_hdr.icmp;
        printf("  [ICMPv4]\n");
        printf("    Type: %u, Code: %u, Checksum: 0x%04x\n", icmp->type, icmp->code, icmp->checksum);
        printf("    ID: %u, Sequence: %u\n", icmp->id, icmp->sequence);
    } else if (layer3_data->next_proto == layer3_next_icmpv6) {
        const ICMPv6Header *icmp6 = &layer3_data->control_hdr.icmpv6;
        printf("  [ICMPv6]\n");
        printf("    Type: %u, Code: %u, Checksum: 0x%04x\n", icmp6->type, icmp6->code, icmp6->checksum);
        printf("    ID: %u, Sequence: %u\n", icmp6->id, icmp6->sequence);
    }
}