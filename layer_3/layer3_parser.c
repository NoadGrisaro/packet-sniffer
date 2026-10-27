#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "layer_2/layer2_types.h"
#include "layer_3/layer3_types.h"

static int handleICMP(const uint8_t *buffer, size_t length, size_t *offset, layer3Data *layer3_data) {
    layer3_data->next_proto = layer3_next_icmp;

    if (length < *offset + ICMP_MIN_HEADER_LEN) {
        fprintf(stderr, "Layer 3 error: truncated ICMP header\n");
        return -1;
    }

    const uint8_t *icmp_ptr = buffer + *offset;
    layer3_data->control_hdr.icmp.type = icmp_ptr[0];
    layer3_data->control_hdr.icmp.code = icmp_ptr[1];
    layer3_data->control_hdr.icmp.checksum = ntohs(*(const uint16_t *)(icmp_ptr + 2));
    layer3_data->control_hdr.icmp.id = ntohs(*(const uint16_t *)(icmp_ptr + 4));
    layer3_data->control_hdr.icmp.sequence = ntohs(*(const uint16_t *)(icmp_ptr + 6));

    *offset += ICMP_MIN_HEADER_LEN;
    return 0;
}

static int handleICMPv6(const uint8_t *buffer, size_t length, size_t *offset, layer3Data *layer3_data) {
    layer3_data->next_proto = layer3_next_icmpv6;

    if (length < *offset + ICMPV6_MIN_HEADER_LEN) {
        fprintf(stderr, "Layer 3 error: truncated ICMPv6 header\n");
        return -1;
    }

    const uint8_t *icmp6_ptr = buffer + *offset;
    layer3_data->control_hdr.icmpv6.type = icmp6_ptr[0];
    layer3_data->control_hdr.icmpv6.code = icmp6_ptr[1];
    layer3_data->control_hdr.icmpv6.checksum = ntohs(*(const uint16_t *)(icmp6_ptr + 2));
    layer3_data->control_hdr.icmpv6.id = ntohs(*(const uint16_t *)(icmp6_ptr + 4));
    layer3_data->control_hdr.icmpv6.sequence = ntohs(*(const uint16_t *)(icmp6_ptr + 6));

    *offset += ICMPV6_MIN_HEADER_LEN;
    return 0;
}

static void setUpIPv4(const uint8_t *ip_ptr, IPv4Header *v4) {
    v4->type_of_service = ip_ptr[1];
    v4->total_length = ntohs(*(const uint16_t *)(ip_ptr + 2));
    v4->id = ntohs(*(const uint16_t *)(ip_ptr + 4));

    uint16_t flags_frag = ntohs(*(const uint16_t *)(ip_ptr + 6));
    v4->flag_reserved = (flags_frag >> 15) & 0x01;
    v4->flag_dont_fragments = (flags_frag >> 14) & 0x01;
    v4->flag_more_fragments = (flags_frag >> 13) & 0x01;
    v4->fragment_offset = (flags_frag & 0x1FFF) * 8;

    v4->time_to_live = ip_ptr[8];
    v4->protocol = ip_ptr[9];
    v4->checksum = ntohs(*(const uint16_t *)(ip_ptr + 10));

    memcpy(v4->src_ip, ip_ptr + 12, IPV4_ADDR_LEN);
    memcpy(v4->dst_ip, ip_ptr + 16, IPV4_ADDR_LEN);

    if (v4->header_length_bytes > 5) {
        v4->has_options = true;
        v4->options_len = v4->header_length_bytes - IPV4_MIN_HEADER_LEN;
    } else {
        v4->has_options = false;
        v4->options_len = 0;
    }
}

static int handleNextProtocol(const uint8_t *buffer, size_t length, size_t *offset, 
    layer3Data *layer3_data, uint8_t protocol) {
    switch (protocol) {
        case IP_PROTO_TCP:
            layer3_data->next_proto = layer3_next_tcp;
            return 0;

        case IP_PROTO_UDP:
            layer3_data->next_proto = layer3_next_udp;
            return 0;

        case IP_PROTO_ICMP:
            return handleICMP(buffer, length, offset, layer3_data);

        case IP_PROTO_IPV6_ICMP:
            return handleICMPv6(buffer, length, offset, layer3_data);
        default:
            layer3_data->next_proto = layer3_next_none;
            return 0;
    }
}

static int parseIPv4(const uint8_t *buffer, size_t length, size_t *offset, layer3Data *layer3_data) {
    if (length < *offset + IPV4_MIN_HEADER_LEN) {
        fprintf(stderr, "Layer 3 error: truncated IPv4 header\n");
        return -1;
    }

    const uint8_t *ip_ptr = buffer + *offset;
    IPv4Header *v4 = &layer3_data->net_hdr.ipv4;

    uint8_t ver_ihl = ip_ptr[0];
    v4->version = (ver_ihl >> 4) & 0x0F;
    v4->header_length_bytes = (ver_ihl & 0x0F) * 4;

    if (v4->version != 4 || v4->header_length_bytes < IPV4_MIN_HEADER_LEN) {
        fprintf(stderr, "Layer 3 error: invalid IPv4 version (%u) or Internet Header Len (%u)\n", 
                v4->version, v4->header_length_bytes);
        return -1;
    }

    if (length < *offset + v4->header_length_bytes) {
        fprintf(stderr, "Layer 3 error: truncated IPv4 options\n");
        return -1;
    }

    setUpIPv4(ip_ptr, v4);

    *offset += v4->header_length_bytes;

    return handleNextProtocol(buffer, length, offset, layer3_data, v4->protocol);
}

static int parseIPv6(const uint8_t *buffer, size_t length, size_t *offset, layer3Data *layer3_data) {
    if (length < *offset + IPV6_HEADER_LEN) {
        fprintf(stderr, "Layer 3 error: truncated IPv6 header\n");
        return -1;
    }

    const uint8_t *ip_ptr = buffer + *offset;
    IPv6Header *v6 = &layer3_data->net_hdr.ipv6;

    uint32_t first_word = ntohl(*(const uint32_t *)ip_ptr);
    v6->version = (first_word >> 28) & 0x0F;
    v6->traffic_class = (first_word >> 20) & 0xFF;
    v6->flow_label = first_word & 0x000FFFFF;

    if (v6->version != 6) {
        fprintf(stderr, "Layer 3 error: invalid IPv6 version (%u)\n", v6->version);
        return -1;
    }

    v6->payload_len = ntohs(*(const uint16_t *)(ip_ptr + 4));
    v6->next_header = ip_ptr[6];
    v6->hop_limit = ip_ptr[7];

    memcpy(v6->src_ip, ip_ptr + 8, IPV6_ADDR_LEN);
    memcpy(v6->dst_ip, ip_ptr + 24, IPV6_ADDR_LEN);

    *offset += IPV6_HEADER_LEN;

    return handleNextProtocol(buffer, length, offset, layer3_data, v6->next_header);
}

int parseLayer3(const uint8_t *buffer, size_t length, size_t *offset, 
    Layer2NextProtocol l2_next_proto, layer3Data *layer3_data) {
    if (!buffer || !offset || !layer3_data) {
        return -1;
    }

    memset(layer3_data, 0, sizeof(layer3Data));

    if (l2_next_proto == layer2_next_ipv4) {
        layer3_data->ip_type = layer3_type_ipv4;
        return parseIPv4(buffer, length, offset, layer3_data);
    } else if (l2_next_proto == layer2_next_ipv6) {
        layer3_data->ip_type = layer3_type_ipv6;
        return parseIPv6(buffer, length, offset, layer3_data);
    }

    layer3_data->ip_type = layer3_type_none;
    return 0; 
}