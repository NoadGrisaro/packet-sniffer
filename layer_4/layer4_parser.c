#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "layer_3/layer3_types.h"
#include "layer_4/layer4_types.h"

static Layer4NextProtocol identifyAppProtocol(uint16_t src_port, uint16_t dst_port) {
    uint16_t p1 = src_port;
    uint16_t p2 = dst_port;

    if (p1 == 80  || p2 == 80)  return layer4_next_http;
    if (p1 == 443 || p2 == 443) return layer4_next_https;
    if (p1 == 53  || p2 == 53)  return layer4_next_dns;
    if (p1 == 67  || p2 == 67 || p1 == 68 || p2 == 68) return layer4_next_dhcp;
    if (p1 == 20  || p2 == 20 || p1 == 21 || p2 == 21) return layer4_next_ftp;
    if (p1 == 22  || p2 == 22)  return layer4_next_ssh;
    if (p1 == 123 || p2 == 123) return layer4_next_ntp;
    if (p1 == 23  || p2 == 23)  return layer4_next_telnet;

    return layer4_next_unknown;
}

static int initTcpValues(const uint8_t *buffer, size_t length, size_t *offset, layer4Data *layer4) {
    if (length < *offset + TCP_MIN_HEADER_LEN) {
        fprintf(stderr, "Layer 4 error: truncated TCP header\n");
        return -1;
    }

    const uint8_t *tcp_ptr = buffer + *offset;
    TCPHeader *tcp = &layer4->transport_hdr.tcp;

    tcp->src_port = ntohs(*(const uint16_t *)(tcp_ptr + 0));
    tcp->dst_port = ntohs(*(const uint16_t *)(tcp_ptr + 2));
    tcp->seq_num  = ntohl(*(const uint32_t *)(tcp_ptr + 4));
    tcp->ack_num  = ntohl(*(const uint32_t *)(tcp_ptr + 8));

    return 0;
}

static void flagTcpParsing(const uint8_t *tcp_ptr, TCPHeader *tcp) {
    uint8_t flags_byte = tcp_ptr[13];
    tcp->flag_cwr = (flags_byte >> 7) & 0x01;
    tcp->flag_ece = (flags_byte >> 6) & 0x01;
    tcp->flag_urg = (flags_byte >> 5) & 0x01;
    tcp->flag_ack = (flags_byte >> 4) & 0x01;
    tcp->flag_psh = (flags_byte >> 3) & 0x01;
    tcp->flag_rst = (flags_byte >> 2) & 0x01;
    tcp->flag_syn = (flags_byte >> 1) & 0x01;
    tcp->flag_fin = flags_byte & 0x01;

    tcp->window_size =ntohs(*(const uint16_t *)(tcp_ptr + 14));
    tcp->checksum =ntohs(*(const uint16_t *)(tcp_ptr + 16));
    tcp->urgent_pointer =ntohs(*(const uint16_t *)(tcp_ptr + 18));
}

static int parseTcpHeaderLength(const uint8_t *tcp_ptr, size_t length, size_t offset, TCPHeader *tcp) {
    uint8_t doff_byte = tcp_ptr[12];
    tcp->data_offset = (doff_byte >> 4) & 0x0F;
    tcp->header_length_bytes = tcp->data_offset * 4;

    if (tcp->header_length_bytes < TCP_MIN_HEADER_LEN) {
        fprintf(stderr, "Layer 4 error: invalid TCP data offset (%u)\n", tcp->data_offset);
        return -1;
    }

    if (length < offset + tcp->header_length_bytes) {
        fprintf(stderr, "Layer 4 error: truncated TCP options\n");
        return -1;
    }

    return 0;
}

static void parseTcpOptions(TCPHeader *tcp) {
    if (tcp->data_offset > 5) {
        tcp->has_options = true;
        tcp->options_len = tcp->header_length_bytes - TCP_MIN_HEADER_LEN;
    } else {
        tcp->has_options = false;
        tcp->options_len = 0;
    }
}

static int parseTCP(const uint8_t *buffer, size_t length, size_t *offset, layer4Data *layer4) {
    if (initTcpValues(buffer, length, offset, layer4) != 0) {
        return -1;
    }

    const uint8_t *tcp_ptr = buffer + *offset;
    TCPHeader *tcp = &layer4->transport_hdr.tcp;

    if (parseTcpHeaderLength(tcp_ptr, length, *offset, tcp) != 0) {
        return -1;
    }

    flagTcpParsing(tcp_ptr, tcp);
    parseTcpOptions(tcp);

    *offset += tcp->header_length_bytes;
    layer4->next_proto = identifyAppProtocol(tcp->src_port, tcp->dst_port);

    return 0;
}

static int parseUDP(const uint8_t *buffer, size_t length, size_t *offset, layer4Data *layer4) {
    if (length < *offset + UDP_HEADER_LEN) {
        fprintf(stderr, "Layer 4 error: truncated UDP header\n");
        return -1;
    }

    const uint8_t *udp_ptr = buffer + *offset;
    UDPHeader *udp = &layer4->transport_hdr.udp;

    udp->src_port = ntohs(*(const uint16_t *)(udp_ptr + 0));
    udp->dst_port = ntohs(*(const uint16_t *)(udp_ptr + 2));
    udp->length   = ntohs(*(const uint16_t *)(udp_ptr + 4));
    udp->checksum = ntohs(*(const uint16_t *)(udp_ptr + 6));

    *offset += UDP_HEADER_LEN;
    layer4->next_proto = identifyAppProtocol(udp->src_port, udp->dst_port);

    return 0;
}

int parseLayer4(const uint8_t *buffer, size_t length, size_t *offset, 
                Layer3NextProtocol layer3_next_proto, layer4Data *layer4_data) {
    if (!buffer || !offset || !layer4_data) {
        return -1;
    }

    memset(layer4_data, 0, sizeof(layer4Data));

    if (layer3_next_proto == layer3_next_tcp) {
        layer4_data->type = layer4_type_tcp;
        return parseTCP(buffer, length, offset, layer4_data);
    } else if (layer3_next_proto == layer3_next_udp) {
        layer4_data->type = layer4_type_udp;
        return parseUDP(buffer, length, offset, layer4_data);
    }

    layer4_data->type = layer4_type_none;
    layer4_data->next_proto = layer4_next_unknown;
    return 0;
}