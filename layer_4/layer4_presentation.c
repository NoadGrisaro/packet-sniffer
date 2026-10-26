#include <stdio.h>
#include "layer_4/layer4_types.h"

static const char *appProtoToString(Layer4NextProtocol proto) {
    switch (proto) {
        case layer4_next_http:   return "HTTP";
        case layer4_next_https:  return "HTTPS";
        case layer4_next_dns:    return "DNS";
        case layer4_next_dhcp:   return "DHCP";
        case layer4_next_ftp:    return "FTP";
        case layer4_next_ssh:    return "SSH";
        case layer4_next_ntp:    return "NTP";
        case layer4_next_telnet: return "Telnet";
        default:                 return "Unknown";
    }
}

void printLayer4(const layer4Data *layer4) {
    if (!layer4 || layer4->type == layer4_type_none) {
        return;
    }

    printf("--- Layer 4 (Transport) ---\n");

    if (layer4->type == layer4_type_tcp) {
        const TCPHeader *tcp = &layer4->transport_hdr.tcp;
        printf("  Protocol: TCP\n");
        printf("  Source Port:      %u\n", tcp->src_port);
        printf("  Destination Port: %u\n", tcp->dst_port);
        printf("  Sequence Number:  %u\n", tcp->seq_num);
        printf("  Ack Number:       %u\n", tcp->ack_num);
        printf("  Header Length:    %u bytes (Data Offset: %u)\n", 
               tcp->header_length_bytes, tcp->data_offset);
        
        printf("  Flags:            [");
        if (tcp->flag_cwr) printf("CWR ");
        if (tcp->flag_ece) printf("ECE ");
        if (tcp->flag_urg) printf("URG ");
        if (tcp->flag_ack) printf("ACK ");
        if (tcp->flag_psh) printf("PSH ");
        if (tcp->flag_rst) printf("RST ");
        if (tcp->flag_syn) printf("SYN ");
        if (tcp->flag_fin) printf("FIN ");
        printf("]\n");

        printf("  Window Size:      %u\n", tcp->window_size);
        printf("  Checksum:         0x%04x\n", tcp->checksum);
        printf("  Urgent Pointer:   %u\n", tcp->urgent_pointer);
        if (tcp->has_options) {
            printf("  Options:          Present (%u bytes)\n", tcp->options_len);
        }
    } else if (layer4->type == layer4_type_udp) {
        const UDPHeader *udp = &layer4->transport_hdr.udp;
        printf("  Protocol: UDP\n");
        printf("  Source Port:      %u\n", udp->src_port);
        printf("  Destination Port: %u\n", udp->dst_port);
        printf("  Length:           %u bytes\n", udp->length);
        printf("  Checksum:         0x%04x\n", udp->checksum);
    }

    if (layer4->next_proto != layer4_next_unknown) {
        printf("  Identified Next Protocol: %s\n", appProtoToString(layer4->next_proto));
    }
}