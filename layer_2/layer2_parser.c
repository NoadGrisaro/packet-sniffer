#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "layer_2/layer2_types.h"

int initValues(const uint8_t *buffer, size_t length, layer2Data *layer2_data) {
    if (!buffer || !layer2_data) {
        return -1;
    }

    if (length < ETH_HEADER_LEN) {
        fprintf(stderr, "Layer 2 error: packet truncated (length < 14)\n");
        return -1;
    }

    memset(layer2_data, 0, sizeof(layer2Data));
    return 0;
}

void initEth(const uint8_t *buffer, size_t *offset, layer2Data *layer2_data) {
    memcpy(layer2_data->eth.dst_mac, buffer, ETH_ADDRESS_LENGTH);
    memcpy(layer2_data->eth.src_mac, buffer + ETH_ADDRESS_LENGTH, ETH_ADDRESS_LENGTH);

    uint16_t current_ethertype = ntohs(*(const uint16_t *)(buffer + 2 * ETH_ADDRESS_LENGTH));
    layer2_data->eth.ethertype = current_ethertype;
    *offset = ETH_HEADER_LEN;
}

int handleVlan(const uint8_t *buffer, size_t length, size_t *offset, layer2Data *layer2_data) {
    if (length < *offset + VLAN_HEADER_LEN) {
        fprintf(stderr, "Layer 2 error: truncated VLAN header\n");
        return -1;
    }

    layer2_data->has_vlan = true;
    layer2_data->vlan.tpid = layer2_data->eth.ethertype;

    uint16_t tag_cntrl_info = ntohs(*(const uint16_t *)(buffer + *offset));

    layer2_data->vlan.priority_code = (tag_cntrl_info >> 13) & 0x07;
    layer2_data->vlan.drop_eligible_indicator = (tag_cntrl_info >> 12) & 0x01;
    layer2_data->vlan.vlan_id = tag_cntrl_info & 0x0FFF;

    *offset += 2;

    // עדכון ה-EtherType לזה שמופיע בתוך ה-VLAN
    uint16_t inner_ethertype = ntohs(*(const uint16_t *)(buffer + *offset));
    layer2_data->eth.ethertype = inner_ethertype;
    *offset += 2;

    return 0;
}

int applyNextLayer2Protocol(const uint8_t *buffer, size_t length, size_t *offset, layer2Data *layer2_data) {
    switch (layer2_data->eth.ethertype) {
        case ETHERTYPE_ARP:
            if (length < *offset + ARP_HEADER_LEN) {
                fprintf(stderr, "Layer 2 error: truncated ARP header\n");
                return -1;
            }

            layer2_data->next_proto = layer2_next_arp;

            const uint8_t *arp_ptr = buffer + *offset;
            layer2_data->payload.arp.hardware_type = ntohs(*(const uint16_t *)(arp_ptr + 0));
            layer2_data->payload.arp.protocol_type =ntohs(*(const uint16_t *)(arp_ptr + 2));
            layer2_data->payload.arp.hardware_len =arp_ptr[4];
            layer2_data->payload.arp.protocol_len =arp_ptr[5];
            layer2_data->payload.arp.opcode =ntohs(*(const uint16_t *)(arp_ptr + 6));

            memcpy(layer2_data->payload.arp.sender_mac,arp_ptr + 8, ETH_ADDRESS_LENGTH);
            memcpy(layer2_data->payload.arp.sender_ip, arp_ptr + 14, 4);
            memcpy(layer2_data->payload.arp.target_mac,arp_ptr + 18, ETH_ADDRESS_LENGTH);
            memcpy(layer2_data->payload.arp.target_ip, arp_ptr + 24, 4);

            *offset += ARP_HEADER_LEN;
            break;

        case ETHERTYPE_IPV4:
            layer2_data->next_proto = layer2_next_ipv4;
            break;

        case ETHERTYPE_IPV6:
            layer2_data->next_proto = layer2_next_ipv6;
            break;

        default:
            layer2_data->next_proto = layer2_next_none;
            break;
    }

    return 0;
}

int parseLayer2(const uint8_t *buffer, size_t length, size_t *offset, layer2Data *layer2_data) {
    if (!offset) {
        return -1;
    }

    if (initValues(buffer, length, layer2_data) == -1) {
        return -1;
    }

    initEth(buffer, offset, layer2_data);

    if (layer2_data->eth.ethertype == ETHERTYPE_VLAN) {
        if (handleVlan(buffer, length, offset, layer2_data) == -1) {
            return -1;
        }
    }

    if (applyNextLayer2Protocol(buffer, length, offset, layer2_data) == -1) {
        return -1;
    }

    return 0;
}