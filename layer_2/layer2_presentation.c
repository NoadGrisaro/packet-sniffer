#include "layer_2/layer2_types.h"
#include <stdio.h>

static void printMacAddress(const uint8_t mac[ETH_ADDRESS_LENGTH]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void printLayer2(const layer2Data *l2_data) {
    if (!l2_data) {
        return;
    }

    printf("--- Layer 2 (Data Link) ---\n");
    printf(" Protocol: Ethernet II\n");
    printf(" Destination MAC: ");
    printMacAddress(l2_data->eth.dst_mac);
    printf("\n Source MAC: ");
    printMacAddress(l2_data->eth.src_mac);
    printf("\n EtherType: 0x%04x\n", l2_data->eth.ethertype);

    if (l2_data->has_vlan) {
        printf("  [802.1Q VLAN Tag]\n");
        printf("    VLAN ID:  %u\n", l2_data->vlan.vlan_id);
        printf("    Priority: %u\n", l2_data->vlan.priority_code);
        printf("    DEI:      %u\n", l2_data->vlan.drop_eligible_indicator);
    }

    if (l2_data->next_proto == layer2_next_arp) {
        const ARPHeader *arp = &l2_data->payload.arp;
        printf("  [ARP Header]\n");
        printf("    Hardware Type: %u, Protocol Type: 0x%04x\n", arp->hardware_type, arp->protocol_type);
        printf("    Opcode: %u (%s)\n", arp->opcode,
               arp->opcode == 1 ? "ARP Request" : (arp->opcode == 2 ? "ARP Reply" : "Unknown"));
        printf("    Sender MAC: ");
        printMacAddress(arp->sender_mac);
        printf(" | Sender IP: %u.%u.%u.%u\n",
               arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
        printf("    Target MAC: ");
        printMacAddress(arp->target_mac);
        printf(" | Target IP: %u.%u.%u.%u\n",
               arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3]);
    }
}