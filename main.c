#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include "nic_sniffer.h"
#include "sniffer_presentation.h"

#include "layer_2/layer2_funcs.h"
#include "layer_2/layer2_types.h"

#include "layer_3/layer3_funcs.h"
#include "layer_3/layer3_types.h"

#include "layer_4/layer4_funcs.h"
#include "layer_4/layer4_types.h"

#include "layer_5_7/layer5_7_funcs.h"
#include "layer_5_7/layer5_7_types.h"

#define MAX_BUFFER_SIZE 65536// 64k 

static volatile bool loop_keep_running = true;

static void handleSigint(int sig_id) {
    (void)sig_id;
    loop_keep_running = false;
}

static int setUpNicConnection(const char *interface_name) {
    signal(SIGINT, handleSigint);

    int sock_fd = nicInit(interface_name);
    if (sock_fd < 0) {
        return -1;
    }

    printf("Sniffer listening on '%s'...\n", interface_name);
    return sock_fd;
}

int buildAndPrintLayer2(const uint8_t *buffer, size_t bytes_captured,
     size_t *offset, layer2Data *layer2_data) {
    if (parseLayer2(buffer, bytes_captured, offset, layer2_data) ==-1) {
        return -1;
    }
    printLayer2(layer2_data);
    return 0;
}

int buildAndPrintLayer3(const uint8_t *buffer, size_t bytes_captured,
        size_t *offset, const layer2Data *layer2_data, layer3Data *layer3_data) {

    if (parseLayer3(buffer, bytes_captured, offset, layer2_data->next_proto, layer3_data)==-1) {
        return -1;
    }

    printLayer3(layer3_data);
    return 0;
}

int buildAndPrintLayer4(const uint8_t *buffer, size_t bytes_captured,
        size_t *offset, const layer3Data *layer3_data, layer4Data *layer4_data) {

    if (parseLayer4(buffer, bytes_captured, offset, layer3_data->next_proto, layer4_data) ==-1) {
        return -1;
    }

    printLayer4(layer4_data);
    return 0;
}


int buildAndPrintLayer5_7(const uint8_t *buffer, size_t bytes_captured,
        size_t *offset, const layer4Data *layer4_data, layer5_7Data *layer5_7_data) {

    if (parseLayer5_7(buffer, bytes_captured, offset, layer4_data->next_proto, layer5_7_data)==-1) {
        return -1;
    }
    printLayer5_7(layer5_7_data);
    return 0;
}


int buildAndPrintAllLayers(const uint8_t *buffer, size_t bytes_captured) {
    size_t offset = 0;
    layer2Data layer2_data;
    layer3Data layer3_data;
    layer4Data layer4_data;
    layer5_7Data layer5_7_data;

    if (buildAndPrintLayer2(buffer, bytes_captured, &offset, &layer2_data) != 0) {
        fprintf(stderr, "Error building layer 2\n");
        return -1;
    }

    if (layer2_data.next_proto == layer2_next_arp || layer2_data.next_proto == layer2_next_none) {
        return 0;
    }

    if (buildAndPrintLayer3(buffer, bytes_captured, &offset, &layer2_data, &layer3_data) != 0) {
        fprintf(stderr, "Error building layer 3\n");
        return -1;
    }

    if (layer3_data.next_proto == layer3_next_icmp || layer3_data.next_proto == layer3_next_icmpv6
        || layer3_data.next_proto == layer3_next_none) {
        return 0;
    }

    if (buildAndPrintLayer4(buffer, bytes_captured, &offset, &layer3_data, &layer4_data) != 0) {
        fprintf(stderr, "Error building layer 4\n");
        return -1;
    }

    if (layer4_data.next_proto == layer4_next_unknown) {
        return 0;
    }

    
    if (buildAndPrintLayer5_7(buffer, bytes_captured, &offset, &layer4_data, &layer5_7_data) != 0) {
        fprintf(stderr, "Error building layer 5-7\n");
        return -1;
    }
    

    return 0;
}

static void listenMainLoop(int sock_fd) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    size_t packet_count = 0;

    while (loop_keep_running) {
        ssize_t bytes_captured = nicGetPacket(sock_fd, buffer, sizeof(buffer));
        if (bytes_captured < 0) {
            if (!loop_keep_running) {
                break;
            }
            perror("recvfrom failed");
            continue;
        }

        printf("Packet #%zu: %zd bytes\n", packet_count++, bytes_captured);
        if(!buildAndPrintAllLayers(buffer, (size_t)bytes_captured)){
            printHexAsciiPayLoad(buffer, (size_t)bytes_captured);
        }
    }
}

static void closeConnection(int sock_fd, const char *interface_name) {
    printf("\nStopping sniffer...\n");
    nicClose(sock_fd, interface_name);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <interface_name>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *interface_name = argv[1];

    int sock_fd = setUpNicConnection(interface_name);
    if (sock_fd < 0) {
        return EXIT_FAILURE;
    }

    listenMainLoop(sock_fd);

    closeConnection(sock_fd, interface_name);

    return EXIT_SUCCESS;
}