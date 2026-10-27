#include "nic_sniffer.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

static int nicCreateRawSocket(void) {
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));//pass this socket all kinds of protocols
    if (sock_fd < 0) {
        perror("Failed to open raw socket");
        return -1;
    }
    return sock_fd;
}

static int nicGetInterfaceIndex(int sock_fd, const char *interface_name) {
    if (!interface_name) {
        fprintf(stderr, "Interface name is null\n");
        return -1;
    }

    struct ifreq ifr;//command struct to network
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {//get the id from the network interfaces table
        perror("Failed to find interface index (SIOCGIFINDEX)");
        return -1;
    }
    return ifr.ifr_ifindex;//return the index from the network interface table in the kernel
}

static int nicBind2Interface(int sock_fd, int interface_index) {
    struct sockaddr_ll netwrok_interface_socket;
    memset(&netwrok_interface_socket, 0, sizeof(netwrok_interface_socket));
    netwrok_interface_socket.sll_family = AF_PACKET;//works on level 2
    netwrok_interface_socket.sll_ifindex = interface_index;
    netwrok_interface_socket.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, (struct sockaddr *)&netwrok_interface_socket, sizeof(netwrok_interface_socket))
    <0) {//socket will only listen now only to our interface
        perror("Failed to bind socket to interface");
        return -1;
    }
    return 0;
}

static int nicSet2PromiscuousMode(int sock_fd, int interface_index) {
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = interface_index;
    mr.mr_type = PACKET_MR_PROMISC;//set to listen mode that allows to capture all packets on the network

    if (setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
     &mr, sizeof(mr)) < 0) {//apply socket changes
        perror("[-] Failed to enable promiscuous mode");
        return -1;
    }
    return 0;
}

static int nicDisablePromiscuousMode(int sock_fd, int interface_index) {
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = interface_index;
    mr.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(sock_fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        perror("Failed to disable promiscuous mode");
        return -1;
    }

    return 0;
}

int nicInit(const char *interface_name) {
    int sock_fd = nicCreateRawSocket();
    if (sock_fd < 0) {
        return -1;
    }

    int interface_index = nicGetInterfaceIndex(sock_fd, interface_name);
    if (interface_index < 0) {
        close(sock_fd);
        return -1;
    }

    if (nicBind2Interface(sock_fd, interface_index) < 0) {
        close(sock_fd);
        return -1;
    }

    if (nicSet2PromiscuousMode(sock_fd, interface_index) < 0) {
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

ssize_t nicGetPacket(int sock_fd, uint8_t *buffer, size_t buffer_size) {
    return recvfrom(sock_fd, buffer, buffer_size, 0, NULL, NULL);
}

void nicClose(int sock_fd, const char *interface_name) {
    if (sock_fd < 0) {
        return;
    }

    if (interface_name) {
        int interface_index = nicGetInterfaceIndex(sock_fd, interface_name);
        if (interface_index >= 0) {
            nicDisablePromiscuousMode(sock_fd, interface_index);
        }
    }

    close(sock_fd);
}