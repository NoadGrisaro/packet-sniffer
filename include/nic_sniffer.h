#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int nicInit(const char *network_interface);
ssize_t nicGetPacket(int sock_fd, uint8_t *buffer, size_t buffer_size);
void nicClose(int sock_fd, const char *network_interface);