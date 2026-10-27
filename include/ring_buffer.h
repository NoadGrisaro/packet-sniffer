#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#define RING_BUFFER_CAPACITY 1024
#define RING_BUFFER_MASK (RING_BUFFER_CAPACITY - 1)
#define PACKET_MAX_BYTES 65536//64 K

typedef struct {
    uint8_t data[PACKET_MAX_BYTES];
    size_t  length;
} rawPacket;//the whole packet. from layer 2 to layer 5-7

typedef struct {
    rawPacket entries[RING_BUFFER_CAPACITY];
    _Atomic size_t head;
    _Atomic size_t tail; 
} ringBuffer;

void ringBufferInit(ringBuffer *rb);
int ringBufferPush(ringBuffer *rb, const uint8_t *data, size_t length);
int ringBufferPop(ringBuffer *rb, rawPacket *entry_out);