#include "ring_buffer.h"
#include <string.h>

void ringBufferInit(ringBuffer *rb) {
    if (!rb) return;
    atomic_init(&rb->head, 0);
    atomic_init(&rb->tail, 0);
}

int ringBufferPush(ringBuffer *rb, const uint8_t *data, size_t length) {
    if (!rb || !data || length == 0 || length > PACKET_MAX_BYTES) {
        return -1;
    }

    size_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);

    // בדיקה האם התור מלא
    if ((head - tail) >= RING_BUFFER_CAPACITY) {
        return -1; // the package will be drop
    }

    size_t index = head & RING_BUFFER_MASK;
    memcpy(rb->entries[index].data, data, length);
    rb->entries[index].length = length;

    atomic_store_explicit(&rb->head, head + 1, memory_order_release);
    return 0;
}

int ringBufferPop(ringBuffer *rb, rawPacket *entry_out) {
    if (!rb || !entry_out) {
        return -1;
    }

    size_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);

    //check if the queue is empty
    if (tail == head) {
        return -1;
    }

    size_t index = tail & RING_BUFFER_MASK;
    memcpy(entry_out->data, rb->entries[index].data, rb->entries[index].length);
    entry_out->length = rb->entries[index].length;

    // Release מבטיח שהקריאה הסתיימה לפני שמשחררים את התא ל-Producer
    atomic_store_explicit(&rb->tail, tail + 1, memory_order_release);
    return 0;
}