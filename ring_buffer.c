#include <stdio.h>
#include <stdlib.h>

typedef struct ring_buffer {
    unsigned char *buffer;
    size_t head;
    size_t tail;
    size_t max; //of the buffer
    int full;
} ring_buffer_t;


int add2RingBuffer() {
    
    return 0;
}