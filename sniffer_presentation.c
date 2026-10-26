#include "sniffer_presentation.h"
#include <stdio.h>
#include <ctype.h>

#define BYTES_PER_LINE 16









static void printHexLine(size_t i, const uint8_t *buffer, size_t length) {
    for (size_t j = 0; j < BYTES_PER_LINE; j++) {
        if (i + j < length) {
            printf("%02x ", buffer[i + j]);
        } else {
            printf("   ");
        }
    }

}

static void printAsciiLine(size_t i, const uint8_t *buffer, size_t length){
    for (size_t j = 0; j < BYTES_PER_LINE; j++) {
        if (i + j < length) {
            uint8_t byte = buffer[i + j];
            printf("%c", isprint(byte) ? byte : '.');
        } else {
            break;
        }
    }

}

void printHexAsciiPayLoad(const uint8_t *buffer, size_t length) {
    if (!buffer || length == 0) {
        return;
    }

    printf("Packet Payload (Hex/ASCII)\n");

    for (size_t i = 0; i < length; i += BYTES_PER_LINE) {//prints a line
        printf("%04zx: ", i);

        printHexLine(i, buffer, length);
        printf(" |");
        printAsciiLine(i, buffer, length);        

        printf("|\n");
    }

    printf("\n");
}