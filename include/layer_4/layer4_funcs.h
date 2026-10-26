#pragma once

#include <stddef.h>
#include <stdint.h>
#include "layer_3/layer3_types.h"
#include "layer4_types.h"

int parseLayer4(const uint8_t *buffer, size_t length, size_t *offset, 
    Layer3NextProtocol layer3_next_proto, layer4Data *layer4_data);

void printLayer4(const layer4Data *layer4_data);