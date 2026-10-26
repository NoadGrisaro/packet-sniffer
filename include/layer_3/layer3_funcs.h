#pragma once

#include <stdint.h>
#include "layer_2/layer2_types.h"
#include "layer3_types.h"


int parseLayer3(const uint8_t *buffer, size_t length, size_t *offset, 
                 Layer2NextProtocol layer2_next_proto, layer3Data *layer3_data);

void printLayer3(const layer3Data *layer3_data);