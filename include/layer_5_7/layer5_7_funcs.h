#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "layer_4/layer4_types.h"
#include "layer_5_7/layer5_7_types.h"

int parseLayer5_7(const uint8_t *buffer, size_t length, size_t *offset,
                  Layer4NextProtocol l4_next_proto, layer5_7Data *layer5_7_data);

void printLayer5_7(const layer5_7Data *layer5_7_data);