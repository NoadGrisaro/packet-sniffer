#pragma once

#include <stddef.h>
#include <stdint.h>
#include "layer2_types.h"

/**
 * @brief Parses Layer 2 Ethernet frame headers, including optional 802.1Q VLAN tags.
 *
 * Extracts MAC addresses, determines the encapsulated EtherType, handles VLAN
 * tagging if present, and advances the buffer offset to the start of the Layer 3 payload.
 *
 * @param[in]     buffer  Pointer to the raw packet buffer received from the network.
 * @param[in]     length  Total size of the captured packet in bytes.
 * @param[in,out] offset  Pointer to current read offset; updated to point past Layer 2 headers.
 * @param[out]    l2_data Pointer to the destination struct where parsed Layer 2 metadata is stored.
 *
 * @return 0 on successful parsing, or a negative value if the header is truncated or malformed.
 */
int parseLayer2(const uint8_t *buffer, size_t length, size_t *offset, layer2Data *l2_data);

/**
 * @brief Prints parsed Layer 2 header information to standard output.
 *
 * Displays source and destination MAC addresses, EtherType, and VLAN metadata
 * (TPID, PCP, DEI, VID) if a VLAN tag was detected.
 *
 * @param[in] l2_data Pointer to the parsed Layer 2 data structure to display.
 */
void printLayer2(const layer2Data *l2_data);