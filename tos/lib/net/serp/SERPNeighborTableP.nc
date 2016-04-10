#include <serp_messages.h>
#include <iprouting.h>
#include <lib6lowpan/ip.h>
#include "blip_printf.h"

module SERPNeighborTableP {
    provides interface SERPNeighborTable;
} implementation {
    serp_neighbor_t neighbor_table[MAX_SERP_NEIGHBOR_COUNT];

    command error_t SERPNeighborTable.addNeighbor(serp_neighbor_t *neighbor) {
        int i;
        serp_neighbor_t *entry;

        // zero out top 64 bits
        neighbor->ip.s6_addr32[0] = 0;
        neighbor->ip.s6_addr32[1] = 0;

        for (i=0; i < MAX_SERP_NEIGHBOR_COUNT; i++) {
            entry = &neighbor_table[i];
            // test for duplicate entry
            if (neighbor != NULL && entry != NULL && (memcmp(&neighbor->ip, &entry->ip, 16) == 0)) {
                return SUCCESS;
            }
        }

        // here, we know that we haven't added the entry yet

        // the table is full
        if (neighbor_table[MAX_SERP_NEIGHBOR_COUNT-1].valid) return FAIL;

        // iterate through the table until we find an empty or invalid entry
        for (i = 0; i < MAX_SERP_NEIGHBOR_COUNT; i++) {
            if (!neighbor_table[i].valid) break;
        }
        // add ourselves to this entry
        neighbor_table[i] = *neighbor;
        return SUCCESS;
    }

    command serp_neighbor_t* SERPNeighborTable.getNeighbor(int index) {
        return &neighbor_table[index];
    }

    command serp_neighbor_t* SERPNeighborTable.getLowestHopCount() {
        int i;
        serp_neighbor_t *entry;
        uint8_t hop_count = 0xFF;
        int lowest_index = MAX_SERP_NEIGHBOR_COUNT;

        for (i=0; i < MAX_SERP_NEIGHBOR_COUNT; i++) {
            entry = &neighbor_table[i];
            if (entry->hop_count < hop_count) {
                hop_count = entry->hop_count;
                lowest_index = i;
            }
        }

        // we want to fail if:
        if ((hop_count = 0xFF) || // if the hop count is still infinity
            (lowest_index == MAX_SERP_NEIGHBOR_COUNT)) { // or if we didn't find anything
            return NULL;
        }
        // return the found entry
        return &neighbor_table[lowest_index];
    }

    command serp_neighbor_t* SERPNeighborTable.getLowestHopCountWithPower() {
        return NULL;
    }
}
