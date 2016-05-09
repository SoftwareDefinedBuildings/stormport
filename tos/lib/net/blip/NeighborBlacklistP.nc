/**
 * Helpful little module to enforce routing topologies by restricting which nodes can get added
 * to the neighbor/forwarding table in blip
 *
 * @author Gabe Fierro <gtfierro@eecs.berkeley.edu>
 */

#include <iprouting.h>
#include <lib6lowpan/ip.h>
#include "blip_printf.h"

module NeighborBlacklistP {
    provides {
        interface NeighborBlacklist;
    }
} implementation {

    struct blacklist_entry {
        int valid:1;
        struct in6_addr address;
    };

    // basically using the same structure as IPForwardingEngineP
    struct blacklist_entry blacklist_table[1];

    void printIgnore(struct in6_addr *addr) {
#ifndef BLIP_STFU
        printf("\033[31;1mIgnoring");
        printf_in6addr(addr);
        printf("\n\033[0m");
#endif
    }

    /**
     * Given an ipv6 address of a neighbor, we mask out the top 64 bits, because
     * the lower 64 bits are the part that actually identify the neighbor (that is,
     * we want to remain indifferent to whatever prefix is being used).
     * We search the table for an entry that matches our given neighbor address.
     * If we find one, we return success, else we add it to the table.
     */
    command error_t NeighborBlacklist.ignore(struct in6_addr *neighbor) {
        int i;
        struct blacklist_entry *entry;

        // zero out top 64 bits
        neighbor->s6_addr32[0] = 0;
        neighbor->s6_addr32[1] = 0;
        for (i = 0; i < ROUTE_TABLE_SZ; i++) {
            entry = &blacklist_table[i];
            if (neighbor != NULL && entry != NULL && (memcmp(&entry->address, neighbor, 16) == 0)) {
                // we found this entry already
                printIgnore(neighbor);
                return SUCCESS;
            }
        }
        // if we're here, then the entry doesn't exist yet. Using a simplified
        // version of alloc_entry from IPForwardingEngineP

        // if table is full, then we FAIL
        if (blacklist_table[ROUTE_TABLE_SZ-1].valid) return FAIL;

        // go through until we find an empty entry
        for (i = 0; i < ROUTE_TABLE_SZ; i++) {
            if (!blacklist_table[i].valid) break;
        }
        // add ourselves to this entry
        blacklist_table[i].valid = 1;
        blacklist_table[i].address = *neighbor;

        printIgnore(neighbor);
        return SUCCESS;
    }

    // performs same as .ignore, but converts from a char* first
    command error_t NeighborBlacklist.ignoreAddrFromString(char *addr) {
        struct in6_addr newaddr;
        memset(&newaddr, 0, sizeof(newaddr));
        inet_pton6(addr, &newaddr);
        call NeighborBlacklist.ignore(&newaddr);
    }

    command void NeighborBlacklist.listIgnored() {
        int i;
        struct blacklist_entry *entry;
        if (!blacklist_table[i].valid) { 
            return; 
        }
#ifndef BLIP_STFU
        printf("\n\nIgnoring following neighbors:\n");
        for (i = 0; i < ROUTE_TABLE_SZ; i++) {
            entry = &blacklist_table[i];
            if (entry->valid) {
                printf("\nIgnore ");
                printf_in6addr(&entry->address);
                printf("\n");
            }
        }
        printf("\n");
#endif
    }

    command error_t NeighborBlacklist.unignore(struct in6_addr *neighbor) {
        return SUCCESS;
    }

    /**
     * This method returns true if the LOWER 64 bits of the provided address
     * are contained in the blacklist table
     */
    command bool NeighborBlacklist.ignored(struct in6_addr *address) {
        int i;
        struct blacklist_entry *entry;
        // fail early
        if (!blacklist_table[0].valid) return FALSE;

        for (i = 0; i < ROUTE_TABLE_SZ; i++) {
            entry = &blacklist_table[i];
            if (entry->valid &&
                (memcmp(&entry->address.s6_addr32[2], &address->s6_addr32[2], 4) == 0) &&
                (memcmp(&entry->address.s6_addr32[3], &address->s6_addr32[3], 4) == 0)) {
                return TRUE;
            }
        }
        return FALSE;
    }
}
