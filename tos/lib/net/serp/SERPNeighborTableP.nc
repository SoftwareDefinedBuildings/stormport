#include <iprouting.h>
#include <lib6lowpan/ip.h>
#include <lib6lowpan/ip_malloc.h>
#include <lib6lowpan/in_cksum.h>
#include <serp_messages.h>

#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define RESET   "\033[0m"

#define SENDC   YELLOW
#define RECVC   GREEN
#define ERRORC  RED
#define INFOC   WHITE


module SERPNeighborTableP {
    provides interface SERPNeighborTable;
    provides interface Init;
} implementation {
    serp_neighbor_t neighbor_table[MAX_SERP_NEIGHBOR_COUNT];

#define compare_ipv6(node1, node2) \
  (!memcmp((node1), (node2), sizeof(struct in6_addr)))

    bool neighbors_are_equal(serp_neighbor_t *a, serp_neighbor_t *b) {
      bool res;
      //printf("Neighbor A: hop count %d power profile %d ip ", a->hop_count, a->power_profile);
      //printf_in6addr(&a->ip);
      //printf("\n");
      //printf("Neighbor B: hop count %d power profile %d ip ", b->hop_count, b->power_profile);
      //printf_in6addr(&b->ip);
      //printf("\n");
      res = (compare_ipv6(&a->ip, &b->ip) && (a->hop_count == b->hop_count) &&
              (a->power_profile == b->power_profile));
      //printf("RESULT %d\n", res);
      return res;
    }

    command error_t Init.init() {
        memset(neighbor_table, 0, sizeof(neighbor_table));
    }


    command error_t SERPNeighborTable.addNeighbor(struct in6_addr *addr, uint8_t hop_count, serp_power_type power_profile) {
        int i;
        serp_neighbor_t *entry;
        serp_neighbor_t neighbor;
        error_t err;

        printf(INFOC "Adding SERP neighbor table with IP ");
        printf_in6addr(addr);
        printf("\n" RESET);

        memcpy(&neighbor.ip, addr, sizeof(struct in6_addr));
        neighbor.hop_count = hop_count;
        neighbor.power_profile = power_profile;
        neighbor.valid = TRUE;

        // zero out top 64 bits
        neighbor.ip.s6_addr32[0] = 0;
        neighbor.ip.s6_addr32[1] = 0;
        neighbor.ip.s6_addr16[0] = htons(0xfe80);

        for (i=0; i < MAX_SERP_NEIGHBOR_COUNT; i++) {
            entry = &neighbor_table[i];
            // test for duplicate entry
            if (entry != NULL && compare_ipv6(&neighbor.ip, &entry->ip)) {
                return SUCCESS;
            }
        }

        // here, we know that we haven't added the entry yet

        // iterate through the table until we find an empty or invalid entry
        for (i = 0; i < MAX_SERP_NEIGHBOR_COUNT; i++) {
            if (!neighbor_table[i].valid) break;
        }
        if (i == MAX_SERP_NEIGHBOR_COUNT) {
            return FAIL;
        }
        // add ourselves to this entry
        memcpy(&neighbor_table[i].ip, &neighbor.ip, sizeof(struct in6_addr));
        neighbor_table[i].hop_count = neighbor.hop_count;
        neighbor_table[i].power_profile = neighbor.power_profile;
        neighbor_table[i].valid = 1;
        printf(INFOC "SUCCESS added IP ");
        printf_in6addr(&neighbor_table[i].ip);
        printf(" to neighbor table\n" RESET);
        return SUCCESS;
    }

    command serp_neighbor_t* SERPNeighborTable.getNeighbor(int index) {
        return &neighbor_table[index];
    }

    command void SERPNeighborTable.printNeighbor(int index) {

          serp_neighbor_t *entry;
          if (index >= MAX_SERP_NEIGHBOR_COUNT) return;

          entry = &neighbor_table[index];
          if (!entry->valid) return;
          printf_in6addr(&entry->ip);
          printf("    %d         %d          %d\n", entry->hop_count, entry->power_profile, entry->valid);
    }

    command bool SERPNeighborTable.isNeighbor(struct in6_addr *addr) {
        int i;
        serp_neighbor_t *entry;

        for (i=0; i < MAX_SERP_NEIGHBOR_COUNT; i++) {
            entry = &neighbor_table[i];
            //printf("COMPARE adding ");
            //printf_in6addr(addr);
            //printf(" test ");
            //printf_in6addr(&entry->ip);
            //printf("\n");
            if (compare_ipv6(addr, &entry->ip) ||
                (memcmp(&addr->s6_addr, &entry->ip.s6_addr, 16) == 0) ||
                (memcmp(&addr->s6_addr32[3], &entry->ip.s6_addr32[3], sizeof(uint32_t)) == 0)) {
                return TRUE;
            }
        }
        return FALSE;
    }

    command serp_neighbor_t* SERPNeighborTable.getLowestHopCount() {
        int i;
        serp_neighbor_t *entry;
        uint8_t hop_count = 0xFF;
        int lowest_index = MAX_SERP_NEIGHBOR_COUNT;

        for (i=0; i < MAX_SERP_NEIGHBOR_COUNT; i++) {
            entry = &neighbor_table[i];
            if (entry->valid && (entry->hop_count < hop_count)) {
                hop_count = entry->hop_count;
                lowest_index = i;
            }
        }

        // we want to fail if:
        if ((hop_count == 0xFF) || // if the hop count is still infinity
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
