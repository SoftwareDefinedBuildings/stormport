#include <serp_messages.h>
interface SERPNeighborTable {

  // NOTE: neighbor table entries only use the LOWER 64-bits of the provided
  // address.

  // ignore the neighbor with the given address
  command error_t addNeighbor(struct in6_addr *addr, uint8_t hop_count, serp_power_type power_profile);

  command serp_neighbor_t* getNeighbor(int index);

  command bool isNeighbor(struct in6_addr *addr);

  command serp_neighbor_t* getLowestHopCount();

  command serp_neighbor_t* getLowestHopCountWithPower();
}
