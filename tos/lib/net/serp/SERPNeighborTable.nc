#include <serp_messages.h>
interface SERPNeighborTable {

  // NOTE: neighbor table entries only use the LOWER 64-bits of the provided
  // address.

  // ignore the neighbor with the given address
  command error_t addNeighbor(serp_neighbor_t *neighbor);

  command serp_neighbor_t* getNeighbor(int index);

  command serp_neighbor_t* getLowestHopCount();

  command serp_neighbor_t* getLowestHopCountWithPower();
}
