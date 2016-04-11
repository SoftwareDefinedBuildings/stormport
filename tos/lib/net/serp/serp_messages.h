/*
 * Data structures for SERP routing
 */

#ifndef SERP_MESSAGES_H
#define SERP_MESSAGES_H

#include <icmp6.h>

/*** constants for SERP ***/
#define MAX_SERP_NEIGHBOR_COUNT 10

/*** SERP structs ***/
typedef enum {
    SERP_BATTERY_POWERED = 0x00,
    SERP_MAINS_POWERED = 0xFF
} serp_power_type;

// option attached to a router advertisement that
// is unicast do a node petititioning to be part of
// the mesh
struct nd_option_serp_mesh_info_t {
    // ND6_SERP_MESH_INFO
    uint8_t type;
    // option length is 3 (3 << 3 bytes)
    uint8_t option_length;
    // length in bits of the prefix
    uint8_t prefix_length;
    // the power profile of this mote
    serp_power_type powered;
    // the hop count from a border router of the sender
    uint8_t sender_hop_count;
    // should be 0
    uint8_t reserved1;
    // should be 0
    uint16_t reserved2;
    // the prefix of the mesh
    struct in6_addr prefix;
};

typedef struct {
    struct in6_addr ip;
    uint8_t hop_count;
    serp_power_type power_profile;
    int valid:1; // used for the neighbor table
} serp_neighbor_t;

#endif
