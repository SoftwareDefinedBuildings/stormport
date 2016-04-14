/*
 * Data structures for SERP routing
 */

#ifndef SERP_MESSAGES_H
#define SERP_MESSAGES_H

#include <icmp6.h>

/*** constants for SERP ***/
#define MAX_SERP_NEIGHBOR_COUNT 10
#define MAX_SERP_NEIGHBOR_MSG 2
#define IPV6_ADDR_ALL_ROUTERS "ff02::2"

/*** SERP structs ***/
typedef enum {
    SERP_BATTERY_POWERED = 0x00,
    SERP_MAINS_POWERED = 0xFF
} serp_power_type;

typedef struct {
    struct in6_addr ip;
    uint8_t hop_count;
    serp_power_type power_profile;
    int valid:1; // used for the neighbor table
} serp_neighbor_t;

/*** Routing options ***/

// Router Advertisement - Mesh Info
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

// Router Advertisement - Mesh Announcement
// option attached to RA messages to announce to the mesh
// - preferred parent (e.g. default route)
// - list of reachable downstream neighbors
struct nd_option_serp_mesh_announcement_t {
    // ND6_SERP_MESH_ANN
    uint8_t type;
    // option length is 3 (3 << 3 bytes)
    uint8_t option_length;
    // hop count
    uint8_t hop_count;
    // number of neighbors included
    uint8_t neighbor_count;
    // list of reachable neighbors
    // TODO: right now this uses unique 2-byte identifiers for
    // nodes. We'll want to do prefix encoding for compression of
    // the ful 64-bit lower addresses
    uint16_t neighbors[2];
    // the preferred parent/default route chosen
    struct in6_addr parent;
};

#endif
