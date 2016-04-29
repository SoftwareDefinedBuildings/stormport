/*
 * Data structures for SERP routing
 */

#ifndef SERP_MESSAGES_H
#define SERP_MESSAGES_H

#include <icmp6.h>

/*** constants for SERP ***/
#define MAX_SERP_NEIGHBOR_COUNT 20
#define MAX_SERP_NEIGHBOR_MSG 8
#define IPV6_ADDR_ALL_ROUTERS "ff02::2"
#define WAIT_BEFORE_SEND_ANNOUNCEMENT 5000 //  5 seconds

/*** SERP structs ***/
typedef enum {
    SERP_BATTERY_POWERED = 0x00,
    SERP_MAINS_POWERED = 0xFF
} serp_power_type;

typedef struct {
    struct in6_addr ip;
    uint8_t hop_count;
    serp_power_type power_profile;
    bool valid;
} serp_neighbor_t;

/*** Routing options ***/

// Router Advertisement - Mesh Info
// option attached to a router advertisement that
// is unicast do a node petititioning to be part of
// the mesh
struct nd_option_serp_mesh_info_t {
    // ND6_SERP_MESH_INFO
    uint8_t type;
    // option length is 2
    uint8_t option_length;
    // length in bits of the prefix
    uint8_t prefix_length;
    // the power profile of this mote
    serp_power_type powered;
    // 4 bytes

    // the hop count from a border router of the sender
    uint8_t sender_hop_count;
    uint8_t neighbor_count;
    // this 
    uint16_t reserved0;
    // 4 bytes

    uint16_t neighbors[8];
    // 4 bytes

    // the prefix of the mesh
    struct in6_addr prefix;
    // 4 bytes
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
    // 4 bytes

    // list of reachable neighbors
    // TODO: right now this uses unique 2-byte identifiers for
    // nodes. We'll want to do prefix encoding for compression of
    // the ful 64-bit lower addresses
    uint16_t neighbors[8];
    // 4 bytes

    // the preferred parent/default route chosen
    struct in6_addr parent;
    // 4 bytes
};

/*** debugging ***/

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


#endif
