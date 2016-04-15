#include <lib6lowpan/ip_malloc.h>
#include <lib6lowpan/in_cksum.h>
#include <lib6lowpan/ip.h>
#include "neighbor_discovery.h"
#include <serp_messages.h>

module SERPRoutingEngineP {
    provides {
        interface StdControl as SERPControl;
        interface RootControl;
    }
    uses {
        interface IP as IP_RA;
        interface IP as IP_RS;
        interface Random;
        interface IPAddress;
        interface Ieee154Address;
        interface NeighborDiscovery;
        interface SERPNeighborTable;
        interface ForwardingTable;
        interface Timer<TMilli> as RouterAdvMeshAnnTimer;
        interface Timer<TMilli> as PrintTimer;
    }
} implementation {

#define ADD_SECTION(SRC, LEN) ip_memcpy(cur, (uint8_t *)(SRC), LEN);\
  cur += (LEN); length += (LEN);
#define compare_ipv6(node1, node2) \
  (!memcmp((node1), (node2), sizeof(struct in6_addr)))

  // SERP Routing values

  // current hop count. Start at 0xff == infinity
  uint8_t hop_count = 0xff;
  // whether or not we are part of a mesh. This should be set to TRUE if we are a root node
  bool part_of_mesh = FALSE;
  // number of outstanding RS messages
  uint8_t outstanding_RS_messages = 0;

  struct in6_addr BCAST_ADDRESS;
  struct in6_addr unicast_rs_destination;

  serp_neighbor_t preferred_parent;

  /**** Global Vars ***/
  // whether or not the routing protocol is running
  bool running = FALSE;

  // if this node is root
  bool I_AM_ROOT = FALSE;

  // this is where we store the LL address of the node
  // who sent us a broadcast RS. We need to unicast an RA
  // back to them.
  //struct in6_addr ra_meshinfo_destination;

  // initial period becomes 2 << (10 - 1) == 512 milliseconds
  uint32_t tx_interval_min = 10;

  // Predelcarations
  task void send_mesh_announcement_RA();
  task void send_mesh_info_RA();
  task void send_rs_task ();
  task void startMeshAdvertising();

  task void init() {
    if (I_AM_ROOT) {
        // we don't actually advertise the mesh. It is driven entirely
        // by clients that want to join
        post startMeshAdvertising();
    } else {
    }
  }

  task void startMeshAdvertising() {
    call RouterAdvMeshAnnTimer.startPeriodic(10000);
  }

  // Returns the length of the added option
  uint8_t add_sllao (uint8_t* data) {
    struct nd_option_slla_t sllao;

    sllao.type = ND6_OPT_SLLAO;
    sllao.option_length = 2; // length in multiples of 8 octets, need 10 bytes
                             // so we must round up to 16.
    sllao.ll_addr = call Ieee154Address.getExtAddr();

    ip_memcpy(data, (uint8_t*) &sllao, sizeof(struct nd_option_slla_t));
    memset(data+sizeof(struct nd_option_slla_t), 0,
      16-sizeof(struct nd_option_slla_t));
    return 16;
  }

  bool neighbors_are_equal(serp_neighbor_t *a, serp_neighbor_t *b) {
    bool res;
    res = (compare_ipv6(&a->ip, &b->ip) && (a->hop_count == b->hop_count) &&
            (a->power_profile == b->power_profile));
    return res;
  }

/*
 What's the logic for handling an incoming RA? When we receive an RA and we are *not* part of a mesh, we need
 to become part of the mesh. The received RA contains:
 - prefix for the mesh (and the prefix length)
 - hop count of the sender
 - power profile of the sender
 What we need is a table of "neighbors" that indexes this heard information. Currently, we only send the mesh
 info RA if we are part of a mesh, but if we change so we always send an RA, we can tell if a RA sender is part
 of the mesh or not by what their hop count is (0xff == no, else yes).

 Table is: serp_neighbor_t neighbors[MAX_NEIGHBOR_COUNT];
 MAX_NEIGHBOR_COUNT needs to be calculated: we want the control message overhead to be below a certain
 percentage, so MAX_NEIGHBOR_COUNT should be the maximum number of neighbors with whom the exchange of
 control traffic is expected to be below a given amount.
 For now, lets just go with 10.

 The neighbor table should support the following methods:
 - find neighbor with lowest hop count
 - find neighbor w/ lowest hop count, using power profile (see note below)
 - remove neighbor
 - add neighbor
**/

  /***** Handle Incoming RA *****/
  event void IP_RA.recv(struct ip6_hdr *hdr,
                        void *packet,
                        size_t len,
                        struct ip6_metadata *meta) {

    struct nd_router_advertisement_t* ra;
    uint8_t* cur = (uint8_t*) packet;
    uint8_t type;
    uint8_t olen;
    error_t err;

    printf(RECVC "Received an SERP RA from");
    printf_in6addr(&hdr->ip6_src);
    printf(RESET "\n");

    //TODO: what's the right behavior if it has a different prefix than ours?

    if (len < sizeof(struct nd_router_advertisement_t)) return;
    ra = (struct nd_router_advertisement_t*) packet;

    // skip the base of the packet
    cur += sizeof(struct nd_router_advertisement_t);
    len -= sizeof(struct nd_router_advertisement_t);

    // because we've heard a sender, we can process it!
    // add route to the sender via itself
    call ForwardingTable.addRoute(hdr->ip6_src.s6_addr, 128, &hdr->ip6_src, ROUTE_IFACE_154);
    // add the sender to the neighbor table
    if (part_of_mesh) {
      err = call SERPNeighborTable.addNeighbor(&hdr->ip6_src, hop_count+1, 0xFF);
    }

    if (err != SUCCESS) {
        printf(ERRORC "2Error adding to serp neighbor table\n" RESET);
    }

    // Iterate through all of the SERP-specific options
    while (TRUE) {
      if (len < 2) break;
      // Get the type byte of the first option
      type = *cur;
      olen = *(cur+1) << 3;

      if (len < olen) return;
      switch (type) {
      case ND6_SERP_MESH_INFO:
        {
            struct nd_option_serp_mesh_info_t* meshinfo;
            serp_neighbor_t nn;
            struct route_entry* entry;
            struct in6_addr our_address;
            error_t err;
            int i;

            // do not process if we are root
            if (I_AM_ROOT) break;

            meshinfo = (struct nd_option_serp_mesh_info_t*) cur;
            printf(RECVC "Received a SERP Mesh Info message with pfx len: %d, power: %d, hop_count: %d and prefix ", meshinfo->prefix_length, meshinfo->powered, meshinfo->sender_hop_count);
            printf_in6addr(&meshinfo->prefix);
            printf("\n" RESET);

            if (meshinfo->prefix_length > 0) {
              part_of_mesh = TRUE;
              call NeighborDiscovery.setPrefix(&meshinfo->prefix, meshinfo->prefix_length, IP6_INFINITE_LIFETIME, IP6_INFINITE_LIFETIME);
              printf(INFOC "Setting prefix from meshinfo msg to ");
              printf_in6addr(&meshinfo->prefix);
              printf("\n" RESET);
            }

            // populate a neighbor table entry
            err = call SERPNeighborTable.addNeighbor(&hdr->ip6_src, meshinfo->sender_hop_count,meshinfo->powered);
            if (err != SUCCESS) {
                printf(ERRORC "3Error adding to serp neighbor table\n" RESET);
                break;
            }

            // test if we are in the list of neighbors in the msh info message. If we are NOT,
            // then we need to respond!
            call IPAddress.getLLAddr(&our_address);
            for (i=0;i<meshinfo->neighbor_count;i++) {
                printf(INFOC "Mesh info contains node %x\n" RESET, htons(meshinfo->neighbors[i]));
                if (our_address.s6_addr16[7] == meshinfo->neighbors[i]) {
                    break;
                }
            }
            if (meshinfo->neighbor_count == 0 || i == meshinfo->neighbor_count) { // we were not in the list
                printf(ERRORC "%x Was not in neighbor list \n" RESET, htons(our_address.s6_addr16[7]));
                // save the unicast destination
                memcpy(&unicast_rs_destination, &hdr->ip6_src, sizeof(struct in6_addr));
                post send_rs_task();
            }

            // wait some time before sending the announcement to make sure we have a change to
            // get up-to-date info
            if (!call RouterAdvMeshAnnTimer.isRunning()) {
                call RouterAdvMeshAnnTimer.startOneShot(call Random.rand32() % WAIT_BEFORE_SEND_ANNOUNCEMENT);
            }

            break;
        }
      case ND6_SERP_MESH_ANN:
        // This should be received as a broadcast from a "lower" node in the mesh.
        // If the hop count of this node is higher than ours, we should ignore this message
        // TODO: (or maybe use it to install point-to-point routes?).
        // The announcement contains the nodeids (lowest 2 bytes of the address) of all nodes
        // with a hop count GREATER than the node that sends the message -- implying that all of
        // those nodes are reachable via that node. We cycle through those nodeids and check
        // our own neighbor table to see if using the announced route would be shorter. If
        // it is, we use it, else we ignore it
        {
            int i = 0;
            struct nd_option_serp_mesh_announcement_t* announcement;
            struct in6_addr dest;
            announcement = (struct nd_option_serp_mesh_announcement_t*) cur;

            printf(RECVC "Received a RA Announcement from ");
            printf_in6addr(&hdr->ip6_src);
            printf("with %d neighbors and default route " , announcement->neighbor_count);
            printf_in6addr(&announcement->parent);
            printf("\n" RESET);
            err = call SERPNeighborTable.addNeighbor(&hdr->ip6_src, hop_count+1, 0xFF);
            printf(INFOC "Add route to ");
            printf_in6addr(&hdr->ip6_src);
            printf(" via ");
            printf_in6addr(&hdr->ip6_src);
            printf("\n" RESET);
            call ForwardingTable.addRoute(hdr->ip6_src.s6_addr, 128, &hdr->ip6_src, ROUTE_IFACE_154);

            //memcpy(&dest, &hdr->ip6_src, sizeof(struct in6_addr));
            //memcpy(&dest, call NeighborDiscovery.getPrefix(), call NeighborDiscovery.getPrefixLength()/8);
            //for (i=0;i<announcement->neighbor_count;i++) {
            //    // adjust lower 2 bytes of address
            //    dest.s6_addr16[7] = announcement->neighbors[i];
            //    // skip if address is equal to us
            //    if (call IPAddress.isLocalAddress(&dest)) continue;
            //    // TODO: add to forwarding table if the hop would be less
            //    if (call SERPNeighborTable.isNeighbor(&dest)) continue;
            //    printf(INFOC "Adding route to ");
            //    printf_in6addr(&dest);
            //    printf(" via ");
            //    printf_in6addr(&hdr->ip6_src);
            //    printf("\n" RESET);
            //    //call ForwardingTable.addRoute(dest.s6_addr, 128, &hdr->ip6_src, ROUTE_IFACE_154);
            //}
            break;
        }
      default:
        printf(ERRORC "unrecognized option type %d\n" RESET, type);
        break;
      }
      cur += olen;
      len -= olen;
    }
  }

  /***** Send Router Advertisement *****/
  // This is the RA that we send to a new mote that
  // probably hasn't joined the mesh yet. This is sent as a
  // unicast in response to a received RS
  // Most of this implementation is taken from IPNeighborDiscoveryP
  task void send_mesh_info_RA() {
    struct nd_router_advertisement_t ra;

    struct ip6_packet pkt;
    struct ip_iovec   v[1];


    uint8_t sllao_len;
    uint8_t data[100];
    uint8_t* cur = data;
    uint16_t length = 0;
    int i;

    // if we don't have prefix, we aren't part of mesh and
    // shouldn't respond to this
    if (!call NeighborDiscovery.havePrefix()) {
        return;
    }

    ra.icmpv6.type = ICMP_TYPE_ROUTER_ADV;
    ra.icmpv6.code = ICMPV6_CODE_RA;
    ra.icmpv6.checksum = 0;
    ra.hop_limit = 16;
    ra.flags_reserved = 0;
    ra.flags_reserved |= RA_FLAG_MANAGED_ADDR_CONF << ND6_ADV_M_SHIFT;
    ra.flags_reserved |= RA_FLAG_OTHER_CONF << ND6_ADV_O_SHIFT;
    ra.router_lifetime = RTR_LIFETIME;
    ra.reachable_time = 0; // unspecified at this point...
    ra.retransmit_time = 0; // unspecified at this point...
    ADD_SECTION(&ra, sizeof(struct nd_router_advertisement_t));

    sllao_len = add_sllao(cur);
    cur += sllao_len;
    length += sllao_len;

    if (call NeighborDiscovery.havePrefix()) {
        struct nd_option_serp_mesh_info_t option;
        serp_neighbor_t *neighbor;
        uint8_t n_idx = 0;

        memset(&option, 0, sizeof(struct nd_option_serp_mesh_info_t));
        option.type = ND6_SERP_MESH_INFO;
        option.option_length = 5;
        option.reserved1 = 0;
        // add prefix length
        option.prefix_length = call NeighborDiscovery.getPrefixLength();
        // add prefix
        memcpy(&option.prefix, call NeighborDiscovery.getPrefix(), call NeighborDiscovery.getPrefixLength()/8);
        // fail early if the prefix is just 0
        if (option.prefix.s6_addr32[0] == 0x00) return;
        // treat all nodes as powered for now
        // TODO: fix this!
        option.powered = SERP_MAINS_POWERED;
        option.sender_hop_count = hop_count;
        // want to attach our neighbors
        for (i=0;i<MAX_SERP_NEIGHBOR_COUNT;i++) {
            neighbor = call SERPNeighborTable.getNeighbor(i);
            if (n_idx == 4) continue; // limited?
            if (!neighbor->valid) continue;
            memcpy(&option.neighbors[n_idx], &neighbor->ip.s6_addr16[7], sizeof(uint16_t));
            printf(INFOC "to mesh info msg add neighbor %x\n" RESET, option.neighbors[n_idx]);
            n_idx++;
        }
        option.neighbor_count = n_idx;
        printf(SENDC "Sending a SERP Mesh Info message with pfx len: %d, power: %d, hop_count: %d and prefix ", option.prefix_length, option.powered, option.sender_hop_count);
        printf_in6addr(&option.prefix);
        printf(RESET "\n");
        ADD_SECTION(&option, sizeof(struct nd_option_serp_mesh_info_t));
    }

    v[0].iov_base = data;
    v[0].iov_len = length;
    v[0].iov_next = NULL;

    pkt.ip6_hdr.ip6_nxt = IANA_ICMP;
    pkt.ip6_hdr.ip6_plen = htons(length);

    pkt.ip6_data = &v[0];

    // Send unicast RA to the link local address
    memcpy(&pkt.ip6_hdr.ip6_dst, &BCAST_ADDRESS, 16);

    // reset this when we send
    outstanding_RS_messages = 0;

    // set the src address to our link layer address
    call IPAddress.getLLAddr(&pkt.ip6_hdr.ip6_src);
    call IP_RA.send(&pkt);
  }

  task void send_mesh_announcement_RA() {
    struct nd_router_advertisement_t ra;

    struct ip6_packet pkt;
    struct ip_iovec   v[1];
    error_t err;

    uint8_t sllao_len;
    uint8_t data[120];
    uint8_t* cur = data;
    uint16_t length = 0;

    ra.icmpv6.type = ICMP_TYPE_ROUTER_ADV;
    ra.icmpv6.code = ICMPV6_CODE_RA;
    ra.icmpv6.checksum = 0;
    ra.hop_limit = 16;
    ra.flags_reserved = 0;
    ra.flags_reserved |= RA_FLAG_MANAGED_ADDR_CONF << ND6_ADV_M_SHIFT;
    ra.flags_reserved |= RA_FLAG_OTHER_CONF << ND6_ADV_O_SHIFT;
    ra.router_lifetime = RTR_LIFETIME;
    ra.reachable_time = 0; // unspecified at this point...
    ra.retransmit_time = 0; // unspecified at this point...
    ADD_SECTION(&ra, sizeof(struct nd_router_advertisement_t));

    // add announcement option
    // TODO: only send if hop_count < 0xff?
    {
        int i;
        int n_idx = 0;
        struct nd_option_serp_mesh_announcement_t option;
        struct route_entry *default_route;
        serp_neighbor_t *neighbor;

        option.type = ND6_SERP_MESH_ANN;
        option.option_length = 6;
        option.hop_count = hop_count;
        // default route:
        default_route = call ForwardingTable.lookupRoute(NULL, 0);
        memcpy(&option.parent, &default_route->next_hop, sizeof(struct in6_addr));
        // populate the list of downstream neighbors
        for (i=0;i<MAX_SERP_NEIGHBOR_COUNT;i++) {
            neighbor = call SERPNeighborTable.getNeighbor(i);
            if (n_idx == MAX_SERP_NEIGHBOR_MSG) continue; // limited?
            if (!neighbor->valid) continue;
            if (neighbor->hop_count < hop_count) continue;
            //option.neighbors[n_idx] = neighbor->ip.s6_addr16[7];
            memcpy(&option.neighbors[n_idx], &neighbor->ip.s6_addr16[7], sizeof(uint16_t));
            printf(BLUE ">> have neighbor ");
            printf_in6addr(&neighbor->ip);
            printf(" with hop count %d", neighbor->hop_count);
            printf(" node id %x ", option.neighbors[n_idx]);
            printf(" nnode id %x ", neighbor->ip.s6_addr16[7]);
            printf("\n" RESET);
            n_idx++;
        }
        {
        option.neighbor_count = n_idx;
        ADD_SECTION(&option, sizeof(struct nd_option_serp_mesh_announcement_t));
        }
    }

    v[0].iov_base = data;
    v[0].iov_len = length;
    v[0].iov_next = NULL;

    pkt.ip6_hdr.ip6_nxt = IANA_ICMP;
    pkt.ip6_hdr.ip6_plen = htons(length);

    pkt.ip6_data = &v[0];
    // Send multicast RA
    memcpy(&pkt.ip6_hdr.ip6_dst, &preferred_parent.ip, 16);
    // set the src address to our link layer address
    call IPAddress.getLLAddr(&pkt.ip6_hdr.ip6_src);
    printf(SENDC "Sending a RA Announcement to ");
    printf_in6addr(&pkt.ip6_hdr.ip6_dst);
    printf(" with len %d with address ", length);
    printf_in6addr(&pkt.ip6_hdr.ip6_src);
    printf("\n" RESET);
    err = call IP_RA.send(&pkt);
    if (err != SUCCESS) {
        printf(ERRORC "CAnnot send packet?!\n" RESET);
    } else {
        printf(ERRORC "send successful\n"  RESET);
    }
  }

  /***** Handle Incoming RS *****/
  // When we receive an RS
  event void IP_RS.recv(struct ip6_hdr *hdr,
                        void *packet,
                        size_t len,
                        struct ip6_metadata *meta) {
    error_t err;
    printf(RECVC "Received an RS in SERP from ");
    printf_in6addr(&hdr->ip6_src);
    printf("\n" RESET);
    //memcpy(&ra_meshinfo_destination, &(hdr->ip6_src), sizeof(struct in6_addr));

    // increment the number of outstanding RS messages we have to respond to
    outstanding_RS_messages++;

    // add to the neighbor table. If we are the root, this means we have a 1 hop distnace
    // to them. IF we are not root, then we don't know what their hop count is because they
    // don't have one because they are sending a RS message
    if (I_AM_ROOT) {
      err = call SERPNeighborTable.addNeighbor(&hdr->ip6_src, 1, 0xFF);
      call ForwardingTable.addRoute(hdr->ip6_src.s6_addr, 128, &hdr->ip6_src, ROUTE_IFACE_154);
    } else {
      err = call SERPNeighborTable.addNeighbor(&hdr->ip6_src, 0xFF, 0xFF);
    }
    if (err != SUCCESS) {
        printf(ERRORC "1Error adding to serp neighbor table\n" RESET);
    }

    // send our unicast reply with the mesh info
    if (part_of_mesh) {
        post send_mesh_info_RA();
    } else {
        //TODO: send the normal RA to populate the neighbor table?
    }
  }

  event void RouterAdvMeshAnnTimer.fired() {
        // if we are not root when this timer fires, we should run through the neighbor table
        // to make sure we announce the most up to date information
        if (!I_AM_ROOT && part_of_mesh) {
            serp_neighbor_t *chosen_parent;
            chosen_parent = call SERPNeighborTable.getLowestHopCount();
            if (chosen_parent == NULL) {
                printf(ERRORC "No parent w/ lowest hop count\n" RESET);
                return;
            }

            // only send mesh annoucement if
            // a) we have a *new* neighbor, or
            // b) we have a *new* lowest hop count
            if (!neighbors_are_equal(chosen_parent, &preferred_parent)) {
              printf(SENDC "Sending Router ANN\n", RESET);

              printf(INFOC "Choosing a parent as default route: IP addr ");
              printf_in6addr(&chosen_parent->ip);
              printf(" w/ hop count %d and power profile %d\n" RESET, chosen_parent->hop_count, chosen_parent->power_profile);
              // we set our hop count to be one greater than the hop count of the parent we've chosen
              hop_count = chosen_parent->hop_count + 1;
              call ForwardingTable.addRoute(NULL, 0, &chosen_parent->ip, ROUTE_IFACE_154);

              // make a note of our preferred parent
              preferred_parent.hop_count = chosen_parent->hop_count;
              preferred_parent.power_profile = chosen_parent->power_profile;
              memcpy(&preferred_parent.ip, &chosen_parent->ip, sizeof(struct in6_addr));
              post send_mesh_announcement_RA();
              return;
           }
        } else {
          printf(SENDC "Router advertisement mesh send BCAST\n" RESET);
          //memcpy(&ra_meshinfo_destination, &BCAST_ADDRESS, sizeof(struct in6_addr));
          post send_mesh_info_RA();
        }
  }

  /***** SERPControl *****/
  command error_t SERPControl.start() {
    printf("\n>>>>> SERPICOOOO start <<<<<\n\n");
    inet_pton6("ff02::1", &BCAST_ADDRESS);
    if (!running) {
        post init();
        call PrintTimer.startPeriodic(10000);
        running = TRUE;
    }
    return SUCCESS;
  }

  command error_t SERPControl.stop() {
      call PrintTimer.stop();
      running = FALSE;
      return SUCCESS;
  }

  /***** RootControl *****/
  command error_t RootControl.setRoot() {
    printf(INFOC "Setting root!\n" RESET);
    I_AM_ROOT = TRUE;
    part_of_mesh = TRUE;
    hop_count = 0;
    //call RPLRankInfo.declareRoot();
    return SUCCESS;
  }

  command error_t RootControl.unsetRoot() {
    I_AM_ROOT = FALSE;
    //call RPLRankInfo.cancelRoot();
    return SUCCESS;
  }

  command bool RootControl.isRoot() {
    return I_AM_ROOT;
  }

  event void PrintTimer.fired() {
      int i;
      serp_neighbor_t *entry;
      printf(INFOC "Hop count: %d Part of mesh? %d i am root? %d\n", hop_count, part_of_mesh, I_AM_ROOT);
      printf("Preferred parent ");
      printf_in6addr(&preferred_parent.ip); printf("\n");
      printf("SERP Neighbors\nIP addr                   hop_count  power_profile  valid?\n");
      for (i=0; i < MAX_SERP_NEIGHBOR_COUNT; i++) {
        call SERPNeighborTable.printNeighbor(i);
      }
      printf(RESET);
  }

  task void send_rs_task () {
    struct nd_router_solicitation_t msg;

    struct ip6_packet pkt;
    struct ip_iovec   v[1];

    uint8_t sllao_len;
    uint8_t data[60];
    uint8_t* cur = data;
    uint16_t length = 0;

    // Constructing a router solicitation message is straightforward. Mostly
    // just setting the ICMP header correctly.
    msg.icmpv6.type = ICMP_TYPE_ROUTER_SOL;
    msg.icmpv6.code = ICMPV6_CODE_RS;
    msg.icmpv6.checksum = 0;
    msg.reserved = 0;
    ADD_SECTION(&msg, sizeof(struct nd_router_solicitation_t));

    sllao_len = add_sllao(cur);
    cur += sllao_len;
    length += sllao_len;

    v[0].iov_base = data;
    v[0].iov_len = length;
    v[0].iov_next = NULL;

    pkt.ip6_hdr.ip6_nxt = IANA_ICMP;
    pkt.ip6_hdr.ip6_plen = htons(length);

    pkt.ip6_data = &v[0];
    printf(SENDC "Sending router solicitation to ");
    printf_in6addr(&unicast_rs_destination);
    printf("\n" RESET);
    memcpy(&pkt.ip6_hdr.ip6_dst, &unicast_rs_destination, 16);
    call IPAddress.getLLAddr(&pkt.ip6_hdr.ip6_src);
    call IP_RS.send(&pkt);
  }

  event void Ieee154Address.changed() {}
  event void IPAddress.changed(bool global_valid) {}
}
