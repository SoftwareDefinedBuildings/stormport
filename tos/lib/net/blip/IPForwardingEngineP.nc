/**
 * Forwarding abstractions for blip IPv6 stack.
 *
 * Routing protocols can manipulate the forwarding state using the
 * ForwardingTable interface and receive notifications of forwarding
 * events using ForwardingEvents.  In particular, the forwarding
 * events are useful for datapath validation and updating link
 * estimates.
 *
 * @author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
 */

#include <iprouting.h>
#include <lib6lowpan/ip.h>

#include "blip_printf.h"

module IPForwardingEngineP {
  provides {
    interface ForwardingTable;
    interface ForwardingTableEvents;
    interface ForwardingEvents[uint8_t ifindex];
    interface IP;
    interface IP as IPRaw;
    interface Init;
  }
  uses {
    interface IPForward[uint8_t ifindex];
    interface IPAddress;
    interface IPPacket;
    interface Pool<struct in6_iid>;
    interface FlashAttr;

#ifdef PRINTFUART_ENABLED
    interface Timer<TMilli> as PrintTimer;
#endif
  }
} implementation {

#define min(X,Y) (((X) < (Y)) ? (X) : (Y))

  /* simple routing table for now */
  /* we can optimize memory consumption later since most of these
     address will have known prefixes -- either LL or the shared
     global prefix. */
  /* the routing table is sorted by prefix length, so that the entries
     with the longest prefix are at the top. */
  /* if a route to the given prefix already exists, this updates it. */
  struct route_entry routing_table[ROUTE_TABLE_SZ];

  // read from flash
  uint8_t flashkey [10];
  char flashprefix [65];
  uint8_t flashval_len;
  bool prefix_from_flash = 0;
  error_t e;

  route_key_t last_key = 1;

  void task getPrefix() {
    e = call FlashAttr.getAttr(2, flashkey, flashprefix, &flashval_len);
    // use the prefix if we get it from flash
    if (e == SUCCESS && flashval_len > 0) { // prefix set
        prefix_from_flash = 1;
    } else if (e == SUCCESS && flashval_len == 0) { // prefix not set
        return;
    } else if (e == EBUSY) { // busy = retry
        printf("error? %d length %d\n", e, flashval_len);
        post getPrefix();
    }
  }

  command error_t Init.init() {
    memset(routing_table, 0, sizeof(routing_table));
    post getPrefix();
  }

  int alloc_key() {
    int i;
    int key;
  retry:
    key = last_key++;
    for (i = 0; i < ROUTE_TABLE_SZ; i++) {
      if (routing_table[i].valid && routing_table[i].key == key)
        goto retry;
    }
    return key;
  }

  struct route_entry *alloc_entry(int pfxlen) {
    int i;
    /* full table */
    if (routing_table[ROUTE_TABLE_SZ-1].valid) return NULL;

    for (i = 0; i < ROUTE_TABLE_SZ; i++) {
      /* if there's an invalid entry there are spare entries and we
         don't have to insert in the middle of the table. */
      if (!routing_table[i].valid) goto init_entry;
      /* we keep the table sorted by prefix length so we skip all the
         entries with longer prefixes. */
      else if (routing_table[i].prefixlen >= pfxlen) continue;

      /* we're pointing at a valid entry that is our new slot; we know
         there's at least one free entry in the table, too. */
      /* shift the table down and return the current entry; */
      memmove((void *)&routing_table[i+1], (void *)&routing_table[i],
              sizeof(struct route_entry) * (ROUTE_TABLE_SZ - i - 1));
      goto init_entry;
    }
    return NULL;
  init_entry:
    routing_table[i].valid = 1;
    routing_table[i].key = alloc_key();
    return &routing_table[i];
  }

  task void defaultRouteAddedTask() {
    signal ForwardingTableEvents.defaultRouteAdded();
  }

  command route_key_t ForwardingTable.addRoute(const uint8_t *prefix,
                                               int prefix_len_bits,
                                               struct in6_addr *next_hop,
                                               uint8_t ifindex) {
    struct route_entry *entry;
    int i;
#ifndef BLIP_STFU
    printf("adding route with length %d on if %d\n", prefix_len_bits, ifindex);
#endif
    /* no reason to support non-byte length prefixes for now... */
    if (prefix_len_bits % 8 != 0 || prefix_len_bits > 128)
    {
#ifndef BLIP_STFU
        printf("\033[31;1minvalid prefix length\n\033[0m");
#endif
        return ROUTE_INVAL_KEY;
    }
    entry = call ForwardingTable.lookupRoute(prefix, prefix_len_bits);
#ifdef RPL_SINGLE_HOP
    /**
     * In single-hop mode, we have already statically set the single hop route
     * in IPNeighborDiscoveryP.  Here, we check to see if we already have a
     * route for the given prefix before we add a new route.  If a route
     * already exists, then we do not overwrite it. Else, the method continues
     * as usual -- Gabe
     */
    if (entry != NULL && memcmp(&entry->prefix, next_hop, sizeof(struct in6_addr)) != 0)  {
#ifndef BLIP_STFU
        printf("\033[31;1merror bc already have route for that prefix\n\033[0m");
#endif
        return ROUTE_INVAL_KEY;
    }
#endif
    if (entry == NULL || entry->prefixlen != prefix_len_bits) {
      /* if there's no entry, or there's another entry but it has a
         different prefix length, we allocate a new slot in the
         table. */
      entry = alloc_entry(prefix_len_bits);

      /* got a default route and we didn't already have one */
      if (prefix_len_bits == 0) {
        post defaultRouteAddedTask();
      }
    }
    if (entry == NULL)
    {
#ifndef BLIP_STFU
      printf("\033[31;1mENTRY NULL\n\033[0m");
#endif
      return ROUTE_INVAL_KEY;
    }

    entry->prefixlen = prefix_len_bits;
    entry->ifindex = ifindex;
    if (prefix_len_bits >= 8)
      memcpy(&entry->prefix, prefix, prefix_len_bits / 8);
    if (next_hop)
      memcpy(&entry->next_hop, next_hop, sizeof(struct in6_addr));
    return entry->key;
  }

  command error_t ForwardingTable.delRoute(route_key_t key) {
    int i;
    for (i = 0; i < ROUTE_TABLE_SZ; i++) {
      if (routing_table[i].key == key) {
        /* remove the default route? */
        if (routing_table[i].prefixlen == 0) {
          signal ForwardingTableEvents.defaultRouteRemoved();
        }

        memmove((void *)&routing_table[i], (void *)&routing_table[i+1],
                sizeof(struct route_entry) * (ROUTE_TABLE_SZ - i - 1));
        routing_table[ROUTE_TABLE_SZ-1].valid = 0;
        return SUCCESS;
      }
    }
    return FAIL;
  }

  /**
   * Look up the route to a prefix.
   *
   * If next_hop is not NULL, the next hop will be written in there.
   * @return the route key associated with this route.
   */
  command struct route_entry *ForwardingTable.lookupRoute(const uint8_t *prefix,
                                                          int prefix_len_bits) {
    int i;
    for (i = 0; i < ROUTE_TABLE_SZ; i++) {
      if (routing_table[i].valid &&
          ((routing_table[i].prefixlen == 0) ||
          (memcmp(prefix, routing_table[i].prefix.s6_addr,
                  min(prefix_len_bits, routing_table[i].prefixlen) / 8) == 0 &&
            prefix_len_bits))) {
        /* match! */
        return &routing_table[i];
      }
    }
    return NULL;
  }
  command struct route_entry *ForwardingTable.lookupRouteKey(route_key_t key) {
    int i;
    for (i = 0; i < ROUTE_TABLE_SZ; i++) {
      if (routing_table[i].valid &&
          routing_table[i].key == key)
        return &routing_table[i];
    }
    return NULL;
  }

  command struct route_entry *ForwardingTable.getTable(int *n) {
    *n = ROUTE_TABLE_SZ;
    return routing_table;
  }

  error_t do_send(uint8_t ifindex, struct in6_addr *next, struct ip6_packet *pkt) {
    error_t rc;
    struct in6_iid *iid = call Pool.get();
    if (iid != NULL)
      memcpy(iid->data, &next->s6_addr[8], 8);
    printf("Sending: %d %d\n", (int) ifindex, ROUTE_IFACE_154);
    rc = call IPForward.send[ifindex](next, pkt, iid);
    if (rc != SUCCESS && iid != NULL)
      call Pool.put(iid);
    return rc;
  }

  command error_t IP.send(struct ip6_packet *pkt) {
    struct route_entry *next_hop_entry =
      call ForwardingTable.lookupRoute(pkt->ip6_hdr.ip6_dst.s6_addr, 128);

#ifdef PRINTFUART_ENABLED
    if (!call PrintTimer.isRunning())
      call PrintTimer.startPeriodic(10000);
#endif

    if (call IPAddress.isLocalAddress(&pkt->ip6_hdr.ip6_dst) &&
        pkt->ip6_hdr.ip6_dst.s6_addr[0] != 0xff) {
        #ifndef BLIP_STFU
            printf("Forwarding -- send with local unicast address!\n");
        #endif
      return FAIL;
    } else if (call IPAddress.isLLAddress(&pkt->ip6_hdr.ip6_dst) &&
               (!next_hop_entry || next_hop_entry->prefixlen < 128)) {
      /* in this case, we need to figure out which interface the
         source address is attached to, and send the packet out on
         that interface. */
      /* with traditional ND we would check the cache for each
         interface and then start discover on all of them; however,
         since we're assuming that link-local addresses are on-link
         for the 15.4 side, we just send all LL addresses that way. */
      /* this is probably the worst part about not doing ND -- LL
         addressed don't work on other links...  we should probably do
         ND in this case, or at least keep a cache so we can reply to
         messages on the right interface. */
      #ifndef BLIP_STFU
      printf("Forwarding -- send to LL address:");
      printf_in6addr(&pkt->ip6_hdr.ip6_dst);
      printf("\n");
      #endif
      pkt->ip6_hdr.ip6_hlim = 1;
      // only do this for unicast packets
      if (pkt->ip6_hdr.ip6_dst.s6_addr[0] != 0xff) {
        return do_send(ROUTE_IFACE_154, &pkt->ip6_hdr.ip6_dst, pkt);
      } else {
        return call IPForward.send[ROUTE_IFACE_154](&pkt->ip6_hdr.ip6_dst, pkt, NULL);
      }
    } else if (next_hop_entry) {
      #ifndef BLIP_STFU
      printf("Forwarding -- got from routing table\n");
      #endif
      /* control messages do not need routing headers */
      if (!(signal ForwardingEvents.initiate[next_hop_entry->ifindex](pkt,
                                             &next_hop_entry->next_hop)))
        return FAIL;

      return do_send(next_hop_entry->ifindex, &next_hop_entry->next_hop, pkt);
    }

    #ifndef BLIP_STFU
    printf("Forwarding -- no route found for packet. FAIL.\n");
    printf("Forwarding -- dest addr: ");
    printf_in6addr(&pkt->ip6_hdr.ip6_dst);
    printf("\n");
    #endif

    return FAIL;
  }

  command error_t IPRaw.send(struct ip6_packet *pkt) {
    return FAIL;
  }

  event void IPForward.recv[uint8_t ifindex](struct ip6_hdr *iph, void *payload,
                                             struct ip6_metadata *meta) {
    struct ip6_packet pkt;
    struct in6_addr *next_hop;
    size_t len = ntohs(iph->ip6_plen);
    uint8_t next_hop_ifindex;
    struct ip_iovec v = {
      .iov_next = NULL,
      .iov_base = payload,
      .iov_len  = len,
    };

    /* signaled before *any* processing  */
    signal IPRaw.recv(iph, payload, len, meta);

    if (call IPAddress.isLocalAddress(&iph->ip6_dst)) {
      /* local delivery */
      signal IP.recv(iph, payload, len, meta);
      return;
    } else {
      /* forwarding */
      uint8_t nxt_hdr = IPV6_ROUTING;
      int header_off = call IPPacket.findHeader(&v, iph->ip6_nxt, &nxt_hdr);
      uint8_t i;
      if (!(--iph->ip6_hlim)) {
        /* ICMP may send time exceeded */
        // call ForwardingEvents.drop(iph, payload, len, ROUTE_DROP_HLIM);
        return;
      }

      if (header_off >= 0) {
        //  we found a routing header in the packet
        //  look up the next hop in the header if we understand it (type 4)
        // TODO
        //  next_hop_ifindex = ifindex;
        return;
      } else {
        /* look up the next hop in the routing table */
        struct route_entry *next_hop_entry =
          call ForwardingTable.lookupRoute(iph->ip6_dst.s6_addr,
                                           128);
#ifdef RPL_SINGLE_HOP_ROOT
        // if we are the root in a single hop network, we use the IN6_PREFIX
        // in order to do the address translation
        // IN6_PREFIX comes from flash if the getPrefix() task completes. and has
        // something valid in attribute 2, else we use the Makefile IN6_PREFIX
        struct sockaddr_in6 local_prefix;
        if (prefix_from_flash) {
            inet_pton6(flashprefix, &local_prefix.sin6_addr);
        } else {
            inet_pton6(IN6_PREFIX, &local_prefix.sin6_addr);
        }
#endif

        if (next_hop_entry == NULL) {
          /* oops, no route. */
          /* RPL will reencapsulate the packet in some cases here */
          // call ForwardingEvents.drop(iph, payload, len, ROUTE_DROP_NOROUTE);
          return;
        }
#ifdef RPL_SINGLE_HOP_ROOT
        /** Check the first 64 bytes of our destination address. If it matches the IPv6
         *  prefix for the 802.15.4 mesh, then we replace the prefix with the link-local
         *  address, fe80 -- Gabe
        **/
        if (next_hop_entry->ifindex == 1 && // only do this for 802.15.4, not ethernet
           iph->ip6_dst.s6_addr32[0] == local_prefix.sin6_addr.s6_addr32[0] &&
           iph->ip6_dst.s6_addr32[1] == local_prefix.sin6_addr.s6_addr32[1] &&
           iph->ip6_dst.s6_addr16[0] != 0) {
               // our next hop should be the destination, but with the global ipv6 prefix switched for link-local
               // overwrite first 64 bits of address
               next_hop_entry->next_hop.s6_addr32[0] = htons(0xfe80);
               next_hop_entry->next_hop.s6_addr32[1] = 0;
               next_hop_entry->next_hop.s6_addr32[2] = iph->ip6_dst.s6_addr32[2];
               next_hop_entry->next_hop.s6_addr32[3] = iph->ip6_dst.s6_addr32[3];
        }
#endif
        next_hop = &next_hop_entry->next_hop;
        next_hop_ifindex = next_hop_entry->ifindex;
      }

      memcpy(&pkt.ip6_hdr, iph, sizeof(struct ip6_hdr));
      pkt.ip6_data = &v;
      pkt.ip6_inputif = ifindex;

      /* give the routing protocol a chance to do data-path validation
         on this packet. */
      /* RPL uses this to update the flow label fields */
      if (!(signal ForwardingEvents.approve[next_hop_ifindex](&pkt, next_hop)))
        return;

      do_send(next_hop_ifindex, next_hop, &pkt);
    }
  }

  event void IPForward.sendDone[uint8_t ifindex](struct send_info *status) {
    struct in6_addr next;
    struct in6_iid *iid = (struct in6_iid *)status->upper_data;
    memset(next.s6_addr, 0, 16);
    next.s6_addr16[0] = htons(0xfe80);
    #ifndef BLIP_STFU
    printf("sendDone: iface: %d key: %p\n", ifindex, iid);
    #endif
    if (iid != NULL) {
      memcpy(&next.s6_addr[8], iid->data, 8);
      signal ForwardingEvents.linkResult[ifindex](&next, status);
      call Pool.put(iid);
    }
  }

#ifdef PRINTFUART_ENABLED
  event void PrintTimer.fired() {
    #ifndef BLIP_STFU
    int i, ctr=0;
    static char print_buf[44];
    char* buf;
    printf("\n#    ");
    printf("destination                                ");
    printf("gateway                   ");
    printf("iface\n");
    for (i = 0; i < ROUTE_TABLE_SZ; i++) {
      if (routing_table[i].valid) {
        buf = print_buf;

        printf("%d ", ctr++);

        buf += inet_ntop6(&routing_table[i].prefix, print_buf, 44) - 1;
        snprintf(buf, (44 - (buf - print_buf)), "/%i", routing_table[i].prefixlen);
        printf("%s ", print_buf);

        inet_ntop6(&routing_table[i].next_hop, print_buf, 30);
        printf("%s ", print_buf);

        printf("%d \n", routing_table[i].ifindex);
      }
    }
    printf("\n");
    //printfflush();
    #endif
  }
#endif

  default event bool ForwardingEvents.approve[uint8_t idx](struct ip6_packet *pkt,
                                                           struct in6_addr *next_hop) {
    return TRUE;
  }
  default event bool ForwardingEvents.initiate[uint8_t idx](struct ip6_packet *pkt,
                                                            struct in6_addr *next_hop) {
    return TRUE;
  }
  default event void ForwardingEvents.linkResult[uint8_t idx](struct in6_addr *host,
                                                              struct send_info * info) {}

  default command error_t IPForward.send[uint8_t ifindex](struct in6_addr *next_hop,
                                                          struct ip6_packet *pkt,
                                                          void *data) {
    return SUCCESS;
  }

  default event void IPRaw.recv(struct ip6_hdr *iph, void *payload,
                                size_t len, struct ip6_metadata *meta) {}

  default event void ForwardingTableEvents.defaultRouteAdded() {}
  default event void ForwardingTableEvents.defaultRouteRemoved() {}

  event void IPAddress.changed(bool global_valid) {}
}
