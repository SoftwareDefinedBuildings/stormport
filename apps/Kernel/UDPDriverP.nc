#include <lib6lowpan/ip_malloc.h>
module UDPDriverP
{
    provides interface Driver;
    provides interface Init;
    uses interface UDP[uint8_t clnt];
    uses interface BlipStatistics<ip_statistics_t> as ip_stats;
    uses interface BlipStatistics<udp_statistics_t> as udp_stats;
    uses interface BlipStatistics<retry_statistics_t> as retry_stats;
    uses interface BlipStatistics<rpl_statistics_t> as rpl_stats;
}
implementation
{

    #define NUM_SOCKETS 16 //32 in udpP, must be pow2
    #define SOCK_BASE   8

    #define SEND_DONE 2
    #define SEND_BUSY 1
    #define SEND_IDLE 0
    typedef struct
    {
        udp_callback_t recv_callback;
        uint8_t bound;
    } socket_t;

    // blipstats struct
    struct
    {
        uint16_t sent;       // total IP datagrams sent
        uint16_t forwarded;  // total IP datagrams forwarded
        uint8_t rx_drop;     // L2 frags dropped due to 6lowpan failure
        uint8_t tx_drop;     // L2 frags dropped due to link failures
        uint8_t fw_drop;     // L2 frags dropped when forwarding due to queue overflow
        uint8_t rx_total;    // L2 frags received
        uint8_t encfail;     // frags dropped due to send queue
        uint8_t fragpool;    // free fragments in pool
        uint8_t sendinfo;    // free sendinfo structures
        uint8_t sendentry;   // free send entryies
        uint8_t sndqueue;    // free send queue entries
        uint8_t reserved;
        uint16_t heapfree;   // available free space in the heap
        uint16_t udpsent;  // UDP datagrams sent from app
        uint16_t udprcvd;  // UDP datagrams delivered to apps
    } __attribute__((packed)) stats;

    // retry stats struct
    struct
    {
        uint16_t pkt_cnt;
        uint16_t tx_cnt;
    } __attribute__((packed)) rstats;

    struct {
      uint8_t dis_tx;
      uint8_t dio_tx;
      uint8_t dao_tx;
      uint16_t rank;
    } __attribute__((packed)) rplstats;

    uint8_t scanidx;

    socket_t  norace sockets [NUM_SOCKETS];
    command error_t Init.init()
    {
        int i;
        scanidx = 0;
        for (i=0;i<NUM_SOCKETS;i++)
        {
            sockets[i].bound = 0;
            sockets[i].recv_callback.buffer = NULL;
        }
    }

    command driver_callback_t Driver.peek_callback()
    {
        uint8_t startidx = scanidx;
        do
        {
            if (sockets[scanidx].bound == 0 || (sockets[scanidx].recv_callback.buffer == NULL))
            {
                scanidx = (scanidx + 1) & NUM_SOCKETS-1;
            }
            else if (sockets[scanidx].recv_callback.buffer != NULL)
            {
                return (driver_callback_t) &sockets[scanidx].recv_callback;
            }
        } while(scanidx != startidx);
        return NULL;
    }
    command void Driver.pop_callback()
    {
        ip_free(sockets[scanidx].recv_callback.buffer);
        sockets[scanidx].recv_callback.buffer = NULL;
    }

    int alloc_socket()
    {
        int i;
        for (i=0;i<NUM_SOCKETS;i++)
        {
            if (sockets[i].bound == 0)
            {
                sockets[i].bound = 1;
                return i;
            }
        }
        return -1;
    }
    async command syscall_rv_t Driver.syscall_ex(
        uint32_t number, uint32_t arg0,
        uint32_t arg1, uint32_t arg2,
        uint32_t *argx)
    {
        switch(number & 0xFF)
        {
            case 0x01: //udp_socket()
            {
                return alloc_socket();
            }
            case 0x02: //udp_bind(sockid, port)
            {
                error_t rv;
                if (arg0 < NUM_SOCKETS)
                {
                    rv = call UDP.bind[arg0 + SOCK_BASE](arg1);
                    if (rv != SUCCESS)
                        return -1;
                    return 0;
                }
                return -1;
            }
            case 0x03: //udp_close(sockid)
            {
                if (arg0 < NUM_SOCKETS)
                {
                    if (sockets[arg0].bound == 0)
                        return -1;
                    if (sockets[arg0].recv_callback.buffer != NULL)
                    {
                        ip_free(sockets[arg0].recv_callback.buffer);
                        sockets[arg0].recv_callback.buffer = NULL;
                    }
                    call UDP.bind[arg0 + SOCK_BASE](0);
                    sockets[arg0].bound = 0;
                    sockets[arg0].recv_callback.addr = 0;
                    return 0;
                }
                return -1;
            }
                       //              0       1     2         x[0]  x[1]
            case 0x04: //udp_sendto(sockid, buffer, bufferlen, addr, port
            {
                if (arg0 < NUM_SOCKETS)
                {
                    struct sockaddr_in6 dest;
                    error_t rv;
                    if (sockets[arg0].bound == 0)
                        return -1;
                    inet_pton6((char*)argx[0], &dest.sin6_addr);
                    dest.sin6_port = htons((uint16_t)argx[1]);
                    rv = call UDP.sendto[arg0 + SOCK_BASE](&dest, (char*)arg1, arg2);
                    if (rv != SUCCESS) return -1;
                    return 0;
                }
                return -1;
            }
            case 0x05: //udp_set_recvfrom(sockid, cb, r)
            {
                if (arg0 < NUM_SOCKETS)
                {
                    if (sockets[arg0].bound == 0)
                        return -1;
                    sockets[arg0].recv_callback.addr = arg1;
                    sockets[arg0].recv_callback.r = (void*) arg2;
                    return 0;
                }
                return -1;
            }
#ifdef BLIP_STATS
            case 0x06: //udp_get_blipstats()
            {
                ip_statistics_t ips;
                udp_statistics_t udps;
                call ip_stats.get(&ips);
                call udp_stats.get(&udps);

                stats.sent = ips.sent;
                stats.forwarded = ips.forwarded;
                stats.rx_drop = ips.rx_drop;
                stats.tx_drop = ips.tx_drop;
                stats.fw_drop = ips.fw_drop;
                stats.rx_total = ips.rx_total;
                stats.encfail = ips.encfail;
                stats.fragpool = ips.fragpool;
                stats.sendinfo = ips.sendinfo;
                stats.sendentry = ips.sendentry;
                stats.sndqueue = ips.sndqueue;
                stats.heapfree = ips.heapfree;

                stats.udpsent = udps.sent;
                stats.udprcvd = udps.rcvd;

                return &stats;
            }
            case 0x07: //udp_clear_blipstats()
            {
                call ip_stats.clear();
                call udp_stats.clear();
                return 0;
            }

            case 0x08: //udp_get_retrystats()
            {
                retry_statistics_t r;
                call retry_stats.get(&r);
                rstats.pkt_cnt = r.pkt_cnt;
                rstats.tx_cnt = r.tx_cnt;
                return &rstats;
            }
            case 0x09: // udp_clear_retrystats()
            {
                call retry_stats.clear();
                return 0;
            }
            case 0x0c: // udp_get_rplstats() -- start at c because a,b is blip
            {
                rpl_statistics_t r;
                call rpl_stats.get(&r);
                rplstats.dis_tx = r.dis_tx;
                rplstats.dio_tx = r.dio_tx;
                rplstats.dao_tx = r.dao_tx;
                rplstats.rank = r.rank;
                return &rplstats;
            }
            case 0x0d:
            {
                call rpl_stats.clear();
                return 0;
            }
#endif // BLIP_STATS
        }
    }

    event void UDP.recvfrom[uint8_t sock](struct sockaddr_in6 *src, void *payload,
                      uint16_t len, struct ip6_metadata *meta)
    {
        int sockid;
        if (sock < SOCK_BASE) return;
        sockid = sock - SOCK_BASE;
        if (sockid >= NUM_SOCKETS) return;
        if (sockets[sockid].bound == FALSE) return;
        if (sockets[sockid].recv_callback.addr == 0) return; //no point, no callback
        if (sockets[sockid].recv_callback.buffer != NULL)
        {
            printf("PACKET DROP\n");
            return;
        }
        sockets[sockid].recv_callback.buffer = ip_malloc(len);
        if (!sockets[sockid].recv_callback.buffer)
        {
            printf("Could not alloc recv buf\n");
            return;
        }
        memcpy(sockets[sockid].recv_callback.buffer, payload, len);
        memcpy(sockets[sockid].recv_callback.src_address, &src->sin6_addr, 16);
        sockets[sockid].recv_callback.port = htons(src->sin6_port);
        sockets[sockid].recv_callback.buflen = len;
	sockets[sockid].recv_callback.rssi = meta->rssi;
	sockets[sockid].recv_callback.lqi = meta->lqi;
    }
}
