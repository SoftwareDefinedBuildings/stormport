#include <IPDispatch.h>
#include <lib6lowpan/lib6lowpan.h>
#include <lib6lowpan/ip.h>
#include <lib6lowpan/ip.h>
#include "version.h"

module EthernetP
{
    uses
    {
        interface SplitControl as IPControl;
        interface ForwardingTable;
        interface RootControl;
        interface EthernetShieldConfig;
        interface RawSocket;
        interface LocalIeeeEui64;
    }
    provides
    {
        interface IPForward;
    }
}
implementation
{
    void *ipf_data;
    bool busy;
    uint32_t destip;

    struct sockaddr_in6 route_dest_154;
    ieee_eui64_t address;
    uint8_t mac [6];

    event void IPControl.startDone (error_t error) {
        printf("Ethernet set as default route\n");
        inet_pton6(IN6_PREFIX, &route_dest_154.sin6_addr);
        call ForwardingTable.addRoute(NULL, 0, NULL, ROUTE_IFACE_ETH0);
        call ForwardingTable.addRoute((uint8_t*) &route_dest_154.sin6_addr, 64, NULL, ROUTE_IFACE_154);
        {
            int i;
            address = call LocalIeeeEui64.getId(); // This is how we autogenerate the MAC address from the serial number -- GTF
            mac[0] = address.data[0];
            mac[1] = address.data[1];
            mac[2] = address.data[2];
            mac[3] = address.data[3];
            mac[4] = address.data[6];
            mac[5] = address.data[7];
        }
        busy = FALSE;
        destip = 192 << 24 | 168 << 16 | 1 << 8 | 1;
        //destip = 0x0a040a8e; //10.4.10.150
        //destip = 0x0a040a87; // 10.4.10.135
        //destip = 0x364365f1; //54.67.101.241
        {
            uint32_t srcip   = 192  << 24 | 168   << 16 | 1  << 8 | 4;
            uint32_t netmask = 255 << 24 | 255 << 16 | 255 << 8 | 0  ;
            uint32_t gateway = 192  << 24 | 168   << 16 | 1  << 8 | 1  ;
            //uint8_t *mac = "\xde\xad\xbe\xef\xfe\xec";

            call EthernetShieldConfig.initialize(srcip, netmask, gateway, mac);
        }
        call RootControl.setRoot();
        call RawSocket.initialize(41);
        call RootControl.setRoot();
    }

    event void RawSocket.initializeDone(error_t error) {}

    event void IPControl.stopDone (error_t error) {}

    command error_t IPForward.send(struct in6_addr *next_hop,
                                 struct ip6_packet *msg,
                                 void *data) {
        struct ip_iovec hvec;
        if (busy) return EBUSY;
        busy=TRUE;
        hvec.iov_base = (uint8_t*) &msg->ip6_hdr;
        hvec.iov_len = sizeof(struct ip6_hdr);
        hvec.iov_next = msg->ip6_data;
        ipf_data = data;
        call RawSocket.sendPacket(destip, &hvec);

        return SUCCESS;
    }

    event void RawSocket.sendPacketDone(error_t error)
    {
        busy = FALSE;
    }

    event void RawSocket.packetReceived(uint8_t *buf, uint16_t len)
    {
        struct ip6_hdr *iph = (struct ip6_hdr *)buf;
        void *payload = (iph + 1);
        signal IPForward.recv(iph, payload, NULL);
    }

}
