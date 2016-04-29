configuration UDPDriverC
{
    provides interface Driver;
}
implementation
{
    components RealMainP;
    components UDPDriverP;
    components IPDispatchC;
    components SERPRoutingC;
    components UdpP;
    UDPDriverP.Init <- RealMainP.SoftwareInit;
    UDPDriverP.UDP -> UdpP.UDP;
    UDPDriverP.ip_stats -> IPDispatchC;
    UDPDriverP.retry_stats -> IPDispatchC;
    UDPDriverP.udp_stats -> UdpP;
    UDPDriverP.route_stats -> SERPRoutingC.RouteStatistics;
    Driver = UDPDriverP.Driver;
}
