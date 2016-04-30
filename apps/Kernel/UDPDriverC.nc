configuration UDPDriverC
{
    provides interface Driver;
}
implementation
{
    components RealMainP;
    components UDPDriverP;
    components IPDispatchC;
    components RPLRoutingEngineC;
    components UdpP;
    UDPDriverP.Init <- RealMainP.SoftwareInit;
    UDPDriverP.UDP -> UdpP.UDP;
    UDPDriverP.rpl_stats -> RPLRoutingEngineC;
    UDPDriverP.ip_stats -> IPDispatchC;
    UDPDriverP.retry_stats -> IPDispatchC;
    UDPDriverP.udp_stats -> UdpP;
    Driver = UDPDriverP.Driver;
}
