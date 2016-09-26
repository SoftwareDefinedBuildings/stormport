#include <bsdtcp.h>

configuration TCPDriverC {
    provides interface Driver;
    //uses interface BlipStatistics<retry_statistics_t> as ProvidedRetryStatistics;
    //uses interface BlipStatistics<ip_statistics_t> as ProvidedIPStatistics;
} implementation {
    components TCPDriverP, BsdTcpC;
    components RealMainP;

    TCPDriverP.BSDTCPActiveSocket[0] -> BsdTcpC.BSDTCPActiveSocket[unique(UQ_BSDTCP_ACTIVE)];
    //TCPDriverP.BSDTCPActiveSocket[1] -> BsdTcpC.BSDTCPActiveSocket[unique(UQ_BSDTCP_ACTIVE)];
    //TCPDriverP.BSDTCPActiveSocket[2] -> BsdTcpC.BSDTCPActiveSocket[unique(UQ_BSDTCP_ACTIVE)];
    TCPDriverP.BSDTCPPassiveSocket[0] -> BsdTcpC.BSDTCPPassiveSocket[unique(UQ_BSDTCP_PASSIVE)];
    //TCPDriverP.BSDTCPPassiveSocket[1] -> BsdTcpC.BSDTCPPassiveSocket[unique(UQ_BSDTCP_PASSIVE)];
    //TCPDriverP.BSDTCPPassiveSocket[2] -> BsdTcpC.BSDTCPPassiveSocket[unique(UQ_BSDTCP_PASSIVE)];

    TCPDriverP.Init <- RealMainP.SoftwareInit;
    //TCPDriverP.RetryStatistics = ProvidedRetryStatistics;
    //TCPDriverP.IPStatistics = ProvidedIPStatistics;
    Driver = TCPDriverP;

    //components RF230DriverHwAckC;
    //TCPDriverP.RadioStats -> RF230DriverHwAckC;

    //components RF230RadioC;
    //TCPDriverP.TrafficMonitor -> RF230RadioC;
}
