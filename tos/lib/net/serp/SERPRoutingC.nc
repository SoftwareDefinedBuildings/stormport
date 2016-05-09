#include <lib6lowpan/ip.h>
#include <serp_messages.h>

configuration SERPRoutingC {
  provides {
    interface RootControl;
    interface StdControl as SERPControl;
    interface BlipStatistics<serp_route_statistics_t> as RouteStatistics;
  }
} implementation {
    components SERPRoutingEngineC;
    components IPNeighborDiscoveryC;
    RootControl = SERPRoutingEngineC.RootControl;
    SERPControl = SERPRoutingEngineC.SERPControl;
    RouteStatistics = SERPRoutingEngineC.RouteStatistics;
    SERPRoutingEngineC.NeighborDiscovery -> IPNeighborDiscoveryC;
} 
