#include <lib6lowpan/ip.h>
#include <serp_messages.h>

configuration SERPRoutingC {
  provides {
    interface RootControl;
    interface StdControl as SERPControl;
  }
} implementation {
    components SERPRoutingEngineC;
    components IPNeighborDiscoveryC;
    RootControl = SERPRoutingEngineC.RootControl;
    SERPControl = SERPRoutingEngineC.SERPControl;
    SERPRoutingEngineC.NeighborDiscovery -> IPNeighborDiscoveryC;
}
