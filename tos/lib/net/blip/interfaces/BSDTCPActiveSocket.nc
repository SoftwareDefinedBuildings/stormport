#include <bsdtcp/lbuf.h>

interface BSDTCPActiveSocket {
    command int getID();
    command int getState();
    command void getPeerInfo(struct in6_addr** addr, uint16_t** port);

    command error_t bind(uint16_t port);

    command error_t connect(struct sockaddr_in6* addr, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp);
    event void connectDone(struct sockaddr_in6* addr);

    event void sendDone(uint32_t freedentries);
    command error_t send(struct lbufent* data, int moretocome, int* status);

    event void receiveReady(int gotfin);
    command error_t receive(uint8_t* buffer, uint32_t length, size_t* bytessent);

    event void connectionLost(uint8_t how);

    command void getStats(int* segsrcvd, int* segssent, int* sacks_sent, int* srtt, int* delacks);

    command error_t shutdown(bool reads, bool writes);
    command error_t abort();
}
