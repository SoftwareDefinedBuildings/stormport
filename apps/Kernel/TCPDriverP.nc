#include <bsdtcp/lbuf.h>
#include <bsdtcp/sys/errno.h>
#include "driver.h"
#include "BlipStatistics.h"

// Number of active sockets and number of passive sockets must be the same
#define NUMSOCKETS 1

module TCPDriverP {
    provides interface Driver;
    provides interface Init;
    uses interface BSDTCPActiveSocket[uint8_t aclient];
    uses interface BSDTCPPassiveSocket[uint8_t pclient];
    //uses interface BlipStatistics<retry_statistics_t> as RetryStatistics;
    //uses interface BlipStatistics<ip_statistics_t> as IPStatistics;
    //uses interface RadioStats;
    //uses interface TrafficMonitor;
} implementation {
    #include <bsdtcp/socket.h>
    #include <bsdtcp/tcp.h>
    #include <bsdtcp/tcp_fsm.h>

    typedef struct {
        tcp_callback_t connectDone;
        tcp_callback_t sendDone;
        tcp_callback_t recvReady;
        tcp_callback_t connectionLost;
        uint8_t readycbs;
    } active_socket_t;

    typedef struct {
        int acceptinginto;
        tcp_callback_t acceptDone;
        uint8_t readycbs;
    } passive_socket_t;

    /* Bitmasks that record which sockets are currently allocated. */
    norace uint32_t activemask;
    norace uint32_t passivemask;

    /* Socket structures. */
    norace active_socket_t activesockets[NUMSOCKETS];
    norace passive_socket_t passivesockets[NUMSOCKETS];

    /* For remembering the callback. */
    norace bool passive;
    norace uint8_t socket_idx;
    norace uint8_t cb_type;

    void clear_activesocket(int i) {
        activesockets[i].connectDone.addr = 0;
        activesockets[i].connectDone.type = TCP_CONNECT_DONE_CB;
        activesockets[i].sendDone.addr = 0;
        activesockets[i].sendDone.type = TCP_SEND_DONE_CB;
        activesockets[i].sendDone.arg0 = 0;
        activesockets[i].recvReady.addr = 0;
        activesockets[i].recvReady.type = TCP_RECV_READY_CB;
        activesockets[i].connectionLost.addr = 0;
        activesockets[i].connectionLost.type = TCP_CONNECTION_LOST_CB;
    }

    void clear_passivesocket(int i) {
        passivesockets[i].acceptinginto = -1;
        passivesockets[i].acceptDone.addr = 0;
        passivesockets[i].acceptDone.type = TCP_ACCEPT_DONE_CB;
    }

    command error_t Init.init() {
        int i;
        activemask = 0;
        passivemask = 0;
        for (i = 0; i < NUMSOCKETS; i++) {
            clear_activesocket(i);
            activesockets[i].readycbs = 0;
            clear_passivesocket(i);
            passivesockets[i].readycbs = 0;
        }
        passive = FALSE;
        socket_idx = 0;
        cb_type = TCP_CONNECT_DONE_CB;
    }

    /* Increments *CBT, and returns TRUE if it wrapped. */
    bool next_cb_type(uint8_t* cbt) {
        switch (*cbt) {
        case TCP_CONNECT_DONE_CB:
            *cbt = TCP_SEND_DONE_CB;
            return FALSE;
        case TCP_SEND_DONE_CB:
            *cbt = TCP_RECV_READY_CB;
            return FALSE;
        case TCP_RECV_READY_CB:
            *cbt = TCP_CONNECTION_LOST_CB;
            return FALSE;
        case TCP_CONNECTION_LOST_CB:
            *cbt = TCP_ACCEPT_DONE_CB;
            return FALSE;
        case TCP_ACCEPT_DONE_CB:
            *cbt = TCP_CONNECT_DONE_CB;
            return TRUE;
        default:
            return FALSE;
        }
    }

    tcp_callback_t* get_callback(uint8_t sock_idx, uint8_t cbt) {
        switch (cbt) {
        case TCP_CONNECT_DONE_CB:
            return &activesockets[sock_idx].connectDone;
        case TCP_SEND_DONE_CB:
            return &activesockets[sock_idx].sendDone;
        case TCP_RECV_READY_CB:
            return &activesockets[sock_idx].recvReady;
        case TCP_CONNECTION_LOST_CB:
            return &activesockets[sock_idx].connectionLost;
        case TCP_ACCEPT_DONE_CB:
            return &passivesockets[sock_idx].acceptDone;
        default:
            return NULL;
        }
    }

    command driver_callback_t Driver.peek_callback() {
        uint8_t start_idx = socket_idx;
        uint8_t start_cb_type = cb_type;
        tcp_callback_t* toconsider;
        do {
            if ((IS_PASSIVE_CB(cb_type) && (passivesockets[socket_idx].readycbs & cb_type)) ||
                (!IS_PASSIVE_CB(cb_type) && (activesockets[socket_idx].readycbs & cb_type))) {
                toconsider = get_callback(socket_idx, cb_type);
                if (toconsider->addr != 0) {
                    return (driver_callback_t) toconsider;
                }
            }
            if (next_cb_type(&cb_type)) {
                socket_idx = (socket_idx + 1) % NUMSOCKETS;
            }
        } while (socket_idx != start_idx && cb_type != start_cb_type);
        return NULL;
    }

    command void Driver.pop_callback() {
        if (IS_PASSIVE_CB(cb_type)) {
            passivesockets[socket_idx].readycbs &= ~cb_type;
        } else {
            activesockets[socket_idx].readycbs &= ~cb_type;
            if (cb_type == TCP_SEND_DONE_CB) {
                activesockets[socket_idx].sendDone.arg0 = 0; // Clear outstanding callbacks
            }
        }
    }

    event void BSDTCPPassiveSocket.acceptDone[uint8_t pi](struct sockaddr_in6* addr, int asockid) {
        passivesockets[pi].acceptDone.arg0 = (uint8_t) passivesockets[pi].acceptinginto;
        passivesockets[pi].readycbs |= TCP_ACCEPT_DONE_CB;
        passivesockets[pi].acceptinginto = -1;
        printf("Accepted connection!\n");
    }

    event void BSDTCPActiveSocket.connectDone[uint8_t ai](struct sockaddr_in6* addr) {
        activesockets[ai].readycbs |= TCP_CONNECT_DONE_CB;
        printf("Connection done!\n");
    }

    event void BSDTCPActiveSocket.receiveReady[uint8_t ai](int gotfin) {
        activesockets[ai].recvReady.arg0 = (uint8_t) gotfin;
        activesockets[ai].readycbs |= TCP_RECV_READY_CB;
        printf("Receive ready!\n");
    }

    event void BSDTCPActiveSocket.sendDone[uint8_t ai](uint32_t numentries) {
        activesockets[ai].sendDone.arg0 += (uint8_t) numentries;
        activesockets[ai].readycbs |= TCP_SEND_DONE_CB;
        printf("Send done!\n");
    }

    event void BSDTCPActiveSocket.connectionLost[uint8_t ai](uint8_t how) {
        activesockets[ai].connectionLost.arg0 = how;
        activesockets[ai].readycbs |= TCP_CONNECTION_LOST_CB;
        printf("Connection lost!\n");
    }

    default command error_t BSDTCPPassiveSocket.bind[uint8_t pundef](uint16_t port) {
        return EBADF;
    }

    default command error_t BSDTCPPassiveSocket.listenaccept[uint8_t pundef] (int activesockid, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp) {
        return EBADF;
    }

    default command error_t BSDTCPPassiveSocket.close[uint8_t pundef] () {
        return EBADF;
    }

    default command error_t BSDTCPActiveSocket.bind[uint8_t aundef](uint16_t port) {
        return EBADF;
    }

    default command int BSDTCPPassiveSocket.getID[uint8_t pundef]() {
        return -1; // BE CAREFUL
    }

    default command int BSDTCPActiveSocket.getID[uint8_t aundef]() {
        return -1; // BE CAREFUL
    }

    default command int BSDTCPActiveSocket.getState[uint8_t aundef]() {
        return TCPS_CLOSED; // BE CAREFUL
    }

    default command void BSDTCPActiveSocket.getPeerInfo[uint8_t aundef](struct in6_addr** addr, uint16_t** port) {
    	*addr = NULL; // BE CAREFUL
    	*port = NULL;
    }

    default command error_t BSDTCPActiveSocket.connect[uint8_t aundef](struct sockaddr_in6* addr, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp) {
        return EBADF;
    }

    default command error_t BSDTCPActiveSocket.send[uint8_t aundef](struct lbufent* data, int moretocome, int* status) {
        return EBADF;
    }

    default command error_t BSDTCPActiveSocket.receive[uint8_t aundef](uint8_t* buffer, uint32_t length, size_t* bytessent) {
        return EBADF;
    }

    default command error_t BSDTCPActiveSocket.shutdown[uint8_t aundef](bool reads, bool writes) {
        return EBADF;
    }

    default command error_t BSDTCPActiveSocket.abort[uint8_t aundef]() {
        return EBADF;
    }

    default command void BSDTCPActiveSocket.getStats[uint8_t asockid](int* segsrcvd, int* segssent, int* sackssent, int* srtt, int* delacks) {
    }

    int alloc_fd(uint32_t* mask, bool (*isvalid)(int) ) {
        int i;
        for (i = 0; i < NUMSOCKETS; i++) {
            if (!(*mask & (1 << i)) && isvalid(i)) {
                *mask |= (1 << i);
                return i;
            }
        }
        return -1;
    }

    bool always_true(int pi) {
        return TRUE;
    }

    int alloc_pfd() {
        int pfd = alloc_fd(&passivemask, always_true);
        if (pfd != -1) {
            passivesockets[pfd].readycbs = 0;
        }
        return pfd + NUMSOCKETS;
    }

    bool active_isclosed(int ai) {
        return TCPS_CLOSED == call BSDTCPActiveSocket.getState[ai]();
    }

    bool active_istimewait(int ai) {
        return TCPS_TIME_WAIT == call BSDTCPActiveSocket.getState[ai]();
    }

    int alloc_afd() {
        int afd;
        // First, try to get a socket that's closed.
        afd = alloc_fd(&activemask, active_isclosed);
        if (afd == -1) {
            // If that failed, try to get a socket in TIME-WAIT, and end the TIME-WAIT early.
            afd = alloc_fd(&activemask, active_istimewait);
            call BSDTCPActiveSocket.abort[afd]();
        }
        if (afd != -1) {
            activesockets[afd].readycbs = 0;
        }
        return afd;
    }

    void dealloc_fd(uint32_t fd, uint32_t* mask) {
        *mask &= ~(1 << fd);
    }

    void dealloc_afd(int afd) {
        dealloc_fd((uint32_t) afd, &activemask);
        clear_activesocket(afd);
    }

    void dealloc_pfd(int pfd) {
        dealloc_fd((uint32_t) pfd, &passivemask);
        clear_passivesocket(pfd);
    }

    inline int check_fd(uint32_t fd, uint32_t* mask) {
        return (*mask & (1 << fd));
    }

    int decode_fd(uint32_t rawfd, bool* passive) {
        if (rawfd >= NUMSOCKETS) {
            *passive = TRUE;
            rawfd -= NUMSOCKETS;
            if (!check_fd(rawfd, &passivemask)) {
                return -1;
            }
        } else {
            *passive = FALSE;
            if (!check_fd(rawfd, &activemask)) {
                return -1;
            }
        }
        return (int) rawfd;
    }

    async command syscall_rv_t Driver.syscall_ex(uint32_t number, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t* argx) {
        struct sockaddr_in6 addr;
        bool passive;
        uint8_t* buffer;
        int fd;
        int afd;
        int afd_id;
        int state;
        size_t length;
        uint32_t svc_id;
        struct in6_addr* addrptr;
        uint16_t* portptr;
        tcp_callback_t* tostore;
        union {
            retry_statistics_t rstats;
            ip_statistics_t istats;
        } stats;
        syscall_rv_t rv = (syscall_rv_t) EBADF;
        fd = decode_fd(arg0, &passive); // most syscalls need this info
        svc_id = number & 0xFF;
        switch (svc_id) {
            case 0x00: // passivesocket()
                rv = (syscall_rv_t) alloc_pfd();
                break;
            case 0x01: // activesocket()
                rv = (syscall_rv_t) alloc_afd();
                break;
            case 0x02: // bind(fd, lport)
                if (fd < 0) {
                    break;
                }
                if (passive) {
                    rv = (syscall_rv_t) call BSDTCPPassiveSocket.bind[fd]((uint16_t) arg1);
                    printf("Bound passive socket to port %d\n", arg1);
                } else {
                    rv = (syscall_rv_t) call BSDTCPActiveSocket.bind[fd]((uint16_t) arg1);
                    printf("Bound active socket to port %d\n", arg1);
                }
                break;
            case 0x03: // connect(fd, faddr, fport, recvbuf, recvbuflen, reassbuf)
                if (fd < 0 || passive) {
                    break;
                }
                if (arg2 > 0xFFFF) {
                    rv = (syscall_rv_t) EINVAL;
                    break;
                }
                inet_pton6((char*) arg1, &addr.sin6_addr);
                addr.sin6_port = htons((uint16_t) arg2);
                rv = (syscall_rv_t) call BSDTCPActiveSocket.connect[fd](&addr, (uint8_t*) argx[0], (size_t) argx[1], (uint8_t*) argx[2]);
                break;
            case 0x04: // listenaccept(fd, recvbuf, recvbuflen, reassbuf)
                if (fd < 0 || !passive) {
                    break;
                }
                afd = alloc_afd();
                if (afd == -1) {
                    rv = (syscall_rv_t) ENFILE;
                    break;
                }
                passivesockets[fd].acceptinginto = afd;
                afd_id = call BSDTCPActiveSocket.getID[afd]();
                rv = (syscall_rv_t) call BSDTCPPassiveSocket.listenaccept[fd](afd_id, (uint8_t*) arg1, (size_t) arg2, (uint8_t*) argx[0]);
                printf("Accepting into socket %d\n", afd);
                break;
            case 0x05: // send(fd, data, status)
                if (fd < 0 || passive) {
                    break;
                }
                rv = (syscall_rv_t) call BSDTCPActiveSocket.send[fd]((struct lbufent*) arg1, 0, (int*) arg2);
                break;
            case 0x06: // receive(fd, buffer, length, numbytes)
                if (fd < 0 || passive) {
                    break;
                }
                buffer = (uint8_t*) arg1;
                length = (size_t) arg2;
                rv = (syscall_rv_t) call BSDTCPActiveSocket.receive[fd](buffer, length, (size_t*) argx[0]);
                break;
            case 0x07: // shutdown(fd, how)
                if (fd < 0 || passive) {
                    break;
                }
                rv = (syscall_rv_t) call BSDTCPActiveSocket.shutdown[fd]((arg1 == SHUT_RD) || (arg1 == SHUT_RDWR),
                                                                         (arg1 == SHUT_WR) || (arg1 == SHUT_RDWR));
                break;
            case 0x08: // close(fd)
                if (fd < 0) {
                    break;
                }
                if (passive) {
                    rv = (syscall_rv_t) call BSDTCPPassiveSocket.close[fd]();
                    dealloc_pfd(fd);
                    if (passivesockets[fd].acceptinginto != -1) {
                        dealloc_afd(passivesockets[fd].acceptinginto);
                        passivesockets[fd].acceptinginto = -1;
                    }
                } else {
                    rv = (syscall_rv_t) call BSDTCPActiveSocket.shutdown[fd](TRUE, TRUE);
                    dealloc_afd(fd);
                }
                break;
            case 0x09: // abort(fd)
                if (fd < 0) {
                    break;
                }
                if (passive) {
                    rv = (syscall_rv_t) call BSDTCPPassiveSocket.close[fd]();
                } else {
                    rv = (syscall_rv_t) call BSDTCPActiveSocket.abort[fd]();
                }
                break;
            case 0x0a: // set_connectDone_cb(fd, cb, r)
                if (fd < 0 || passive) {
                    break;
                }
                tostore = &activesockets[fd].connectDone;
                goto setcb;
            case 0x0b: // set_sendDone_cb(fd, cb, r)
                if (fd < 0 || passive) {
                    break;
                }
                tostore = &activesockets[fd].sendDone;
                goto setcb;
            case 0x0c: // set_recvReady_cb(fd, cb, r)
                if (fd < 0 || passive) {
                    break;
                }
                tostore = &activesockets[fd].recvReady;
                goto setcb;
            case 0x0d: // set_connectionLost_cb(fd, cb, r)
                if (fd < 0 || passive) {
                    break;
                }
                tostore = &activesockets[fd].connectionLost;
                goto setcb;
            case 0x0e: // set_acceptDone_cb(fd, cb, r)
                if (fd < 0 || !passive) {
                    break;
                }
                tostore = &passivesockets[fd].acceptDone;
            setcb:
                tostore->addr = arg1;
                tostore->r = (void*) arg2;
                rv = 0;
                break;
            case 0x0f: // isestablished(fd)
                if (fd < 0 || passive) {
                    break;
                }
                rv = (syscall_rv_t) TCPS_HAVEESTABLISHED(call BSDTCPActiveSocket.getState[fd]());
                break;
            case 0x10: // hasrcvdfin(fd)
                if (fd < 0 || passive) {
                    break;
                }
                state = call BSDTCPActiveSocket.getState[fd]();
                rv = (syscall_rv_t) (state == TCPS_TIME_WAIT || state == TCPS_CLOSE_WAIT || state == TCPS_LAST_ACK || state == TCPS_CLOSING);
                break;
            case 0x11: // peerinfo(fd, addr, len, port)
            	if (fd < 0 || passive) {
            		break;
            	}
            	call BSDTCPActiveSocket.getPeerInfo[fd](&addrptr, &portptr);
            	inet_ntop6(addrptr, (char*) arg1, (int) arg2);
            	*((uint16_t*) argx[0]) = ntohs(*portptr);
            	rv = (syscall_rv_t) 0;
            	break;
            /*case 0x12: // stats(fd, segssent, sackssent, srtt)
                if (fd < 0 || passive) {
                    break;
                }
                call BSDTCPActiveSocket.getStats[fd]((int*) arg1, (int*) arg2, (int*) argx[0], (int*) argx[1], (int*) argx[2]);
                call RetryStatistics.get(&stats.rstats);
                *((int*) argx[3]) = stats.rstats.tx_cnt;
                {
                    char str[100];
                    uint32_t* attempts = call RadioStats.getAttempts();
                    snprintf(str, 100, "rsa: %d, rra: %d, tx: %d, rx: %d, txf: %d\n", attempts[0], attempts[1],
                    call TrafficMonitor.getTxMessages(), call TrafficMonitor.getRxMessages(), call TrafficMonitor.getTxErrors());
                    storm_write_payload(str, strlen(str));
                    snprintf(str, 100, "%d, %d, %d, %d, %d, %d, ND: %d\n", stats.rstats.retries[0], stats.rstats.retries[1], stats.rstats.retries[2], stats.rstats.retries[3], stats.rstats.retries[4], stats.rstats.retries[5], stats.rstats.retries[6]);
                    storm_write_payload(str, strlen(str));
                }
                call IPStatistics.get(&stats.istats);
                *((int*) argx[4]) = stats.istats.rx_total;
                break;*/
            default:
                printf("Doing nothing\n");
                break;
        }
        return rv;
    }
}
