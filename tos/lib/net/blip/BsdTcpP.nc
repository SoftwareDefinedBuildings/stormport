#include <bsdtcp.h>

#include "blip_printf.h"

#define NUMBSDTCPACTIVESOCKETS uniqueCount(UQ_BSDTCP_ACTIVE)
#define NUMBSDTCPPASSIVESOCKETS uniqueCount(UQ_BSDTCP_PASSIVE)

#define hz 1000 // number of ticks per second
#define MILLIS_PER_TICK 1 // number of milliseconds per tick

#define FRAMES_PER_SEG 4
#define FRAMECAP_6LOWPAN (122 - 22 - 12) // Fragmentation limit: maximum frame size of the IP and TCP headers

#define COMPRESSED_IP6HDR_SIZE (2 + 1 + 1 + 16 + 8) // IPHC header (2) + Next header (1) + Hop count (1) + Dest. addr (16) + Src. addr (8)

module BsdTcpP {

    provides {
        interface BSDTCPActiveSocket[uint8_t asockid];
        interface BSDTCPPassiveSocket[uint8_t psockid];
    } uses {
        interface Boot;
        interface IP;
        interface IPAddress;
        interface Timer<TMilli>[uint8_t timerid];
        interface LocalTime<TMilli>;
    }

} implementation {
#include <bsdtcp/cbuf.h>
#include <bsdtcp/lbuf.h>
#include <bsdtcp/tcp_var.h>
#include <bsdtcp/sys/errno.h>

    #define SIG_CONN_ESTABLISHED 0x01
    #define SIG_RECVBUF_NOTEMPTY 0x02
    #define SIG_RCVD_FIN         0x04

    #define CONN_LOST_NORMAL 0 // errno of 0 means that the connection closed gracefully

    uint32_t get_ticks();
    uint32_t get_millis();
    void send_message(struct tcpcb* tp, struct ip6_packet* msg, struct tcphdr* th, uint32_t tlen);
    void set_timer(struct tcpcb* tcb, uint8_t timer_id, uint32_t delay);
    void stop_timer(struct tcpcb* tcb, uint8_t timer_id);
    void accepted_connection(struct tcpcb_listen* tpl, struct in6_addr* addr, uint16_t port);
    void handle_signals(struct tcpcb* tp, uint8_t signals, uint32_t freedentries);
    void connection_lost(struct tcpcb* tp, uint8_t reason);

#include <bsdtcp/bitmap.c>
#include <bsdtcp/cbuf.c>
#include <bsdtcp/lbuf.c>
#include <bsdtcp/tcp_subr.c>
#include <bsdtcp/tcp_output.c>
#include <bsdtcp/tcp_input.c>
#include <bsdtcp/tcp_timer.c>
#include <bsdtcp/tcp_timewait.c>
#include <bsdtcp/tcp_usrreq.c>
#include <bsdtcp/tcp_reass.c>
#include <bsdtcp/tcp_sack.c>
#include <bsdtcp/checksum.c>
#include <bsdtcp/cc/cc_newreno.c>

    struct tcpcb tcbs[NUMBSDTCPACTIVESOCKETS];
    struct tcpcb_listen tcbls[NUMBSDTCPPASSIVESOCKETS];

    int segs_rcvd = 0;

    int delack = 0;

    event void Boot.booted() {
        int i;
        tcp_init();
        for (i = 0; i < NUMBSDTCPACTIVESOCKETS; i++) {
            tcbs[i].index = i;
            initialize_tcb(&tcbs[i], 0, NULL, 0, NULL);
        }
        for (i = 0; i < NUMBSDTCPPASSIVESOCKETS; i++) {
            tcbls[i].t_state = TCPS_CLOSED;
            tcbls[i].index = i;
            tcbls[i].lport = 0;
            tcbls[i].acceptinto = NULL;
        }
    }

    event void Timer.fired[uint8_t timer_id]() {
        struct tcpcb* tp;
        if (call Timer.isRunning[timer_id]()) {
            // In case the timer was rescheduled after this was posted but before this runs
            return;
        }
        printf("Timer %d fired!\n", timer_id);

        tp = &tcbs[timer_id >> 2];
        timer_id &= 0x3;

        switch(timer_id) {
        case TOS_DELACK:
            printf("Delayed ACK\n");
            tcp_timer_delack(tp);
            break;
        case TOS_REXMT: // Also includes persist case
            if (tpistimeractive(tp, TT_REXMT)) {
                printf("Retransmit\n");
                tcp_timer_rexmt(tp);
            } else {
                printf("Persist\n");
                tcp_timer_persist(tp);
            }
            break;
        case TOS_KEEP:
            printf("Keep\n");
            tcp_timer_keep(tp);
            break;
        case TOS_2MSL:
            printf("2MSL\n");
            tcp_timer_2msl(tp);
            break;
        }
    }

    void handle_signals(struct tcpcb* tp, uint8_t signals, uint32_t freedentries) {
        struct sockaddr_in6 addrport;

        if (signals & SIG_CONN_ESTABLISHED) {
            addrport.sin6_port = tp->fport;
            memcpy(&addrport.sin6_addr, &tp->faddr, 0);

            signal BSDTCPActiveSocket.connectDone[tp->index](&addrport);
        }

        if (signals & SIG_RECVBUF_NOTEMPTY) {
            signal BSDTCPActiveSocket.receiveReady[tp->index](0);
        }

        if (signals & SIG_RCVD_FIN) {
            signal BSDTCPActiveSocket.receiveReady[tp->index](1);
        }

        if (freedentries > 0) {
            signal BSDTCPActiveSocket.sendDone[tp->index](freedentries);
        }
    }

    event void IP.recv(struct ip6_hdr* iph, void* packet, size_t len,
                       struct ip6_metadata* meta) {
        // This is only being called if the IP address matches mine.
        // Match this to a TCP socket
        volatile int j;
        int i;
        struct tcphdr* th;
        uint16_t sport, dport;
        struct tcpcb* tcb;
        struct tcpcb_listen* tcbl;
        uint8_t signals = 0; // bitmask of signals that need to be sent to an upper layer
        uint32_t freedentries = 0; // number of lbuf entries that an upper layer can reclaim
        struct ip_iovec wrapper; // to calculate the checksum
        wrapper.iov_base = packet;
        wrapper.iov_len = len;
        wrapper.iov_next = NULL;

        segs_rcvd++;

        th = (struct tcphdr*) packet;
        sport = th->th_sport; // network byte order
        dport = th->th_dport; // network byte order
        #ifndef BLIP_STFU
        printf("TCP - IP.recv: len: %i (%i) srcport: %u dstport: %u SYN: %d ACK: %d, FIN: %d\n",
            ntohs(iph->ip6_plen), len,
            ntohs(sport), ntohs(dport),
            (th->th_flags & TH_SYN) != 0, (th->th_flags & TH_ACK) != 0, (th->th_flags & TH_FIN) != 0);
        #endif
        if (get_checksum(&iph->ip6_src, &iph->ip6_dst, &wrapper, len)) {
            printf("Dropping packet: bad checksum\n");
            return;
        }
        tcp_fields_to_host(th);
        for (i = 0; i < NUMBSDTCPACTIVESOCKETS; i++) {
            tcb = &tcbs[i];
            if (tcb->t_state != TCP6S_CLOSED && dport == tcb->lport && sport == tcb->fport && !memcmp(&iph->ip6_src, &tcb->faddr, sizeof(iph->ip6_src))) {
                // Matches this active socket
                printf("Matches active socket %d\n", i);
                if (RELOOKUP_REQUIRED == tcp_input(iph, (struct tcphdr*) packet, &tcbs[i], NULL, &signals, &freedentries)) {
                    break;
                } else {
                    handle_signals(&tcbs[i], signals, freedentries);
                }
                return;
            }
        }
        for (i = 0; i < NUMBSDTCPPASSIVESOCKETS; i++) {
            tcbl = &tcbls[i];
            if (tcbl->t_state == TCP6S_LISTEN && dport == tcbl->lport) {
                // Matches this passive socket
                printf("Matches passive socket %d\n", i);
                tcp_input(iph, (struct tcphdr*) packet, NULL, &tcbls[i], NULL, NULL);
                return;
            }
        }
        printf("Does not match any socket\n");
        tcp_dropwithreset(iph, th, NULL, len - (th->th_off << 2), ECONNREFUSED);
    }

    event void IPAddress.changed(bool valid) {
    }

    command int BSDTCPPassiveSocket.getID[uint8_t psockid]() {
        return tcbls[psockid].index;
    }

    command int BSDTCPActiveSocket.getID[uint8_t asockid]() {
        return tcbs[asockid].index;
    }

    command int BSDTCPActiveSocket.getState[uint8_t asockid]() {
        return tcbs[asockid].t_state;
    }

    command void BSDTCPActiveSocket.getPeerInfo[uint8_t asockid](struct in6_addr** addr, uint16_t** port) {
    	*addr = &tcbs[asockid].faddr;
    	*port = &tcbs[asockid].fport;
    }

    /* PORT is in network-byte order. */
    bool portisfree(uint16_t port) {
        int i;
        for (i = 0; i < NUMBSDTCPACTIVESOCKETS; i++) {
            if (tcbs[i].lport == port) {
                return FALSE;
            }
        }
        for (i = 0; i < NUMBSDTCPPASSIVESOCKETS; i++) {
            if (tcbls[i].lport == port) {
                return FALSE;
            }
        }
        return TRUE;
    }

    command error_t BSDTCPActiveSocket.bind[uint8_t asockid](uint16_t port) {
        uint16_t oldport = tcbs[asockid].lport;
        port = htons(port);
        tcbs[asockid].lport = 0;
        if (port == 0 || portisfree(port)) {
            tcbs[asockid].lport = port;
            return SUCCESS;
        }
        tcbs[asockid].lport = oldport;
        return EADDRINUSE;
    }

    command error_t BSDTCPPassiveSocket.bind[uint8_t psockid](uint16_t port) {
        uint16_t oldport = tcbls[psockid].lport;
        port = htons(port);
        tcbls[psockid].lport = 0;
        if (port == 0 || portisfree(port)) {
            tcbls[psockid].lport = port;
            return SUCCESS;
        }
        tcbls[psockid].lport = oldport;
        return EADDRINUSE;
    }

    command error_t BSDTCPPassiveSocket.listenaccept[uint8_t psockid](int asockid, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp) {
        tcbls[psockid].t_state = TCPS_LISTEN;
        if (tcbs[asockid].t_state != TCPS_CLOSED) {
            tcbls[psockid].t_state = TCPS_CLOSED;
            return EISCONN;
        }
        initialize_tcb(&tcbs[asockid], tcbs[asockid].lport, recvbuf, recvbuflen, reassbmp);
        tcbls[psockid].acceptinto = &tcbs[asockid];
        return SUCCESS;
    }

    command error_t BSDTCPActiveSocket.connect[uint8_t asockid](struct sockaddr_in6* addr, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp) {
        struct tcpcb* tp = &tcbs[asockid];
        if (tp->t_state != TCPS_CLOSED) { // This is a check that I added
            return (EISCONN);
        }
        initialize_tcb(tp, tp->lport, recvbuf, recvbuflen, reassbmp);
        return tcp6_usr_connect(tp, addr);
    }

    command error_t BSDTCPActiveSocket.send[uint8_t asockid](struct lbufent* data, int moretocome, int* status) {
        struct tcpcb* tp = &tcbs[asockid];
        return (error_t) tcp_usr_send(tp, moretocome, data, status);
    }

    command error_t BSDTCPActiveSocket.receive[uint8_t asockid](uint8_t* buffer, uint32_t len, size_t* bytessent) {
        struct tcpcb* tp = &tcbs[asockid];
        *bytessent = cbuf_read(&tp->recvbuf, buffer, len, 1);
        return (error_t) tcp_usr_rcvd(tp);
    }

    command error_t BSDTCPActiveSocket.shutdown[uint8_t asockid](bool shut_rd, bool shut_wr) {
        int error = SUCCESS;
        if (shut_rd) {
            cbuf_pop(&tcbs[asockid].recvbuf, cbuf_used_space(&tcbs[asockid].recvbuf)); // remove all data from the cbuf
            // TODO We need to deal with bytes received out-of-order
            // Our strategy is to "pretend" that we got those extra bytes and ACK them.
            tpcantrcvmore(&tcbs[asockid]);
        }
        if (shut_wr) {
            error = tcp_usr_shutdown(&tcbs[asockid]);
        }
        return error;
    }

    command error_t BSDTCPPassiveSocket.close[uint8_t psockid]() {
        tcbls[psockid].t_state = TCP6S_CLOSED;
        tcbls[psockid].acceptinto = NULL;
        return SUCCESS;
    }

    command error_t BSDTCPActiveSocket.abort[uint8_t asockid]() {
        tcp_usr_abort(&tcbs[asockid]);
        return SUCCESS;
    }

    command void BSDTCPActiveSocket.getStats[uint8_t asockid](int* segsrcvd, int* segssent, int* sackssent, int* srtt, int* delacks) {
        *segsrcvd = segs_rcvd;
        *segssent = segs_sent;
        *sackssent = sacks_sent;
        *srtt = tcbs[asockid].t_srtt;
        *delacks = delack;
    }

    default event void BSDTCPPassiveSocket.acceptDone[uint8_t psockid](struct sockaddr_in6* addr, int asockid) {
    }

    default event void BSDTCPActiveSocket.connectDone[uint8_t asockid](struct sockaddr_in6* addr) {
    }

    default event void BSDTCPActiveSocket.sendDone[uint8_t asockid](uint32_t numentries) {
    }

    default event void BSDTCPActiveSocket.receiveReady[uint8_t asockid](int gotfin) {
    }

    default event void BSDTCPActiveSocket.connectionLost[uint8_t asockid](uint8_t how) {
    }

    /* Wrapper for underlying C code. */
    void send_message(struct tcpcb* tp, struct ip6_packet* msg, struct tcphdr* th, uint32_t tlen) {
        char destaddr[50];
        msg->ip6_hdr.ip6_vfc = IPV6_VERSION;
        call IPAddress.setSource(&msg->ip6_hdr);
        th->th_sum = 0; // should be zero already, but just in case
        th->th_sum = get_checksum(&msg->ip6_hdr.ip6_src, &msg->ip6_hdr.ip6_dst, msg->ip6_data, tlen);
        inet_ntop6(&msg->ip6_hdr.ip6_dst, destaddr, 50);
        printf("Sending message to %s\n", destaddr);
        //printf("Return value: %d\n", call IP.send(msg));

        segs_sent++;

        if (0 != call IP.send(msg)) {
            printf("tcp: dropped segment\n");
        }
    }

    uint32_t get_ticks() {
        return call LocalTime.get();
    }

    uint32_t get_millis() {
        return call LocalTime.get();
    }

    void set_timer(struct tcpcb* tcb, uint8_t timer_id, uint32_t delay) {
        uint8_t tcb_index = (uint8_t) tcb->index;
        uint8_t timer_index = (tcb_index << 2) | timer_id;
        if (timer_id > 0x3) {
            //printf("WARNING: setting out of bounds timer!\n");
        }
        if (timer_index == 0) {
            delack++;
        }
        //printf("Setting timer %d, delay is %d\n", timer_index, delay * MILLIS_PER_TICK);
        call Timer.startOneShot[timer_index](delay * MILLIS_PER_TICK);
    }

    void stop_timer(struct tcpcb* tcb, uint8_t timer_id) {
        uint8_t tcb_index = (uint8_t) tcb->index;
        uint8_t timer_index = (tcb_index << 2) | timer_id;
        if (timer_id > 0x3) {
            printf("WARNING: stopping out of bounds timer!\n");
        }
        printf("Stopping timer %d\n", timer_index);
        call Timer.stop[timer_index]();
    }

    void accepted_connection(struct tcpcb_listen* tpl, struct in6_addr* addr, uint16_t port) {
        struct sockaddr_in6 addrport;
        addrport.sin6_port = port;
        memcpy(&addrport.sin6_addr, addr, sizeof(struct in6_addr));
        signal BSDTCPPassiveSocket.acceptDone[tpl->index](&addrport, tpl->acceptinto->index);
        tpl->t_state = TCPS_CLOSED;
        tpl->acceptinto = NULL;
    }

    void connection_lost(struct tcpcb* tcb, uint8_t errno) {
        signal BSDTCPActiveSocket.connectionLost[tcb->index](errno);
    }
}
