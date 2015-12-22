#define NUMBSDTCPACTIVESOCKETS 2
#define NUMBSDTCPPASSIVESOCKETS 2

#define hz 10 // number of ticks per second
#define MILLIS_PER_TICK 100 // number of milliseconds per tick

module BsdTcpP {

    provides {
        interface BSDTCPActiveSocket[uint8_t asockid];
        interface BSDTCPPassiveSocket[uint8_t psockid];
    } uses {
        interface Boot;
        interface IP;
        interface IPAddress;
        interface Timer<TMilli>[uint8_t timerid];
        interface Timer<TMilli> as TickTimer;
    }
    
} implementation {
#include <bsdtcp/cbuf.h>
#include <bsdtcp/tcp_var.h>

	#define SIG_CONN_ESTABLISHED 0x01
    #define SIG_SENDBUF_NOTFULL 0x02
    #define SIG_RECVBUF_NOTEMPTY 0x04
    
    #define CONN_LOST_NORMAL 0x00
    #define CONN_LOST_EPIPE 0x01
    #define CONN_LOST_ECONNREFUSED 0x02

    uint32_t get_ticks();
    void send_message(struct tcpcb* tp, struct ip6_packet* msg, struct tcphdr* th, uint32_t tlen);
    void set_timer(struct tcpcb* tcb, uint8_t timer_id, uint32_t delay);
    void stop_timer(struct tcpcb* tcb, uint8_t timer_id);
    void accepted_connection(struct tcpcb_listen* tpl, struct in6_addr* addr, uint16_t port);
    void handle_signals(struct tcpcb* tp, uint8_t signals);
    void connection_lost(struct tcpcb* tp, uint8_t reason);
    
#include <bsdtcp/tcp_subr.c>
#include <bsdtcp/tcp_output.c>

#include <bsdtcp/tcp_input.c>

#include <bsdtcp/tcp_timer.c>
#include <bsdtcp/tcp_timewait.c>
#include <bsdtcp/tcp_usrreq.c>
#include <bsdtcp/checksum.c>

    struct tcpcb tcbs[NUMBSDTCPACTIVESOCKETS];
    struct tcpcb_listen tcbls[NUMBSDTCPPASSIVESOCKETS];
    uint32_t ticks = 0;
    
    event void Boot.booted() {
        int i;
        tcp_init();
        for (i = 0; i < NUMBSDTCPACTIVESOCKETS; i++) {
            initialize_tcb(&tcbs[i], 0, i);
        }
        for (i = 0; i < NUMBSDTCPPASSIVESOCKETS; i++) {
            tcbls[i].t_state = TCPS_CLOSED;
            tcbls[i].index = i;
            tcbls[i].lport = 0;
            tcbls[i].acceptinto = NULL;
        }
        call TickTimer.startPeriodic(MILLIS_PER_TICK);
    }
    
    event void TickTimer.fired() {
        ticks++;
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
        case TOS_REXMT:
            printf("Retransmit\n");
		    tcp_timer_rexmt(tp);
		    break;
	    case TOS_PERSIST:
	        printf("Persist\n");
	        tcp_timer_persist(tp);
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
    
    void handle_signals(struct tcpcb* tp, uint8_t signals) {
        struct sockaddr_in6 addrport;
        
        if (signals & SIG_CONN_ESTABLISHED) {
            addrport.sin6_port = tp->fport;
            memcpy(&addrport.sin6_addr, &tp->faddr, 0);
        
            signal BSDTCPActiveSocket.connectDone[tp->index](&addrport);
        }
        if (signals & SIG_SENDBUF_NOTFULL) {
            signal BSDTCPActiveSocket.sendReady[tp->index]();
        }
        if (signals & SIG_RECVBUF_NOTEMPTY) {
            signal BSDTCPActiveSocket.receiveReady[tp->index]();
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
        
        th = (struct tcphdr*) packet;
        sport = th->th_sport; // network byte order
        dport = th->th_dport; // network byte order
        #ifndef BLIP_STFU
        printf("TCP - IP.recv: len: %i (%i) srcport: %u dstport: %u SYN: %d ACK: %d, FIN: %d\n",
            ntohs(iph->ip6_plen), len,
            ntohs(sport), ntohs(dport),
            (th->th_flags & TH_SYN) != 0, (th->th_flags & TH_ACK) != 0, (th->th_flags & TH_FIN) != 0);
        #endif
        if (get_checksum(&iph->ip6_src, &iph->ip6_dst, th, len)) {
            printf("Dropping packet: bad checksum\n");
            return;
        }
        tcp_fields_to_host(th);
        for (i = 0; i < NUMBSDTCPACTIVESOCKETS; i++) {
            tcb = &tcbs[i];
            if (tcb->t_state != TCP6S_CLOSED && dport == tcb->lport && sport == tcb->fport && !memcmp(&iph->ip6_src, &tcb->faddr, sizeof(iph->ip6_src))) {
                // Matches this active socket
                printf("Matches active socket %d\n", i); 
                if (RELOOKUP_REQUIRED == tcp_input(iph, (struct tcphdr*) packet, &tcbs[i], NULL, &signals)) {
                    break;
                } else {
                    handle_signals(&tcbs[i], signals);
                }
                return;
            }
        }
        for (i = 0; i < NUMBSDTCPPASSIVESOCKETS; i++) {
            tcbl = &tcbls[i];
            if (tcbl->t_state == TCP6S_LISTEN && dport == tcbl->lport) {
                // Matches this passive socket
                printf("Matches passive socket %d\n", i);
                tcp_input(iph, (struct tcphdr*) packet, NULL, &tcbls[i], NULL);
                return;
            }
        }
        printf("Does not match any socket\n");
        tcp_dropwithreset(iph, th, NULL, len - (th->th_off << 2), ECONNREFUSED);
    }
    
    event void IPAddress.changed(bool valid) {
    }
    
    command int BSDTCPActiveSocket.getID[uint8_t asockid]() {
        return tcbs[asockid].index;
    }
    
    command error_t BSDTCPActiveSocket.bind[uint8_t asockid](uint16_t port) {
        tcbs[asockid].lport = htons(port);
        return SUCCESS;
    }
    
    command error_t BSDTCPPassiveSocket.bind[uint8_t psockid](uint16_t port) {
        tcbls[psockid].lport = htons(port);
        return SUCCESS;
    }
    
    command error_t BSDTCPPassiveSocket.listenaccept[uint8_t psockid](int asockid) {
        tcbls[psockid].t_state = TCP6S_LISTEN;
        if (tcbs[asockid].t_state != TCP6S_CLOSED) {
            printf("Cannot accept connection into active socket that isn't closed\n");
            return -1;
        }
        tcbls[psockid].acceptinto = &tcbs[asockid];
        return SUCCESS;
    }
    
    command error_t BSDTCPActiveSocket.connect[uint8_t asockid](struct sockaddr_in6* addr) {
        struct tcpcb* tp = &tcbs[asockid];
        return tcp6_usr_connect(tp, addr);
    }
    
    command error_t BSDTCPActiveSocket.send[uint8_t asockid](uint8_t* data, uint8_t length, int moretocome, size_t* bytessent) {
        struct tcpcb* tp = &tcbs[asockid];
        return (error_t) tcp_usr_send(tp, moretocome, data, length, bytessent);
    }
    
    command error_t BSDTCPActiveSocket.receive[uint8_t asockid](uint8_t* buffer, uint8_t len, size_t* bytessent) {
        struct tcpcb* tp = &tcbs[asockid];
        *bytessent = cbuf_read(tp->recvbuf, buffer, len, 1);
        return (error_t) tcp_usr_rcvd(tp);
    }
    
    command error_t BSDTCPActiveSocket.shutdown[uint8_t asockid](bool shut_rd, bool shut_wr) {
        if (shut_rd) {
            tpcantrcvmore(&tcbs[asockid]);
        }
        if (shut_wr) {
            tcp_usr_shutdown(&tcbs[asockid]);
        }
        return SUCCESS;
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
    
    default event void BSDTCPPassiveSocket.acceptDone[uint8_t psockid](struct sockaddr_in6* addr, int asockid) {
    }
    
    default event void BSDTCPActiveSocket.connectDone[uint8_t asockid](struct sockaddr_in6* addr) {
    }
    
    default event void BSDTCPActiveSocket.sendReady[uint8_t asockid]() {
    }
    
    default event void BSDTCPActiveSocket.receiveReady[uint8_t asockid]() {
    }
    
    default event void BSDTCPActiveSocket.connectionLost[uint8_t asockid](uint8_t how) {
    }

    /* Wrapper for underlying C code. */
    void send_message(struct tcpcb* tp, struct ip6_packet* msg, struct tcphdr* th, uint32_t tlen) {
        char destaddr[100];
        msg->ip6_hdr.ip6_vfc = IPV6_VERSION;
        call IPAddress.setSource(&msg->ip6_hdr);
        th->th_sum = 0; // should be zero already, but just in case
        th->th_sum = get_checksum(&msg->ip6_hdr.ip6_src, &msg->ip6_hdr.ip6_dst, th, tlen);
        inet_ntop6(&msg->ip6_hdr.ip6_dst, destaddr, 100);
        printf("Sending message to %s\n", destaddr);
        printf("Return value: %d\n", call IP.send(msg));
    }
    
    uint32_t get_ticks() {
        return ticks;
    }
    
    void set_timer(struct tcpcb* tcb, uint8_t timer_id, uint32_t delay) {
        uint8_t tcb_index = (uint8_t) tcb->index;
        uint8_t timer_index = (tcb_index << 2) | timer_id;
        if (timer_id > 0x3) {
            printf("WARNING: setting out of bounds timer!\n");
        }
        printf("Setting timer %d, delay is %d\n", timer_index, delay * MILLIS_PER_TICK);
        call Timer.startOneShot[timer_index](delay * MILLIS_PER_TICK);
    }
    
    void stop_timer(struct tcpcb* tcb, uint8_t timer_id) {
        uint8_t tcb_index = (uint8_t) tcb->index;
        uint8_t timer_index = (tcb_index << 2) | timer_id;
        if (timer_index > 0x3) {
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
    
    void connection_lost(struct tcpcb* tcb, uint8_t reason) {
        signal BSDTCPActiveSocket.connectionLost[tcb->index](reason);
    }
}
