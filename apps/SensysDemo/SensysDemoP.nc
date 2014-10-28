/*
 * Copyright (c) 2008-2010 The Regents of the University  of California.
 * All rights reserved."
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the copyright holders nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <IPDispatch.h>
#include <lib6lowpan/lib6lowpan.h>
#include <lib6lowpan/ip.h>
#include <lib6lowpan/ip.h>
#include <printf.h>

#define DATA_TX_PERIOD 5000L

module SensysDemoP
{
    uses
    {
        interface Boot;
        interface SplitControl as RadioControl;
        interface UDP as Sock;
        interface GeneralIO as Led;
        interface Timer<TMilli> as Timer;
        interface SplitControl as SensorControl;
        interface FlashAttr;
        interface RootControl;
        interface FSIlluminance;
        interface FSAccelerometer;
        interface ForwardingTable;
        interface StdControl as RplControl;
    }
}
implementation
{
    struct sockaddr_in6 data_dest;
    struct sockaddr_in6 nhop;
    bool do_data_tx;

    bool shouldBeRoot()
    {
        uint8_t key [10];
        uint8_t val [65];
        uint8_t val_len;
        error_t e;

        e = call FlashAttr.getAttr(1, key, val, &val_len);
        if (e != SUCCESS)
        {
            printf ("failed to get attr\n");
        }
        return (e == SUCCESS && val_len == 1 && (val[0] == 1 || val[0] == '1'));
    }
    void loadDataTarget()
    {
        uint8_t key [10];
        uint8_t val [65];
        uint8_t val_len;
        error_t e;

        e = call FlashAttr.getAttr(2, key, val, &val_len);
        if (e != SUCCESS || val_len < 4)
        {
            printf ("failed to get data target\n");
            do_data_tx = FALSE;
            return;
        }
        val[val_len] = 0;
        printf("sending data to %s\n", val);
        inet_pton6(val, &data_dest.sin6_addr);
        do_data_tx = TRUE;
    }

    event void Boot.booted()
    {
        data_dest.sin6_port = htons(4410);;
        call Timer.startPeriodic(DATA_TX_PERIOD);
        call Sock.bind(4410);
        call Led.makeOutput();
        call Led.set();
        call SensorControl.start();

        if (shouldBeRoot())
        {
            printf("Node configured to be root\n");
            call RootControl.setRoot();
        }
        else
        {
            printf("Node is not DODAG root\n");
        }
        loadDataTarget();
        call RadioControl.start();


    }

    event void RadioControl.startDone(error_t e) {}
    event void RadioControl.stopDone(error_t e) {}
    event void SensorControl.startDone(error_t e) {}
    event void SensorControl.stopDone(error_t e) {}

    typedef struct
    {
        int16_t acc_x;
        int16_t acc_y;
        int16_t acc_z;
        int16_t mag_x;
        int16_t mag_y;
        int16_t mag_z;
        uint16_t lux;
        uint16_t fdest[8];
        uint16_t fnhop[8];
        uint8_t pfxlen[8];
        uint8_t ftable_len;
    } __attribute__((__packed__))  node_data_t;

    void print_dstruct(node_data_t *v)
    {
        int i, mx;
        printf("  ACC_X: %d\n",v->acc_x);
        printf("  ACC_Y: %d\n",v->acc_y);
        printf("  ACC_Z: %d\n",v->acc_z);
        printf("  MAG_X: %d\n",v->mag_x);
        printf("  MAG_Y: %d\n",v->mag_y);
        printf("  MAG_Z: %d\n",v->mag_z);
        printf("    LUX: %d\n",v->lux);
        printf("  FTLEN: %d\n",v->ftable_len);
        mx = v->ftable_len;
        if (mx > 8) mx = 8;
        for (i = 0; i<mx; i++)
        {
            printf("    - [%d]: X::%04x/%d via X::%04x\n", i, v->fdest[i], v->pfxlen[i], v->fnhop[i]);
        }

    }
    event void Sock.recvfrom(struct sockaddr_in6 *from, void *data,
                             uint16_t len, struct ip6_metadata *meta)
    {
        node_data_t *rx;
        uint16_t from_serial;
        from_serial = from->sin6_addr.s6_addr[14];
        from_serial = (from_serial << 8) + from->sin6_addr.s6_addr[15];
        if (len == sizeof(node_data_t))
        {
            printf("\033[32;1m");
            printf("Got a data struct from 0x%04x\n", from_serial);
            rx = (node_data_t*) data;
            print_dstruct(rx);
            printf("\033[0m\n");
        }
        else
        {
            printf("Got random data\n");
        }
    }


    event void Timer.fired()
    {
        node_data_t tx;
        struct route_entry *ft;
        int i;
        int max_size;
        int valid_size;

        if (!do_data_tx) return;
        call Led.toggle();

        tx.acc_x = call FSAccelerometer.getAccelX();
        tx.acc_y = call FSAccelerometer.getAccelY();
        tx.acc_z = call FSAccelerometer.getAccelZ();
        tx.mag_x = call FSAccelerometer.getMagnX();
        tx.mag_y = call FSAccelerometer.getMagnY();
        tx.mag_z = call FSAccelerometer.getMagnZ();
        tx.lux = (uint16_t) call FSIlluminance.getVisibleLux();
        ft = call ForwardingTable.getTable(&max_size);
        valid_size = 0;
        for (i = 0; i < max_size; i++)
        {
            if (!ft[i].valid) continue;
            if (valid_size < 8)
            {
                struct in6_addr ad;
                ad = ft[i].prefix;
                tx.fdest[valid_size] = ((uint16_t)ad.s6_addr[14] << 8) + ad.s6_addr[15];
                ad = ft[i].next_hop;
                tx.fnhop[valid_size] = ((uint16_t)ad.s6_addr[14] << 8) + ad.s6_addr[15];
                tx.pfxlen[valid_size] = ft[i].prefixlen;
            }
            valid_size++;
        }
        tx.ftable_len = valid_size;
        call Sock.sendto(&data_dest, &tx, sizeof(node_data_t));
    }
}
