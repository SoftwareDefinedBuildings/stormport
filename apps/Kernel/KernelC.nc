/*
 * Copyright (c) 2008 The Regents of the University  of California.
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

#include <lib6lowpan/6lowpan.h>

configuration KernelC
{

}
implementation
{
    components MainC, LedsC;
    components KernelMainP;

    KernelMainP.Boot -> MainC;

    components IPStackC;
    components IPAddressC;
    components LocalIeeeEui64P;

    KernelMainP.RadioControl ->  IPStackC;
#if RPL_ROUTING
    components RPLRoutingC;
    KernelMainP.RPLControl -> RPLRoutingC;
    KernelMainP.RootControl -> RPLRoutingC;
#else
#if SERP_ROUTING
    components SERPRoutingC;
    KernelMainP.RootControl -> SERPRoutingC;
#endif
#endif
    KernelMainP.NeighborDiscovery ->  IPStackC;
    KernelMainP.SetIPAddress -> IPAddressC;
    KernelMainP.LocalIeeeEui64 -> LocalIeeeEui64P;

    components FlashAttrC;
    KernelMainP.FlashAttr -> FlashAttrC;

    components new Timer32khzC();
    KernelMainP.Timer -> Timer32khzC;

    components UdpC, IPDispatchC;

    components PlatformSerialC;
    KernelMainP.UartStream -> PlatformSerialC;

    components StaticIPAddressC; // Use LocalIeee154 in address
    components SerialPrintfC;

#ifdef WITH_WIZ
    components IPPacketC;
    components EthernetP;
    components IPForwardingEngineP;
    components RplBorderRouterP;
    EthernetP.LocalIeeeEui64 -> LocalIeeeEui64P;
    RplBorderRouterP.IPPacket -> IPPacketC;
    RplBorderRouterP.ForwardingEvents -> IPStackC.ForwardingEvents[ROUTE_IFACE_ETH0];
    IPForwardingEngineP.IPForward[ROUTE_IFACE_ETH0] -> EthernetP.IPForward;

    components new SocketC();
    components EthernetShieldConfigC;
    EthernetP.IPControl -> IPStackC;
    EthernetP.RootControl -> SERPRoutingC;
    EthernetP.ForwardingTable -> IPStackC;
    EthernetP.RawSocket -> SocketC;
    EthernetP.FlashAttr -> FlashAttrC;
    EthernetP.EthernetShieldConfig -> EthernetShieldConfigC;

#endif

    //I2C sensor rail
    components HplSam4lIOC;
    KernelMainP.ENSEN -> HplSam4lIOC.PC19;

    components HplSam4lClockC;

    KernelMainP.ADCIFEClockCtl -> HplSam4lClockC.ADCIFECtl;
    //Drivers
    components StormSimpleGPIOC;
    KernelMainP.GPIO_Driver -> StormSimpleGPIOC.Driver;
    components TimerDriverC;
    KernelMainP.Timer_Driver -> TimerDriverC.Driver;
    components UDPDriverC;
    KernelMainP.UDP_Driver -> UDPDriverC;
    components StormSysInfoC;
    KernelMainP.SysInfo_Driver -> StormSysInfoC;
    components StormRoutingTableC;
    KernelMainP.RoutingTable_Driver -> StormRoutingTableC;
    components BLEDriverC;
    KernelMainP.BLE_Driver -> BLEDriverC;
    components I2CDriverC;
    KernelMainP.I2C_Driver -> I2CDriverC;
    components SPIDriverC;
    KernelMainP.SPI_Driver -> SPIDriverC;
    components AESDriverC;
    KernelMainP.AES_Driver -> AESDriverC;
    components FlashDriverC;
    FlashDriverC.FlashAttr -> FlashAttrC;
    KernelMainP.Flash_Driver -> FlashDriverC;
    components ScrufflesDriverC;
    KernelMainP.Scruffles_Driver -> ScrufflesDriverC;
    components TCPDriverC;
    KernelMainP.TCP_Driver -> TCPDriverC;
}
