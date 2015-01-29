#include "driver.h"
#include <stdint.h>
module StormSimpleGPIOP
{
    provides interface Driver;
    uses
    {
        interface HplSam4lGeneralIOPort as PortA;
        interface HplSam4lGeneralIOPort as PortB;
        interface HplSam4lGeneralIOPort as PortC;
        interface ByteIRQ as PortA_IRQ [uint8_t id];
        interface ByteIRQ as PortB_IRQ [uint8_t id];
        interface ByteIRQ as PortC_IRQ [uint8_t id];
    }
}
implementation
{
    uint8_t scanport;
    uint8_t scanpin;
    #ifdef WITH_WIZ
        const uint32_t irq_allowed [] = {0x93DA0, 0xEE3F, 0xFF67D275};
    #else
        const uint32_t irq_allowed [] = {0x93DA0, 0xFE3F, 0xFF67D275};
    #endif
    uint32_t norace irq_enabled [] = {0,0,0};
    simple_callback_t norace irq_callback [3][32];
    volatile norace uint32_t irq_fired [] = {0,0,0};
    volatile norace uint32_t irq_repeat [] = {0,0,0};
    command driver_callback_t Driver.peek_callback()
    {
        scanport = 0;
        scanpin = 0;
        do
        {
            uint32_t pinmask = 1<<scanpin;

            if ((irq_fired[scanport] & pinmask) && (irq_enabled[scanport] & pinmask))
            {
                if (!(irq_repeat[scanport] & (1<<scanpin)))
                {
                    irq_enabled[scanport] &= ~(1<<scanpin);
                    switch (scanport)
                    {
                        case 0: call PortA.disableIRQ(scanpin); break;
                        case 1: call PortB.disableIRQ(scanpin); break;
                        case 2: call PortC.disableIRQ(scanpin); break;
                    }
                }
                return &irq_callback[scanport][scanpin];
            }
            else
            {
                scanpin++;
                if (scanpin >= 32 || irq_fired[scanport] == 0)
                {
                    scanport++;
                    scanpin = 0;
                }
                if (scanport >= 3)
                {
                    return NULL;
                }
            }
        } while(1);
        return NULL;
    }
    command void Driver.pop_callback()
    {
        irq_fired[scanport] &= ~(1<<scanpin);
    }

    async event void PortA_IRQ.fired[uint8_t id]()
    {
        uint32_t irqs = *((volatile uint32_t*)(0x400E1000 + 0x0D0)) & irq_allowed[0] & irq_enabled[0];
        irq_fired[0] |= irqs;
        *((volatile uint32_t*)(0x400E1000 + 0x0D8)) = irqs;
    }

    async event void PortB_IRQ.fired[uint8_t id]()
    {
        uint32_t irqs = *((volatile uint32_t*)(0x400E1200 + 0x0D0)) & irq_allowed[1] & irq_enabled[1];
        irq_fired[1] |= irqs;
        *((volatile uint32_t*)(0x400E1200 + 0x0D8)) = irqs;
    }

    async event void PortC_IRQ.fired[uint8_t id]()
    {
        uint32_t irqs = *((volatile uint32_t*)(0x400E1400 + 0x0D0)) & irq_allowed[2] & irq_enabled[2];
        irq_fired[2] |= irqs;
        *((volatile uint32_t*)(0x400E1400 + 0x0D8)) = irqs;
    }

    async command syscall_rv_t Driver.syscall_ex(
        uint32_t number, uint32_t arg0, 
        uint32_t arg1, uint32_t arg2, 
        uint32_t *argx)
    {
        switch(number & 0xFF)
        {
            case 0x01: //set_mode(dir, pinspec)
            {
                uint32_t base_addr = 0x400E1000;
                uint8_t port = arg1 >> 8;
                uint32_t pinmask = 1 << (arg1 & 0xFF);
                if (port > 3)
                    return (uint32_t) - 1;

                if (arg0 == 0) //set 0utput
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x004)) = pinmask; //enable GPIO
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x044)) = pinmask; //enable driver
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x168)) = pinmask; //disable ST
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x078)) = pinmask; //PUERC
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x088)) = pinmask; //PDERC
                    return 0;
                } else if (arg0 == 1) //set 1nput
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x004)) = pinmask; //enable GPIO
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x048)) = pinmask; //disable driver
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x164)) = pinmask; //enable ST
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x078)) = pinmask; //PUERC
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x088)) = pinmask; //PDERC
                    return 0;
                } else if (arg0 == 2) //set peripheral
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x008)) = pinmask; //disable GPIO
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x048)) = pinmask; //disable driver
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x168)) = pinmask; //disable ST
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x078)) = pinmask; //PUERC
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x088)) = pinmask; //PDERC
                    return 0;
                }
                return (uint32_t) -1;
            }
            case 0x02: //set(value, pinspec)
            {
                uint32_t base_addr = 0x400E1000;
                uint8_t port = arg1 >> 8;
                uint32_t pinmask = 1 << (arg1 & 0xFF);
                if (port > 3)
                    return (uint32_t) - 1;

                if (arg0 == 0)
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x058)) = pinmask; //OVRC
                    return 0;
                }
                else if (arg0 == 1)
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x054)) = pinmask; //OVRS
                    return 0;
                }
                else if (arg0 == 2)
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x05c)) = pinmask; //OVRT
                    return 0;
                }
                return (uint32_t) -1;
            }
            case 0x03: //get(pinspec)
            {
                uint32_t base_addr = 0x400E1000;
                uint8_t port = arg0 >> 8;
                if (port > 3)
                    return (uint32_t) - 1;
                return (*((volatile uint32_t*)(base_addr + (0x200*port) + 0x060)) >> (arg0 & 0xFF)) & 1;
            }
            case 0x04: //set_pull(dir, pinspec) 0=off, 1=up, 2=down, 3=keeper
            {
                uint32_t base_addr = 0x400E1000;
                uint8_t port = arg1 >> 8;
                uint32_t pinmask = 1 << (arg1 & 0xFF);
                if (port > 3)
                    return (uint32_t) -1;

                if (arg0 == 0)
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x078)) = pinmask; //PUERC
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x088)) = pinmask; //PDERC
                    return 0;
                }
                else if (arg0 == 1)
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x074)) = pinmask; //PUERS
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x088)) = pinmask; //PDERC
                    return 0;
                }
                else if (arg0 == 2)
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x078)) = pinmask; //PUERC
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x084)) = pinmask; //PDERS
                    return 0;
                }
                else if (arg0 == 3)
                {
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x074)) = pinmask; //PUERS
                    *((volatile uint32_t*)(base_addr + (0x200*port) + 0x084)) = pinmask; //PDERS
                    return 0;
                }
                else
                {
                    return (uint32_t) -1;
                }
            }
            case 0x05: //getd(pinspect) //get drive shadow
            {
                uint32_t base_addr = 0x400E1000;
                uint8_t port = arg0 >> 8;
                if (port > 3)
                    return (uint32_t) -1;
                return (*((uint32_t*)(base_addr + (0x200*port) + 0x050)) >> (arg0 & 0xFF)) & 1;
            }
                       //            arg0    arg1  arg2  argx[0]
            case 0x06: //enable_irq(pinspec, flag, cb, void *r)
            {
                //flag = [repeat][any=0,rising=1,falling=2 x2] (3bits)
                uint8_t port = arg0 >> 8;
                uint8_t pin = arg0 & 0xFF;
                uint32_t pinmask = 1 << (arg0 & 0xFF);
                if (irq_allowed[port] & pinmask == 0)
                    return (uint32_t) -1;
                irq_callback[port][pin].addr = arg2;
                irq_callback[port][pin].r = (void*) argx[0];
                if (arg1 & 0b100) { //repeat
                    irq_repeat[port] |= pinmask;
                } else {
                    irq_repeat[port] &= ~pinmask;
                }
                switch (arg1&3) //IMR0
                {
                    case 0: //any edge
                        *((volatile uint32_t*)(0x400E1000 + (0x200*port) + 0x0A8)) = pinmask; //IMR0C
                        *((volatile uint32_t*)(0x400E1000 + (0x200*port) + 0x0B8)) = pinmask; //IMR1C
                        break;
                    case 1: //rising
                        *((volatile uint32_t*)(0x400E1000 + (0x200*port) + 0x0A4)) = pinmask; //IMR0S
                        *((volatile uint32_t*)(0x400E1000 + (0x200*port) + 0x0B8)) = pinmask; //IMR1C
                        break;
                    case 2: //falling
                        *((volatile uint32_t*)(0x400E1000 + (0x200*port) + 0x0A8)) = pinmask; //IMR0C
                        *((volatile uint32_t*)(0x400E1000 + (0x200*port) + 0x0B4)) = pinmask; //IMR1S
                        break;
                }
                irq_enabled[port] |= pinmask;
                switch (port)
                {
                    case 0: call PortA.enableIRQ(pin); break;
                    case 1: call PortB.enableIRQ(pin); break;
                    case 2: call PortC.enableIRQ(pin); break;
                }
                return 0;
            }
            case 0x07: //disable_irq(pinspec)
            {
                uint8_t port = arg0 >> 8;
                uint8_t pin = arg0 & 0xFF;
                uint32_t pinmask = 1 << (arg0 & 0xFF);
                if (irq_allowed[port] & pinmask == 0)
                    return (uint32_t) -1;
                irq_callback[port][pin].r = NULL;
                irq_callback[port][pin].addr = 0;
                irq_enabled[port] &= ~pinmask;
                switch (port)
                {
                    case 0: call PortA.disableIRQ(pin); break;
                    case 1: call PortB.disableIRQ(pin); break;
                    case 2: call PortC.disableIRQ(pin); break;
                }
                return 0;
            }
            default:
                return (uint32_t) -1;
        }
    }
}

