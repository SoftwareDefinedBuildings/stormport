module EthernetShieldConfigC
{
    uses interface SocketSpi;
    uses interface Timer<T32khz> as Timer;
    provides interface EthernetShieldConfig;
}
implementation
{
    typedef enum
    {
        // initialization states
        state_reset,
        state_write_ipaddress,
        state_write_gatewayip,
        state_write_subnetmask,
        state_write_mac,
        state_initialize_sockets_tx,
        state_initialize_sockets_rx,
        state_initialize_txwr_txrd,
        state_finished_init
    } SocketInitState;

    SocketInitState state = state_reset;

    // our own tx buffer
    uint8_t _txbuf [260];
    uint8_t * const txbuf = &_txbuf[4];
    uint8_t _rxbuf [260];
    uint8_t * const rxbuf = &_rxbuf[4];

    // loop index
    int i = 0;

    command void initialize(uint32_t src_ip, uint32_t netmask, uint32_t gateway, uint8_t *mac)
    {
        switch(state)
        {
        case state_reset:
            state = state_write_ipaddress;
            txbuf[0] = 0x80;
            call SocketSpi.writeRegister(0x0000, _txbuf, 1);
            break;

        // Write which address we are
        case state_write_ipaddress:
            state = state_write_gatewayip;
            txbuf[0] = src_ip >> (3 * 8);
            txbuf[1] = src_ip >> (2 * 8);
            txbuf[2] = src_ip >> (1 * 8);
            txbuf[3] = src_ip >> (0 * 8);
            call SocketSpi.writeRegister(0x000F, _txbuf, 4);
            break;

        // Write the gateway ip
        case state_write_gatewayip:
            state = state_write_subnetmask;
            txbuf[0] = gateway >> (3 * 8);
            txbuf[1] = gateway >> (2 * 8);
            txbuf[2] = gateway >> (1 * 8);
            txbuf[3] = gateway >> (0 * 8);
            call SocketSpi.writeRegister(0x0001, _txbuf, 4);
            break;

        // Write the subnet mask
        case state_write_subnetmask:
            state = state_write_mac;
            txbuf[0] = netmask >> (3 * 8);
            txbuf[1] = netmask >> (2 * 8);
            txbuf[2] = netmask >> (1 * 8);
            txbuf[3] = netmask >> (0 * 8);
            call SocketSpi.writeRegister(0x0005, _txbuf, 4);
            break;

        case state_write_mac:
            state = state_initialize_sockets_tx;
            for (i=0; i < 6; i++)
            {
                txbuf[i] = *mac[i];
            }
            call SocketSpi.writeRegister(0x0009, _txbuf, 6);
            break;

        // Initialize the socket with its tx buffersize, as determined by the Wiz5200 chip
        case state_initialize_sockets_tx:
            state = state_initialize_sockets_rx;
            txbuf[0] = 0x02;
            call SocketSpi.writeRegister(0x4000 + socket * 0x100 + 0x001F, _txbuf, 1);
            break;

        // Initialize the sockets with their rx buffersize, as determined by the Wiz5200 chip
        case state_initialize_sockets_rx:
            state = state_initialize_txwr_txrd;
            txbuf[0] = 0x02;
            call SocketSpi.writeRegister(0x4000 + socket * 0x100 + 0x001E, _txbuf, 1);
            break;

        // Clears the TX read and write pointers for the buffer
        case state_initialize_txwr_txrd:
            txbuf[0] = 0x0;
            txbuf[1] = 0x0;
            txbuf[2] = 0x0;
            txbuf[3] = 0x0;
            call SocketSpi.writeRegister(0x4000 + socket * 0x100 + 0x0022, _txbuf, 4);
            // now finished
            state = state_initialize_finished;
            break;

        // termination case
        case state_initialize_finished:
            break;
        }
    }
}