/*
 * Copyright (c) 2016, University of California, Berkeley
 * All rights reserved.
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
 * - Neither the name of the copyright holder nor the names of
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
 * Author: Sam Kumar <samkumar@berkeley.edu>
 */

#include <Tasklet.h>
#include <RadioAssert.h>

generic module SoftwareCsmaLayerP()
{
	provides
	{
		interface RadioSend;
	}
	uses
	{
		interface RadioSend as SubSend;
        interface RadioAlarm;
	}
}

implementation
{
	message_t *txMsg;
    uint8_t numtries = 0; // number of COMPLETED tries

	enum
	{
		STATE_READY = 0,
		STATE_BACKOFF = 1,
		STATE_SENDING = 2,
        STATE_RADIO_BUSY = 3,
	};
    enum
    {
        MIN_BE = 3,
        MAX_BE = 5,
        MAX_TRIES = 5,
        BACKOFF_PERIOD = 10, // ticks in one backoff period (~320 microseconds)
    };

    uint8_t state = STATE_READY;

    uint16_t seed = 56523; // receiver
    //uint16_t seed = 45623; // sender

    uint16_t random() {
        atomic seed = 49433 * seed + 12345;
        return seed;
    }

    uint16_t randomBackoff(uint8_t backoff_exp) {
        uint16_t MASK = (1 << backoff_exp) - 1;
        return random() & MASK;
    }

    void backoff_and_send()
    {
        uint8_t be;
        atomic
        {
            state = STATE_BACKOFF;
            be = MIN_BE + numtries;
            if (be > MAX_BE)
            {
                be = MAX_BE;
            }
            call RadioAlarm.wait(randomBackoff(be) * BACKOFF_PERIOD);
        }
    }

    async command error_t RadioSend.send(message_t* msg)
    {
        atomic
        {
            if (state != STATE_READY)
            {
                return EBUSY;
            }

            txMsg = msg;
            numtries = 0;

            backoff_and_send();
        }

        return SUCCESS;
    }

    void send()
    {
        error_t rv;

        atomic
        {
            state = STATE_SENDING;

            rv = call SubSend.send(txMsg);
            if (rv == EBUSY)
            {
                state = STATE_RADIO_BUSY;

                // Try again in 1 ms
                call RadioAlarm.wait(32);
            }
        }
    }

    async event void RadioAlarm.fired()
    {
        if (state != STATE_READY)
        {
            send();
        }
    }


	async event void SubSend.sendDone(error_t error)
	{
		RADIO_ASSERT(state == STATE_SENDING);

        if (error == SUCCESS)
        {
            atomic state = STATE_READY;
            signal RadioSend.sendDone(error);
        }
        else
        {
            // Message wasn't sent because the CSMA probes failed
            RADIO_ASSERT(error == EBUSY);
            atomic
            {
                numtries++;
                if (numtries == MAX_TRIES)
                {
                    state = STATE_READY;
                    signal RadioSend.sendDone(error);
                }
                else
                {
                    backoff_and_send();
                }
            }
        }
	}

    async event void SubSend.ready()
	{
        atomic
        {
    		if( state == STATE_READY && call RadioAlarm.isFree())
            {
    			signal RadioSend.ready();
            }
            else if (state == STATE_RADIO_BUSY)
            {
                call RadioAlarm.cancel();
                send();
            }
        }
	}
}
