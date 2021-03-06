/*
 * Copyright (c) 2009 Communication Group and Eislab at
 * Lulea University of Technology
 *
 * Contact: Laurynas Riliskis, LTU
 * Mail: laurynas.riliskis@ltu.se
 * All rights reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of Communication Group at Lulea University of Technology
 *   nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL STANFORD
 * UNIVERSITY OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * MMA7261QT implementation.
 *
 * @author Henrik Makitaavola
 */

module HplMMA7261QTP
{
  provides
  {
    interface Init;
    interface M16c60AdcConfig as AccelXConf;
    interface M16c60AdcConfig as AccelYConf;
    interface M16c60AdcConfig as AccelZConf;
  }
  
  uses
  {
    interface GeneralIO as VCC;
    interface GeneralIO as Sleep;
    interface GeneralIO as GSelect1;
    interface GeneralIO as GSelect2;
    interface GeneralIO as AccelXPort;
    interface GeneralIO as AccelYPort;
    interface GeneralIO as AccelZPort;
  }
}
implementation
{
  command error_t Init.init()
  {
    call VCC.makeOutput();
    call VCC.set();
    call Sleep.makeOutput();
    call Sleep.clr();
    call GSelect1.makeOutput();
    call GSelect1.clr();
    call GSelect2.makeOutput();
    call GSelect2.clr();
    call AccelXPort.makeInput();
    call AccelXPort.clr();
    call AccelYPort.makeInput();
    call AccelYPort.clr();
    call AccelZPort.makeInput();
    call AccelZPort.clr();
  }
  
  inline uint8_t prescaler() { return M16c60_ADC_PRESCALE_4; }
  inline uint8_t precision() { return M16c60_ADC_PRECISION_8BIT; }
  
  async command uint8_t AccelXConf.getChannel()
  {
    return M16c60_ADC_CHL_AN5;
  }

  async command uint8_t AccelXConf.getPrecision()
  {
    return precision();
  }

  async command uint8_t AccelXConf.getPrescaler()
  {
    return prescaler();
  }
  
    async command uint8_t AccelYConf.getChannel()
  {
    return M16c60_ADC_CHL_AN4;
  }

  async command uint8_t AccelYConf.getPrecision()
  {
    return precision();
  }

  async command uint8_t AccelYConf.getPrescaler()
  {
    return prescaler();
  }
  
  async command uint8_t AccelZConf.getChannel()
  {
    return M16c60_ADC_CHL_AN3;
  }

  async command uint8_t AccelZConf.getPrecision()
  {
    return precision();
  }

  async command uint8_t AccelZConf.getPrescaler()
  {
    return prescaler();
  }
}
