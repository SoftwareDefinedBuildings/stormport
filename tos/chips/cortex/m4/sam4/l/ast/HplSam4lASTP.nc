

#include <asthardware.h>
#include <nvichardware.h>
#include <printf.h>
module HplSam4lASTP
{
    provides interface HplSam4lAST;
    uses interface FunctionWrapper as AlarmWrapper;
    uses interface FunctionWrapper as OverflowWrapper;
}
implementation
{


    void AST_ALARM_Handler() @C() @spontaneous()
    {
        call AlarmWrapper.preamble();
        signal HplSam4lAST.alarmFired();
        call AlarmWrapper.postamble();
    }

    void AST_OVF_Handler() @C() @spontaneous()
    {
        call OverflowWrapper.preamble();
        signal HplSam4lAST.overflowFired();
        call OverflowWrapper.postamble();
    }

    async command void HplSam4lAST.enable()
	{
	    while(AST->sr.bits.busy == 1);
		AST->cr.bits.en = 1;
	}

	async command bool HplSam4lAST.isEnabled()
	{
	    return AST->cr.bits.en == 1;
	}

	async command void HplSam4lAST.disable()
	{
	    while(AST->sr.bits.busy == 1);
		AST->cr.bits.en = 0;
		while(AST->sr.bits.busy == 1);
	}

	async command void HplSam4lAST.setPrescalarBit(uint8_t bit)
	{
	    while(AST->sr.bits.busy == 1);
		AST->cr.bits.psel = bit;
	}

	async command uint32_t HplSam4lAST.getCounterValue()
	{
		return AST->cv;
	}

	async command void HplSam4lAST.setCounterValue(uint32_t val)
	{
	    while(AST->sr.bits.busy == 1);
		AST->cv = val;
	}

	async command bool HplSam4lAST.overflowed()
	{
		return AST->sr.bits.ovf == 1;
	}

	async command void HplSam4lAST.clearOverflowed()
	{
	    while(AST->sr.bits.busy == 1);
		AST->scr.bits.ovf = 1;
	}

	async command bool HplSam4lAST.alarm()
	{
		return AST->sr.bits.alarm0 == 1;
	}

	async command void HplSam4lAST.clearAlarm()
	{
	    while(AST->sr.bits.busy == 1);
		AST->scr.bits.alarm0 = 1;
	}

	async command bool HplSam4lAST.busy()
	{
		return AST->sr.bits.busy == 1;
	}

	async command bool HplSam4lAST.clkrdy()
	{
		return AST->sr.bits.clkrdy == 1;
	}

	async command void HplSam4lAST.clearClkrdy()
	{
	    while(AST->sr.bits.busy == 1);
		AST->scr.bits.clkrdy = 1;
	}

	async command bool HplSam4lAST.clkbusy()
	{
		return AST->sr.bits.clkbusy == 1;
	}

	async command void HplSam4lAST.enableOverflowIRQ()
	{
	    //No busy wait required
	    NVIC->ipr.bits.ast_ovf = 0;
	    NVIC->iser.bits.ast_ovf = 1;

		AST->ier.bits.ovf = 1;
	}

	async command void HplSam4lAST.disableOverflowIRQ()
	{
	    //No busy wait required
		AST->idr.bits.ovf = 1;
	}

	async command void HplSam4lAST.enableAlarmIRQ()
	{
	    //No busy wait required

	     NVIC->icpr.bits.ast_alarm = 1;
	    NVIC->ipr.bits.ast_alarm = 0;
	    NVIC->iser.bits.ast_alarm = 1;
	 //   NVIC->iser.flat[1] = 1<<(39&0x1F);

		AST->ier.bits.alarm0 = 1;
	}

	async command void HplSam4lAST.disableAlarmIRQ()
	{
	    //No busy wait required
		AST->idr.bits.alarm0 = 1;
	}

	async command void HplSam4lAST.enablePeriodIRQ()
	{
	    //No busy wait required
	    NVIC->iser.bits.ast_per = 1;
		AST->ier.bits.per0 = 1;
	}

	async command void HplSam4lAST.disablePeriodIRQ()
	{
	    //No busy wait required
		AST->idr.bits.per0 = 1;
	}

	async command void HplSam4lAST.enableOverflowWake()
	{
	    while(AST->sr.bits.busy == 1);
		AST->wer.bits.ovf = 1;
	}

	async command void HplSam4lAST.disableOverflowWake()
	{
	    while(AST->sr.bits.busy == 1);
		AST->wer.bits.ovf = 0;
	}

	async command void HplSam4lAST.enableAlarmWake()
	{
	    while(AST->sr.bits.busy == 1);
		AST->wer.bits.alarm0 = 1;
	}

	async command void HplSam4lAST.disableAlarmWake()
	{
	    while(AST->sr.bits.busy == 1);
		AST->wer.bits.alarm0 = 0;
	}

	async command void HplSam4lAST.enablePeriodWake()
	{
	    while(AST->sr.bits.busy == 1);
		AST->wer.bits.per0 = 1;
	}

	async command void HplSam4lAST.disablePeriodWake()
	{
	    while(AST->sr.bits.busy == 1);
		AST->wer.bits.per0 = 0;
	}

	async command void HplSam4lAST.setAlarm(uint32_t val)
	{
	    while(AST->sr.bits.busy == 1);
	    /*
	     * There is a weird behaviour that as far as I am concerned is a hw bug...
	     * if you read AST->cv with the clock stopped, it can actually change...
	     * this means that by the time setAlarm is called, val might be less
	     * than or equal to cv. This is catastrophic, so we manually bump forward
	     * the alarm time in this situation
	     */
	    if (AST->cv >= val) val = AST->cv+1;
		AST->ar0 = val;
	}

	async command uint32_t HplSam4lAST.getAlarm()
	{
	    while(AST->sr.bits.busy == 1);
		return AST->ar0;
	}

	async command void HplSam4lAST.setPeriod(uint8_t val)
	{
	    while(AST->sr.bits.busy == 1);
		AST->pir0 = val;
	}

	async command uint8_t HplSam4lAST.getPeriod()
	{
		return AST->pir0;
	}

	async command void HplSam4lAST.selectClk_RCSYS()
	{
		//We have to wait for the clock to be changeable
		AST->clock.bits.cen = 0;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cssel = CSSEL_RCSYS;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cen = 1;
		while(AST->sr.bits.clkbusy == 1);
	}

	async command void HplSam4lAST.selectClk_32khz()
	{
		//We have to wait for the clock to be changeable
		AST->clock.bits.cen = 0;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cssel = CSSEL_OSC32;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cen = 1;
		while(AST->sr.bits.clkbusy == 1);
	}

	async command void HplSam4lAST.selectClk_APB()
	{
		//We have to wait for the clock to be changeable
		AST->clock.bits.cen = 0;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cssel = CSSEL_APB;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cen = 1;
		while(AST->sr.bits.clkbusy == 1);
	}

	async command void HplSam4lAST.selectClk_GCLK2()
	{
		//We have to wait for the clock to be changeable
		AST->clock.bits.cen = 0;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cssel = CSSEL_GCLK2;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cen = 1;
		while(AST->sr.bits.clkbusy == 1);
	}

	async command void HplSam4lAST.selectClk_1K()
	{
		//We have to wait for the clock to be changeable
		AST->clock.bits.cen = 0;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cssel = CSSEL_CLK1K;
		while(AST->sr.bits.clkbusy == 1);
		AST->clock.bits.cen = 1;
		while(AST->sr.bits.clkbusy == 1);
	}
}
