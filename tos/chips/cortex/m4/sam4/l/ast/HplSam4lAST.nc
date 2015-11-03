#include <asthardware.h>

interface HplSam4lAST
{
	async command void enable();

	async command void disable();

    async command bool isEnabled();

	async command void setPrescalarBit(uint8_t bit);

	async command uint32_t getCounterValue();

	async command void setCounterValue(uint32_t val);

	async command bool overflowed();

	async event void overflowFired();

	async command void clearOverflowed();

	async command bool alarm();

	async event void alarmFired();

	async command void clearAlarm();

	async command bool busy();

	async command bool clkrdy();

	async command void clearClkrdy();

	async command bool clkbusy();

	async command void enableOverflowIRQ();

	async command void disableOverflowIRQ();

	async command void enableAlarmIRQ();

	async command void disableAlarmIRQ();

	async command void enablePeriodIRQ();

	async command void disablePeriodIRQ();

	async command void enableOverflowWake();

	async command void disableOverflowWake();

	async command void enableAlarmWake();

	async command void disableAlarmWake();

	async command void enablePeriodWake();

	async command void disablePeriodWake();

	async command void setAlarm(uint32_t val);

	async command uint32_t getAlarm();

	async command void setPeriod(uint8_t val);

	async command uint8_t getPeriod();

	async command void selectClk_RCSYS();

	async command void selectClk_32khz();

	async command void selectClk_APB();

	async command void selectClk_GCLK2();

	async command void selectClk_1K();

}
