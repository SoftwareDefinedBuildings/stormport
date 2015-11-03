
module HalSam4lASTP
{
    provides
    {
        interface Init;
        interface Alarm<T32khz,uint32_t> as Alarm;
        interface LocalTime<T32khz> as LocalTime;
        interface Counter<T32khz,uint32_t> as Counter;
    }
    uses
    {
        interface Init as ASTInit;
        interface HplSam4lAST as ast;
        interface HplSam4lBPM as bpm;
        interface HplSam4PeripheralClockCntl as ASTClockCtl;
        interface HplSam4lBSCIF as bscif;
    }
}
implementation
{

    command error_t Init.init()
    {
        call bscif.enableRC32K();
        call bpm.select32kInternal();
        call ASTClockCtl.enable();
        call ast.selectClk_32khz();
        //This unfortunately results in a 16khz clock.
        call ast.setPrescalarBit(0);
        call ast.disableAlarmIRQ();
        call ast.disableOverflowIRQ();
        call ast.enableAlarmWake();
        call ast.disablePeriodIRQ();
        call ast.clearAlarm();
        call ast.enable();
    }

    async event void ast.alarmFired()
    {
        signal Alarm.fired();
    }

    default async event void Alarm.fired(){}

    async event void ast.overflowFired()
    {
        signal Counter.overflow();
    }

    default async event void Counter.overflow(){}

    //Counter
    async command uint32_t Counter.get()
    {
        return call ast.getCounterValue() << 1;
    }
    async command bool Counter.isOverflowPending()
    {
        return call ast.overflowed();
    }
    async command void Counter.clearOverflow()
    {
        call ast.clearOverflowed();
    }

    //LocalTime
    async command uint32_t LocalTime.get()
    {
        return call ast.getCounterValue() << 1;
    }

    //Alarm
    async command void Alarm.start(uint32_t v)
    {
        call Alarm.startAt(call Alarm.getNow(), v);
    }
    async command void Alarm.stop()
    {
        call ast.disableAlarmIRQ();
    }
    async command bool Alarm.isRunning()
    {
        return call ast.isEnabled();
    }
    async command void Alarm.startAt(uint32_t t0, uint32_t dt)
    {
        /* IMPLEMENTATION DETAILS
         * The AST is a 16kHz clock that wraps at 32 bits. We want to provide the abstraction of a
         * 32 kHz clock that wraps at 32 bits, or equivalently a 16 kHz clock that wraps at 31 bits.
         * We can model the AST as two clocks:
         * 1) A short clock that operates at 16 kHz and wraps at 31 bits
         * 2) A long clock that operates at 16 kHz and wraps at 32 bits
         * The code below calculates the counter value on the AST on the long clock, and calls the
         * value cv. It converts t0 to a value on the short clock. Then it computes t1 = t0 + dt on
         * the long clock.
         */

        uint32_t cv, t1;
        atomic {
            call ast.disable();
            call ast.disableAlarmIRQ();
            call ast.clearAlarm();
            
            cv = (call ast.getCounterValue()) & (uint32_t) 0x7FFFFFFF;
            t1 = (t0 >> 1) + (dt >> 1) + (t0 & dt & 1);
            t0 >>= 1;
             
            if (t0 > cv) {
                cv |= (uint32_t) 0x80000000;
            }
            
            if (t1 <= cv) {
                // Fire the alarm right away
                call ast.enable();
                signal Alarm.fired();
            } else {
                // Wait for t1 - cv ticks
                call ast.setCounterValue(cv);
                call ast.setAlarm(t1);
                call ast.enableAlarmIRQ();
                call ast.enable();
            }
        }
    }
    async command uint32_t Alarm.getNow()
    {
        return call ast.getCounterValue() << 1;
    }

    async command uint32_t Alarm.getAlarm()
    {
        return call ast.getAlarm() << 1;
    }
}
