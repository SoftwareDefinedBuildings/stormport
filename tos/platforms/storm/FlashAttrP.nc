module FlashAttrP
{
    provides
    {
        interface FlashAttr;
    }
    uses
    {
        interface FastSpiByte;
        interface HplSam4lSPIChannel;
        interface Resource;
        interface GeneralIO as CS;
    }
}
implementation
{

void sleep()
  {
    volatile uint32_t i;
    for (i=0;i<1000;i++);
  }

    event void Resource.granted(){}
    async command error_t FlashAttr.getAttr(uint8_t idx, uint8_t *key_buf, uint8_t *val_buf, uint8_t *val_len)
    {
        uint32_t addr, i, len;

        if (call Resource.immediateRequest() != SUCCESS)
            return EBUSY;
        call HplSam4lSPIChannel.setMode(0,0);
        call CS.makeOutput();

        call CS.clr();
        sleep();
        call FastSpiByte.write(0xD7);
        i = call FastSpiByte.write(0x00);
        sleep();
        call CS.set();

        if ((i & 0x80) != 0x80)
        {
          //Device is busy with write
          call Resource.release();
          return EBUSY;
        }

        /*
        printf("idx is %d\n", idx);
        //In case we were in (deep) power down
        call CS.clr();
        call FastSpiByte.write(0xAB);
        call CS.set();
        */
        call CS.set();
        sleep();
        call CS.clr();
        sleep();
        call FastSpiByte.write(0x1B);
        addr = idx*64;
        call FastSpiByte.write((uint8_t)(addr >> 16));
        call FastSpiByte.write((uint8_t)(addr >> 8));
        call FastSpiByte.write((uint8_t)(addr));
        call FastSpiByte.write(0x00);
        call FastSpiByte.write(0x00);
        for (i = 0; i < 8; i++)
        {
            key_buf[i] = call FastSpiByte.write(0x00);
            //printf("key %d 0x%02x\n",i,key_buf[i]);
        }
        len = call FastSpiByte.write(0x00);
        if (len > 64)
        {
            call CS.set();
            call Resource.release();
            return FAIL;
        }
        for (i = 0; i<len; i++)
        {
            val_buf[i] = call FastSpiByte.write(0x00);
            //printf("val %d 0x%02x\n",i,val_buf[i]);
        }
        sleep();
        call CS.set();
        *val_len = len;
        call Resource.release();
        return SUCCESS;
    }
    async command error_t FlashAttr.setAttr(uint8_t idx, uint8_t *key_buf, uint8_t *val_buf, uint8_t val_len)
    {
        uint32_t addr, i;

        if (call Resource.immediateRequest() != SUCCESS)
            return EBUSY;
        call HplSam4lSPIChannel.setMode(0,0);
        call CS.makeOutput();

        call CS.clr();
        sleep();
        call FastSpiByte.write(0xD7);
        i = call FastSpiByte.write(0x00);
        sleep();
        call CS.set();

        if ((i & 0x80) != 0x80)
        {
          //Device is busy with write
          call Resource.release();
          return EBUSY;
        }

        /*
        printf("idx is %d\n", idx);
        //In case we were in (deep) power down
        call CS.clr();
        call FastSpiByte.write(0xAB);
        call CS.set();
        */
        sleep();
        call CS.clr();
        sleep();
        call FastSpiByte.write(0x58);
        addr = idx*64;
        call FastSpiByte.write((uint8_t)(addr >> 16));
        call FastSpiByte.write((uint8_t)(addr >> 8));
        call FastSpiByte.write((uint8_t)(addr));
        for (i = 0; i < 8; i++)
        {
            call FastSpiByte.write(key_buf[i]);
            //printf("key %d 0x%02x\n",i,key_buf[i]);
        }
        sleep();
        call FastSpiByte.write((uint8_t)(val_len)); // write length
        for (i = 0; i<val_len; i++)
        {
            call FastSpiByte.write(val_buf[i]);
            //printf("val %d 0x%02x\n",i,val_buf[i]);
        }
        sleep();
        call CS.set();
        call Resource.release();
        return SUCCESS;
    }
}
