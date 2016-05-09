interface FlashAttr
{
    async command error_t getAttr(uint8_t idx, uint8_t *key_buf, uint8_t *val_buf, uint8_t *val_len);
    async command error_t setAttr(uint8_t idx, uint8_t *key_buf, uint8_t *val_buf, uint8_t val_len);
}
