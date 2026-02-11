MEMORY
{
    FLASH    : ORIGIN = 0x08000000, LENGTH = 512K  /* BANK_1 */
    /* Note that the flash is actually 2 banks 1 MB each, but */
    /* we'll be using the upper half of bank 1. */
    RAM      : ORIGIN = 0x24000000, LENGTH = 512K  /* AXIRAM */
    RAM_D3   : ORIGIN = 0x38000000, LENGTH = 64K   /* SRAM4 */
}

SECTIONS
{
    .ram_d3 :
    {
        *(.ram_d3.shared_data)
        *(.ram_d3)
    } > RAM_D3
}