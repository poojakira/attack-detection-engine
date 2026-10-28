/* Cortex-M3 synthetic lab memory map.
 *
 * RAM is declared (rw), NOT (rwx): this fixture executes only from FLASH, so
 * data RAM never needs execute permission. Declaring RAM non-executable keeps
 * the linker intent aligned with a W^X (write-xor-execute) memory policy and
 * with detection_engine/arm_binary_analyzer.py, which flags writable+executable
 * PT_LOAD segments (ARM-ELF-WX, CWE-732). This is a linker-intent/clarity fix;
 * the previously emitted RAM PT_LOAD segment was already RW (not RWE) because
 * no executable section was placed in RAM.
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 64K
  RAM   (rw)  : ORIGIN = 0x20000000, LENGTH = 8K
}
ENTRY(Reset_Handler)
SECTIONS
{
  .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
  .text : { *(.text*) *(.rodata*) } > FLASH
  .data : { *(.data*) } > RAM AT> FLASH
  .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
}
