/* Freestanding lab firmware compiled for a real ARM Cortex-M3 target.
 * No vehicle I/O. All operations are synthetic and locally owned. */
#include <stdint.h>
#define FRAME_MAX 8u

volatile uint32_t lab_result;

int parse_synthetic_frame(const uint8_t *data, uint32_t len) {
    if (data == (const uint8_t *)0 || len > FRAME_MAX) {
        return -1;
    }
    uint32_t sum = 0;
    for (uint32_t i = 0; i < len; ++i) {
        sum += data[i];
    }
    return (int)(sum & 0xffu);
}

void Reset_Handler(void) {
    const uint8_t example[4] = {1, 2, 3, 4};
    lab_result = (uint32_t)parse_synthetic_frame(example, 4u);
    for (;;) {
        __asm__ volatile ("nop");
    }
}

__attribute__((section(".isr_vector"), used))
const uint32_t vectors[2] = {
    0x20001000u,
    (uint32_t)(uintptr_t)&Reset_Handler
};
