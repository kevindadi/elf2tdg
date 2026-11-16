/*
 * Minimal Cortex-M0 real-time example for elf2tdg.
 *
 * The image has a reset handler, a main loop, a sensor task and USART1
 * interrupt 37 (vector 53). It is freestanding so the resulting ELF contains
 * only the code we want to inspect.
 */

typedef unsigned int u32;

volatile u32 ticks;

void Reset_Handler(void);
void Default_Handler(void);
void USART1_IRQHandler(void);
void SystemInit(void);
void sensor_task(void);

__attribute__((noinline)) void SystemInit(void) {
    ticks = 0;
}

__attribute__((noinline)) static void delay(volatile u32 count) {
    while (count--) {
        ticks++;
    }
}

__attribute__((noinline)) void sensor_task(void) {
    delay(3);
    ticks ^= 1u;
}

void USART1_IRQHandler(void) {
    ticks++;
}

int main(void) {
    sensor_task();
    for (;;) {
        delay(100);
    }
}

void Reset_Handler(void) {
    SystemInit();
    main();
    for (;;) {
    }
}

void Default_Handler(void) {
    for (;;) {
    }
}

__attribute__((section(".isr_vector"), used))
void (*const vector_table[54])(void) = {
    [0] = (void (*)(void))0x20001000u,
    [1] = Reset_Handler,
    [2 ... 15] = Default_Handler,
    [16] = Default_Handler,
    [17 ... 52] = Default_Handler,
    [53] = USART1_IRQHandler,
};
