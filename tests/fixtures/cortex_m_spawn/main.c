typedef unsigned int u32;
typedef void (*task_fn)(void *);

volatile u32 ticks;

void xTaskCreate(task_fn entry, const char *name, u32 stack_depth, void *argument,
                 u32 priority);
void Default_Handler(void);

__attribute__((noinline)) void my_task(void *argument) {
    (void)argument;
    ticks++;
    for (;;) {
    }
}

int main(void) {
    xTaskCreate(my_task, "task", 128, (void *)0, 3);
    for (;;) {
    }
}

void xTaskCreate(task_fn entry, const char *name, u32 stack_depth, void *argument,
                 u32 priority) {
    (void)entry;
    (void)name;
    (void)stack_depth;
    (void)argument;
    (void)priority;
    for (;;) {
    }
}

void Default_Handler(void) {
    for (;;) {
    }
}

__attribute__((section(".isr_vector"), used))
void (*const vector_table[16])(void) = {
    [0] = (void (*)(void))0x20001000u,
    [1] = main,
    [2 ... 15] = Default_Handler,
};
