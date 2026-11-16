//! Small no-std Embassy concurrency example for `elf2tdg`.
//!
//! It starts two async tasks from the executor's main task. Build it with
//! `make`; the analyzed ELF targets a Cortex-M4-compatible `thumbv7em` core.

#![no_std]
#![no_main]

use embassy_executor::{Executor, Spawner};
use static_cell::StaticCell;

#[inline(never)]
fn sensor_sample(seed: u32) -> u32 {
    let mut state = seed;
    for _ in 0..16 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    }
    state
}

#[inline(never)]
fn process(sample: u32) -> u32 {
    sample.rotate_left(7) ^ 0x5a5a_5a5a
}

#[embassy_executor::task]
async fn sensor_task(seed: u32) {
    let value = process(sensor_sample(seed));
    core::hint::black_box(value);
}

#[embassy_executor::task]
async fn monitor_task(seed: u32) {
    let value = process(seed.rotate_left(3));
    core::hint::black_box(value);
}

/// Spawn sites stay in one stable, non-inlined function so the CFG example
/// always has a concrete user function to display.
#[inline(never)]
fn start_tasks(spawner: Spawner) {
    if let Ok(task) = sensor_task(0x1234_5678) {
        spawner.spawn(task);
    }
    if let Ok(task) = monitor_task(0xfeed_face) {
        spawner.spawn(task);
    }
}

#[embassy_executor::task]
async fn app_main(spawner: Spawner) {
    start_tasks(spawner);
}

#[cortex_m_rt::entry]
fn main() -> ! {
    static EXECUTOR: StaticCell<Executor> = StaticCell::new();
    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        if let Ok(task) = app_main(spawner) {
            spawner.spawn(task);
        }
    });
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
