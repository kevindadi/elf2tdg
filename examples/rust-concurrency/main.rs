//! Small Rust concurrency example for `elf2tdg`.
//!
//! It contains one ordinary worker thread and one structured-concurrency
//! scope. Build it with `make` and inspect the generated TDG artifacts.

use std::sync::Mutex;
use std::thread;

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

fn main() {
    let worker = thread::spawn(|| process(sensor_sample(0x1234_5678)));
    let joined = worker.join().expect("worker panicked");

    let scoped = thread::scope(|scope| {
        let handle = scope.spawn(|| process(sensor_sample(0xfeed_face)));
        handle.join().expect("scoped worker panicked")
    });

    let observed = Mutex::new(0u64);
    {
        let mut guard = observed.lock().expect("counter lock");
        *guard += u64::from(joined) + u64::from(scoped);
        std::hint::black_box(*guard);
    }

    println!("joined={joined:#010x} scoped={scoped:#010x}");
}
