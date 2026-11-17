//! No-std allocator and trait-object points-to fixture.
//!
//! A `Box<dyn Sensor>` is stored in a heap-allocated holder. The allocator is
//! retained as a direct call target, while the trait method is reached through
//! a vtable loaded from the holder field.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

struct Bump {
    heap: UnsafeCell<[u8; 4096]>,
    next: AtomicUsize,
}

// The fixture is single-threaded at this scale; allocation is serialized by the
// atomic cursor.
unsafe impl Sync for Bump {}

unsafe impl GlobalAlloc for Bump {
    #[inline(never)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let start = self.next.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { self.heap.get().cast::<u8>().add(start) }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: Bump = Bump {
    heap: UnsafeCell::new([0; 4096]),
    next: AtomicUsize::new(0),
};

trait Sensor {
    fn read(&self) -> u32;
}

struct A;
impl Sensor for A {
    #[inline(never)]
    fn read(&self) -> u32 {
        42
    }
}

struct B;
impl Sensor for B {
    #[inline(never)]
    fn read(&self) -> u32 {
        7
    }
}

#[inline(never)]
fn choose(flag: u32) -> Box<dyn Sensor> {
    if flag == 0 {
        Box::new(A)
    } else {
        Box::new(B)
    }
}

struct Holder {
    sensor: Box<dyn Sensor>,
}

#[inline(never)]
fn call_sensor(sensor: &dyn Sensor) -> u32 {
    sensor.read()
}

#[inline(never)]
fn run(flag: u32) -> u32 {
    let holder = Box::new(Holder {
        sensor: choose(flag),
    });
    let value = call_sensor(&*holder.sensor);
    core::hint::black_box(&holder);
    value
}

#[cortex_m_rt::entry]
fn main() -> ! {
    let flag = core::hint::black_box(1u32);
    core::hint::black_box(run(flag));
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
