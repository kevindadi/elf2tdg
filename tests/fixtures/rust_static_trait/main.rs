#![no_std]
#![no_main]

use core::hint::black_box;

trait Handler: Sync {
    fn handle(&self) -> u32;
}

struct A;
impl Handler for A {
    #[inline(never)]
    fn handle(&self) -> u32 { 1 }
}

struct B;
impl Handler for B {
    #[inline(never)]
    fn handle(&self) -> u32 { 2 }
}

static HANDLERS: [&'static dyn Handler; 2] = [&A, &B];

#[inline(never)]
fn dispatch(index: usize) -> u32 {
    HANDLERS[index].handle()
}

#[cortex_m_rt::entry]
fn main() -> ! {
    black_box(dispatch(black_box(1)));
    loop { core::hint::spin_loop(); }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
