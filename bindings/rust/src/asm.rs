use std::arch::{asm, x86_64::{__cpuid, _rdtsc, __rdtscp}};

#[inline]
pub fn cpu_relax() {
    unsafe { asm!("pause") }
}

#[inline]
#[no_mangle]
pub fn cpu_serialize() {
    // originally implemented as a CPUID instruction
    unsafe { __cpuid(0) };
}

#[inline]
pub fn rdtsc() -> u64 {
    unsafe { _rdtsc() }

}
#[inline]
pub fn rdtscp() -> (u64, u32) {
    let mut c: u32 = 0;
    let a: u64 = unsafe { __rdtscp(&mut c as *mut u32) };
    (a, c)
}
