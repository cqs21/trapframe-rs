//! Configure Global Descriptor Table (GDT)

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::asm;
use core::mem::size_of;

use x86_64::instructions::tables::{lgdt, load_tss};
use x86_64::registers::{
    model_specific::Star,
    segmentation::{Segment64, GS},
};
use x86_64::structures::gdt::{Descriptor, SegmentSelector};
use x86_64::structures::DescriptorTablePointer;
use x86_64::{PrivilegeLevel, VirtAddr};

#[cfg(not(feature = "ioport_bitmap"))]
type TSS = x86_64::structures::tss::TaskStateSegment;
#[cfg(feature = "ioport_bitmap")]
type TSS = super::ioport::TSSWithPortBitmap;

/// Init TSS & GDT.
pub unsafe fn init(on_bsp: bool) {
    // allocate stack for trap from user
    // set the stack top to TSS
    // so that when trap from ring3 to ring0, CPU can switch stack correctly
    let tss = if on_bsp {
        init_local_tss_on_bsp()
    } else {
        init_local_tss_on_ap()
    };

    let (tss0, tss1) = match Descriptor::tss_segment(tss) {
        Descriptor::SystemSegment(tss0, tss1) => (tss0, tss1),
        _ => unreachable!(),
    };
    // Extreme hack: the segment limit assumed by x86_64 does not include the port bitmap.
    #[cfg(feature = "ioport_bitmap")]
    let tss0 = (tss0 & !0xFFFF) | (size_of::<TSS>() as u64);

    // get current GDT
    let gdtp = sgdt();
    let entry_count = (gdtp.limit + 1) as usize / size_of::<u64>();
    let old_gdt = core::slice::from_raw_parts(gdtp.base.as_ptr::<u64>(), entry_count);

    // allocate new GDT with 7 more entries
    //
    // NOTICE: for fast syscall:
    //   STAR[47:32] = K_CS   = K_SS - 8
    //   STAR[63:48] = U_CS32 = U_SS32 - 8 = U_CS - 16
    let mut gdt = Vec::from(old_gdt);
    gdt.extend([tss0, tss1, KCODE64, KDATA64, UCODE32, UDATA32, UCODE64].iter());
    let gdt = Vec::leak(gdt);

    // load new GDT and TSS
    lgdt(&DescriptorTablePointer {
        limit: gdt.len() as u16 * 8 - 1,
        base: VirtAddr::new(gdt.as_ptr() as _),
    });
    load_tss(SegmentSelector::new(
        entry_count as u16,
        PrivilegeLevel::Ring0,
    ));

    let sysret = SegmentSelector::new(entry_count as u16 + 4, PrivilegeLevel::Ring3).0;
    let syscall = SegmentSelector::new(entry_count as u16 + 2, PrivilegeLevel::Ring0).0;
    Star::write_raw(sysret, syscall);

    USER_SS = sysret + 8;
    USER_CS = sysret + 16;
}

/// Get current GDT register
#[inline]
unsafe fn sgdt() -> DescriptorTablePointer {
    let mut gdt = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::zero(),
    };
    asm!("sgdt [{}]", in(reg) &mut gdt);
    gdt
}

// The linker script should ensure that cpu_local_tss section is
// at the beginning of cpu_local, so that gsbase -> LOCAL_TSS.
#[allow(dead_code)]
#[link_section = ".cpu_local_tss"]
static mut LOCAL_TSS: TSS = TSS::new();

unsafe fn init_local_tss_on_bsp() -> &'static TSS {
    let tss_ptr = core::ptr::addr_of_mut!(LOCAL_TSS);

    let trap_stack_top = Box::leak(Box::new([0u8; 0x1000])).as_ptr() as u64 + 0x1000;
    (*tss_ptr).privilege_stack_table[0] = VirtAddr::new(trap_stack_top);
    &*tss_ptr
}

unsafe fn init_local_tss_on_ap() -> &'static TSS {
    let gs_base = GS::read_base().as_u64();
    let tss_ptr = gs_base as *mut TSS;

    let trap_stack_top = Box::leak(Box::new([0u8; 0x1000])).as_ptr() as u64 + 0x1000;
    (*tss_ptr).privilege_stack_table[0] = VirtAddr::new(trap_stack_top);
    &*tss_ptr
}

#[no_mangle]
static mut USER_SS: u16 = 0;
#[no_mangle]
static mut USER_CS: u16 = 0;

const KCODE64: u64 = 0x00209800_00000000; // EXECUTABLE | USER_SEGMENT | PRESENT | LONG_MODE
const UCODE64: u64 = 0x0020F800_00000000; // EXECUTABLE | USER_SEGMENT | USER_MODE | PRESENT | LONG_MODE
const KDATA64: u64 = 0x00009200_00000000; // DATA_WRITABLE | USER_SEGMENT | PRESENT
#[allow(dead_code)]
const UDATA64: u64 = 0x0000F200_00000000; // DATA_WRITABLE | USER_SEGMENT | USER_MODE | PRESENT
const UCODE32: u64 = 0x00cffa00_0000ffff; // EXECUTABLE | USER_SEGMENT | USER_MODE | PRESENT
const UDATA32: u64 = 0x00cff200_0000ffff; // EXECUTABLE | USER_SEGMENT | USER_MODE | PRESENT
