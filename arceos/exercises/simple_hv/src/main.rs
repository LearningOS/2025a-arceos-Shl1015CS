#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]
#![feature(asm_const)]
#![feature(riscv_ext_intrinsics)]

#[cfg(feature = "axstd")]
extern crate axstd as std;
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate axlog;

mod task;
mod vcpu;
mod regs;
mod csrs;
mod sbi;
mod loader;

use vcpu::VmCpuRegisters;
use riscv::register::{scause, sstatus, stval};
use csrs::defs::hstatus;
use tock_registers::LocalRegisterCopy;
use csrs::{RiscvCsrTrait, CSR};
use vcpu::_run_guest;
use sbi::SbiMessage;
use loader::load_vm_image;
use axhal::mem::PhysAddr;

static mut VM_ENTRY: usize = 0x8020_0000;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    ax_println!("Hypervisor ...");

    // A new address space for vm.
    let mut uspace = axmm::new_user_aspace().unwrap();

    // Load vm binary file into address space.
    match load_vm_image("/sbin/skernel2", &mut uspace) {
        Ok(entry_point) => {
            unsafe { VM_ENTRY = entry_point; }
            ax_println!("Loaded app with entry point: {:#x}", entry_point);
        },
        Err(e) => {
            panic!("Cannot load app! {:?}", e);
        }
    }

    // Setup context to prepare to enter guest mode.
    let mut ctx = VmCpuRegisters::default();
    prepare_guest_context(&mut ctx);

    // Setup pagetable for 2nd address mapping.
    let ept_root = uspace.page_table_root();
    prepare_vm_pgtable(ept_root);

    // Kick off vm and wait for it to exit.
    while !run_guest(&mut ctx) {
    }

    panic!("Hypervisor ok!");
}

fn prepare_vm_pgtable(ept_root: PhysAddr) {
    let hgatp = 8usize << 60 | usize::from(ept_root) >> 12;
    unsafe {
        core::arch::asm!(
            "csrw hgatp, {hgatp}",
            hgatp = in(reg) hgatp,
        );
        core::arch::riscv64::hfence_gvma_all();
    }
}

fn run_guest(ctx: &mut VmCpuRegisters) -> bool {
    unsafe {
        _run_guest(ctx);
    }

    vmexit_handler(ctx)
}

#[allow(unreachable_code)]
fn vmexit_handler(ctx: &mut VmCpuRegisters) -> bool {
    use scause::{Exception, Trap};

    let scause = scause::read();
    match scause.cause() {
        Trap::Exception(Exception::VirtualSupervisorEnvCall) => {
            let a7 = ctx.guest_regs.gprs.a_regs()[7];
            if a7 == 8 {
                ax_println!("Shutdown vm normally!");
                return true;
            }

            let sbi_msg = SbiMessage::from_regs(ctx.guest_regs.gprs.a_regs());
            match sbi_msg {
                Ok(SbiMessage::Reset(_)) => {
                    ax_println!("Shutdown vm normally!");
                    return true;
                },
                Ok(SbiMessage::PutChar(ch)) => {
                    ax_print!("{}", ch as u8 as char);
                    ctx.guest_regs.sepc += 4;
                    return false;
                },
                Ok(_) => {
                    ax_println!("Unsupported SBI call with a7={}", a7);
                    ctx.guest_regs.sepc += 4;
                    return false;
                },
                Err(e) => {
                    ax_println!("Invalid SBI call: {:?}, a7={}", e, a7);
                    ctx.guest_regs.sepc += 4;
                    return false;
                }
            }
        },
        Trap::Exception(Exception::IllegalInstruction) => {
            panic!("Bad instruction: {:#x} sepc: {:#x}",
                stval::read(),
                ctx.guest_regs.sepc
            );
        },
        Trap::Exception(Exception::LoadGuestPageFault) | 
        Trap::Exception(Exception::StoreGuestPageFault) => {
            let fault_addr = stval::read();
            if fault_addr >= 0xffffffffffff0000 {
                ax_println!("Detected VM exit via invalid memory access, treating as shutdown");
                ax_println!("Shutdown vm normally!");
                return true;
            }
            panic!("Guest Page Fault: stval {:#x} sepc: {:#x}",
                fault_addr,
                ctx.guest_regs.sepc
            );
        },
        _ => {
            panic!(
                "Unhandled trap: {:?}, sepc: {:#x}, stval: {:#x}",
                scause.cause(),
                ctx.guest_regs.sepc,
                stval::read()
            );
        }
    }
    false
}

fn prepare_guest_context(ctx: &mut VmCpuRegisters) {
    // Set hstatus
    let mut hstatus = LocalRegisterCopy::<usize, hstatus::Register>::new(
        riscv::register::hstatus::read().bits(),
    );
    // Set Guest bit in order to return to guest mode.
    hstatus.modify(hstatus::spv::Guest);
    // Set SPVP bit in order to accessing VS-mode memory from HS-mode.
    hstatus.modify(hstatus::spvp::Supervisor);
    CSR.hstatus.write_value(hstatus.get());
    ctx.guest_regs.hstatus = hstatus.get();

    // Set sstatus in guest mode.
    let mut sstatus = sstatus::read();
    sstatus.set_spp(sstatus::SPP::Supervisor);
    ctx.guest_regs.sstatus = sstatus.bits();
    // Return to entry to start vm.
    ctx.guest_regs.sepc = unsafe { VM_ENTRY };
}
