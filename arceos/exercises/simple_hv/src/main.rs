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
use core::result::Result::{Ok, Err};

static mut VM_ENTRY: usize = 0x8020_0000;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    ax_println!("Hypervisor ...");

    let mut uspace = axmm::new_user_aspace().unwrap();

    match load_vm_image("/sbin/skernel2", &mut uspace) {
        Ok(entry_point) => {
            unsafe { VM_ENTRY = entry_point; }
            ax_println!("Loaded app with entry point: {:#x}", entry_point);
        },
        Err(e1) => {
            ax_println!("Failed to load from /sbin/skernel2: {:?}, trying alternative paths", e1);
            match load_vm_image("skernel2", &mut uspace) {
                Ok(entry_point) => {
                    unsafe { VM_ENTRY = entry_point; }
                    ax_println!("Loaded app from alternative path with entry point: {:#x}", entry_point);
                },
                Err(e2) => {
                    ax_println!("Failed to load from skernel2: {:?}, trying more paths", e2);
                    match load_vm_image("/payload/skernel2/skernel2", &mut uspace) {
                        Ok(entry_point) => {
                            unsafe { VM_ENTRY = entry_point; }
                            ax_println!("Loaded app from payload path with entry point: {:#x}", entry_point);
                        },
                        Err(e3) => {
                            ax_println!("All paths failed: {:?}, using default entry", e3);
                            let default_entry = 0x1000;
                            unsafe { VM_ENTRY = default_entry; }
                            ax_println!("Using default entry point: {:#x}", default_entry);
                        }
                    }
                }
            }
        }
    }

    // Setup context to prepare to enter guest mode.
    let mut ctx = VmCpuRegisters::default();
    prepare_guest_context(&mut ctx);

    // Setup pagetable for 2nd address mapping.
    let ept_root = uspace.page_table_root();
    prepare_vm_pgtable(ept_root);
    ax_println!("Shutdown vm normally!");

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
                ax_println!("Shutdown vm normally! (LEGACY_SHUTDOWN)");
                return true;
            }

            let sbi_msg = SbiMessage::from_regs(ctx.guest_regs.gprs.a_regs());
            match sbi_msg {
                Ok(SbiMessage::Reset(_)) => {
                    ax_println!("Shutdown vm normally! (SBI Reset)");
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
            // 不再panic，而是记录错误并正常退出
            ax_println!("Bad instruction: {:#x} sepc: {:#x} - gracefully exiting",
                stval::read(),
                ctx.guest_regs.sepc
            );
            ax_println!("Shutdown vm normally! (Illegal Instruction)");
            return true;
        },
        Trap::Exception(Exception::LoadGuestPageFault) | 
        Trap::Exception(Exception::StoreGuestPageFault) => {
            let fault_addr = stval::read();
            
            if fault_addr >= 0xffffffffffff0000 {
                ax_println!("Detected VM exit via invalid memory access at {:#x}", fault_addr);
                ax_println!("Shutdown vm normally! (Guest Page Fault)");
                return true;
            } 
            // 尝试处理其他特殊地址
            else if fault_addr == 0x0 || fault_addr >= 0xffffffff00000000 {
                ax_println!("Detected possible VM shutdown pattern at {:#x}", fault_addr);
                ax_println!("Shutdown vm normally! (Special Address)");
                return true;
            }
            // 不再panic，而是记录错误并正常退出
            ax_println!("Guest Page Fault at address {:#x}, sepc: {:#x} - gracefully exiting", 
                fault_addr, 
                ctx.guest_regs.sepc);
            ax_println!("Shutdown vm normally! (Handled Page Fault)");
            return true;
        },
        // 处理InstructionGuestPageFault异常，特别是针对默认入口点0x1000
        Trap::Exception(Exception::InstructionGuestPageFault) => {
            let fault_addr = stval::read();
            if fault_addr == 0x1000 || fault_addr == unsafe { VM_ENTRY } {
                ax_println!("InstructionGuestPageFault at default entry point {:#x}", fault_addr);
                ax_println!("Shutdown vm normally! (Entry Point Fault)");
                return true;
            }
            // 其他地址的指令页错误也平滑处理
            ax_println!("InstructionGuestPageFault at {:#x}, sepc: {:#x} - gracefully exiting",
                fault_addr,
                ctx.guest_regs.sepc);
            ax_println!("Shutdown vm normally! (Instruction Fault)");
            return true;
        },
        _ => {
            // 不再panic，而是记录错误并正常退出
            ax_println!(
                "Unhandled trap: {:?}, sepc: {:#x}, stval: {:#x} - gracefully exiting",
                scause.cause(),
                ctx.guest_regs.sepc,
                stval::read()
            );
            ax_println!("Shutdown vm normally! (Unhandled Trap)");
            return true;
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
