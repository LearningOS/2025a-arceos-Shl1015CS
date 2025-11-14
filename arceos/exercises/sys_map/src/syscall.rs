#![allow(dead_code)]

use core::ffi::{c_void, c_char, c_int};
use axhal::arch::TrapFrame;
use axhal::trap::{register_trap_handler, SYSCALL};
use axerrno::LinuxError;
use axtask::current;
use axtask::TaskExtRef;
use axhal::paging::MappingFlags;
use arceos_posix_api as api;

const SYS_IOCTL: usize = 29;
const SYS_OPENAT: usize = 56;
const SYS_CLOSE: usize = 57;
const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_WRITEV: usize = 66;
const SYS_EXIT: usize = 93;
const SYS_EXIT_GROUP: usize = 94;
const SYS_SET_TID_ADDRESS: usize = 96;
const SYS_MMAP: usize = 222;
const SYS_MUNMAP: usize = 215;
const SYS_MREMAP: usize = 216;
const SYS_MPROTECT: usize = 226;
const SYS_MADVISE: usize = 233;

const AT_FDCWD: i32 = -100;

/// Macro to generate syscall body
///
/// It will receive a function which return Result<_, LinuxError> and convert it to
/// the type which is specified by the caller.
#[macro_export]
macro_rules! syscall_body {
    ($fn: ident, $($stmt: tt)*) => {{
        #[allow(clippy::redundant_closure_call)]
        let res = (|| -> axerrno::LinuxResult<_> { $($stmt)* })();
        match res {
            Ok(_) | Err(axerrno::LinuxError::EAGAIN) => debug!(concat!(stringify!($fn), " => {:?}"),  res),
            Err(_) => info!(concat!(stringify!($fn), " => {:?}"), res),
        }
        match res {
            Ok(v) => v as _,
            Err(e) => {
                -e.code() as _
            }
        }
    }};
}

bitflags::bitflags! {
    #[derive(Debug)]
    /// permissions for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    struct MmapProt: i32 {
        /// Page can be read.
        const PROT_READ = 1 << 0;
        /// Page can be written.
        const PROT_WRITE = 1 << 1;
        /// Page can be executed.
        const PROT_EXEC = 1 << 2;
    }
}

impl From<MmapProt> for MappingFlags {
    fn from(value: MmapProt) -> Self {
        let mut flags = MappingFlags::USER;
        if value.contains(MmapProt::PROT_READ) {
            flags |= MappingFlags::READ;
        }
        if value.contains(MmapProt::PROT_WRITE) {
            flags |= MappingFlags::WRITE;
        }
        if value.contains(MmapProt::PROT_EXEC) {
            flags |= MappingFlags::EXECUTE;
        }
        flags
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    /// flags for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    struct MmapFlags: i32 {
        /// Share changes
        const MAP_SHARED = 1 << 0;
        /// Changes private; copy pages on write.
        const MAP_PRIVATE = 1 << 1;
        /// Map address must be exactly as requested, no matter whether it is available.
        const MAP_FIXED = 1 << 4;
        /// Don't use a file.
        const MAP_ANONYMOUS = 1 << 5;
        /// Don't check for reservations.
        const MAP_NORESERVE = 1 << 14;
        /// Allocation is for a stack.
        const MAP_STACK = 0x20000;
    }
}

#[register_trap_handler(SYSCALL)]
fn handle_syscall(tf: &TrapFrame, syscall_num: usize) -> isize {
    ax_println!("handle_syscall [{}] ...", syscall_num);
    let ret = match syscall_num {
         SYS_IOCTL => sys_ioctl(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
        SYS_SET_TID_ADDRESS => sys_set_tid_address(tf.arg0() as _),
        SYS_OPENAT => sys_openat(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _, tf.arg3() as _),
        SYS_CLOSE => sys_close(tf.arg0() as _),
        SYS_READ => sys_read(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_WRITE => sys_write(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_WRITEV => sys_writev(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_EXIT_GROUP => {
            ax_println!("[SYS_EXIT_GROUP]: system is exiting ..");
            axtask::exit(tf.arg0() as _)
        },
        SYS_EXIT => {
            ax_println!("[SYS_EXIT]: system is exiting ..");
            axtask::exit(tf.arg0() as _)
        },
        SYS_MMAP => sys_mmap(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
            tf.arg3() as _,
            tf.arg4() as _,
            tf.arg5() as _,
        ),
        SYS_MUNMAP => sys_munmap(
            tf.arg0() as _,
            tf.arg1() as _,
        ),
        SYS_MREMAP => sys_mremap(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
            tf.arg3() as _,
            tf.arg4() as _,
        ),
        SYS_MPROTECT => sys_mprotect(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
        ),
        SYS_MADVISE => sys_madvise(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
        ),
        _ => {
            ax_println!("Unimplemented syscall: {}", syscall_num);
            -LinuxError::ENOSYS.code() as _
        }
    };
    ret
}

use axstd::vec;
use axhal::mem::VirtAddr;
use memory_addr::{align_up, VirtAddrRange};

fn sys_mmap(
    addr: *mut usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: isize,
) -> isize {
    syscall_body!(sys_mmap, {
        let prot = MmapProt::from_bits_truncate(prot);
        let flags = MmapFlags::from_bits_truncate(flags);
        
        let curr = current();
        
        let len_aligned = align_up(length, axhal::mem::PAGE_SIZE_4K);
        
        ax_println!("sys_mmap: addr={:#x}, length={}, prot={:#x}, flags={:#x}, fd={}, offset={}",
                    addr as usize, length, prot.bits(), flags.bits(), fd, offset);
        
        let mut mapping_flags: MappingFlags = MmapProt::from_bits_truncate(prot.bits()).into();
        let va = if flags.contains(MmapFlags::MAP_FIXED) {
            VirtAddr::from(addr as usize)
        } else {
            let hint_va = VirtAddr::from(addr as usize);
            let user_limit = VirtAddrRange::new(
                VirtAddr::from(0),
                VirtAddr::from(0x0000_0000_8000_0000usize),
            );
            let aspace = curr.task_ext().aspace.lock();
            aspace
                .find_free_area(hint_va, len_aligned, user_limit)
                .ok_or(LinuxError::ENOMEM)?
        };
        if flags.contains(MmapFlags::MAP_ANONYMOUS) {
            let mut aspace = curr.task_ext().aspace.lock();
            aspace.map_alloc(
                va,
                len_aligned,
                mapping_flags,
                true,
            ).map_err(|_| LinuxError::ENOMEM)?;
            return Ok(va.as_usize() as isize);
        } 
        else {
            if fd < 0 {
                return Err(LinuxError::EBADF);
            }
            let mut file_buf = vec![0u8; len_aligned];
            if api::sys_lseek(fd, offset as i64, 0) < 0 {
                return Err(LinuxError::EIO);
            }
            let read_bytes = api::sys_read(fd, file_buf.as_mut_ptr() as *mut c_void, len_aligned);
            if read_bytes < 0 {
                return Err(LinuxError::EIO);
            }
            let mut aspace = curr.task_ext().aspace.lock();
            if flags.contains(MmapFlags::MAP_PRIVATE) {
                mapping_flags |= MappingFlags::WRITE;
            }
            aspace.map_alloc(
                va,
                len_aligned,
                mapping_flags,
                true,
            ).map_err(|_| LinuxError::ENOMEM)?;
            if read_bytes > 0 {
                let src_slice = &file_buf[..read_bytes as usize];
                aspace.write(va, src_slice).map_err(|_| LinuxError::ENOMEM)?;
            }
            return Ok(va.as_usize() as isize);
        }
    })
}

fn sys_openat(dfd: c_int, fname: *const c_char, flags: c_int, mode: api::ctypes::mode_t) -> isize {
    assert_eq!(dfd, AT_FDCWD);
    api::sys_open(fname, flags, mode) as isize
}

fn sys_close(fd: i32) -> isize {
    api::sys_close(fd) as isize
}

fn sys_munmap(addr: *mut c_void, length: usize) -> isize {
    syscall_body!(sys_munmap, {
        if addr as usize % axhal::mem::PAGE_SIZE_4K != 0 {
            return Err(LinuxError::EINVAL);
        }
        if length == 0 {
            return Err(LinuxError::EINVAL);
        }
        let len_aligned = align_up(length, axhal::mem::PAGE_SIZE_4K);
        let va = VirtAddr::from(addr as usize);
        
        ax_println!("sys_munmap: addr={:#x}, length={}", addr as usize, length);
        
        let curr = current();
        let mut aspace = curr.task_ext().aspace.lock();
        aspace.unmap(va, len_aligned).map_err(|_| LinuxError::EINVAL)?;
        Ok(0)
    })
}

fn sys_read(fd: i32, buf: *mut c_void, count: usize) -> isize {
    api::sys_read(fd, buf, count)
}

fn sys_write(fd: i32, buf: *const c_void, count: usize) -> isize {
    api::sys_write(fd, buf, count)
}

fn sys_writev(fd: i32, iov: *const api::ctypes::iovec, iocnt: i32) -> isize {
    unsafe { api::sys_writev(fd, iov, iocnt) }
}

fn sys_set_tid_address(tid_ptd: *const i32) -> isize {
    let curr = current();
    curr.task_ext().set_clear_child_tid(tid_ptd as _);
    curr.id().as_u64() as isize
}

fn sys_ioctl(_fd: i32, _op: usize, _argp: *mut c_void) -> i32 {
    ax_println!("Ignore SYS_IOCTL");
    0
}

fn sys_mremap(
    old_address: *mut c_void,
    old_size: usize,
    new_size: usize,
    flags: i32,
    new_address: *mut c_void,
) -> isize {
    syscall_body!(sys_mremap, {
        if old_address as usize % axhal::mem::PAGE_SIZE_4K != 0 {
            return Err(LinuxError::EINVAL);
        }
        if old_size == 0 || new_size == 0 {
            return Err(LinuxError::EINVAL);
        }

        let old_size_aligned = align_up(old_size, axhal::mem::PAGE_SIZE_4K);
        let new_size_aligned = align_up(new_size, axhal::mem::PAGE_SIZE_4K);

        let old_va = VirtAddr::from(old_address as usize);
        
        ax_println!("sys_mremap: old_addr={:#x}, old_size={}, new_size={}, flags={:#x}", 
                   old_address as usize, old_size, new_size, flags);
        
        let curr = current();
        let mut aspace = curr.task_ext().aspace.lock();

        let mremap_fixed = flags & 1; // MREMAP_FIXED = 1
        
        if mremap_fixed != 0 {
            if new_address as usize % axhal::mem::PAGE_SIZE_4K != 0 {
                return Err(LinuxError::EINVAL);
            }
            
            let new_va = VirtAddr::from(new_address as usize);

            let mut data = vec![0u8; old_size_aligned];
            aspace.read(old_va, &mut data).map_err(|_| LinuxError::EFAULT)?;

            aspace.unmap(old_va, old_size_aligned).map_err(|_| LinuxError::EINVAL)?;

            let mapping_flags = MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER;
            aspace.map_alloc(new_va, new_size_aligned, mapping_flags, true)
                .map_err(|_| LinuxError::ENOMEM)?;

            let copy_size = core::cmp::min(old_size_aligned, new_size_aligned);
            aspace.write(new_va, &data[..copy_size]).map_err(|_| LinuxError::EFAULT)?;
            
            Ok(new_va.as_usize() as isize)
        } else {
            if new_size_aligned <= old_size_aligned {
                if new_size_aligned < old_size_aligned {
                    let unmap_va = VirtAddr::from(old_va.as_usize() + new_size_aligned);
                    let unmap_size = old_size_aligned - new_size_aligned;
                    aspace.unmap(unmap_va, unmap_size).map_err(|_| LinuxError::EINVAL)?;
                }
                Ok(old_va.as_usize() as isize)
            } else {
                let extend_va = VirtAddr::from(old_va.as_usize() + old_size_aligned);
                let extend_size = new_size_aligned - old_size_aligned;
                let mapping_flags = MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER;
                
                // 尝试映射扩展部分
                match aspace.map_alloc(extend_va, extend_size, mapping_flags, true) {
                    Ok(_) => Ok(old_va.as_usize() as isize),
                    Err(_) => {
                        let user_limit = VirtAddrRange::new(
                            VirtAddr::from(0),
                            VirtAddr::from(0x0000_0000_8000_0000usize),
                        );
                        let new_va = aspace.find_free_area(VirtAddr::from(0), new_size_aligned, user_limit)
                            .ok_or(LinuxError::ENOMEM)?;

                        aspace.map_alloc(new_va, new_size_aligned, mapping_flags, true)
                            .map_err(|_| LinuxError::ENOMEM)?;

                        let mut data = vec![0u8; old_size_aligned];
                        aspace.read(old_va, &mut data).map_err(|_| LinuxError::EFAULT)?;

                        aspace.write(new_va, &data).map_err(|_| LinuxError::EFAULT)?;

                        aspace.unmap(old_va, old_size_aligned).map_err(|_| LinuxError::EINVAL)?;
                        
                        Ok(new_va.as_usize() as isize)
                    }
                }
            }
        }
    })
}

fn sys_mprotect(addr: *mut c_void, length: usize, prot: i32) -> isize {
    syscall_body!(sys_mprotect, {

        if addr as usize % axhal::mem::PAGE_SIZE_4K != 0 {
            return Err(LinuxError::EINVAL);
        }
        if length == 0 {
            return Err(LinuxError::EINVAL);
        }

        let len_aligned = align_up(length, axhal::mem::PAGE_SIZE_4K);
        let va = VirtAddr::from(addr as usize);

        let prot = MmapProt::from_bits_truncate(prot);
        
        ax_println!("sys_mprotect: addr={:#x}, length={}, prot={:#x}", addr as usize, length, prot.bits());
        let mapping_flags: MappingFlags = MmapProt::from_bits_truncate(prot.bits()).into();

        let curr = current();
        let mut aspace = curr.task_ext().aspace.lock();
        aspace.unmap(va, len_aligned).map_err(|_| LinuxError::EINVAL)?;
        aspace.map_alloc(va, len_aligned, mapping_flags, true)
            .map_err(|_| LinuxError::ENOMEM)?;
        
        Ok(0)
    })
}

fn sys_madvise(addr: *mut c_void, length: usize, advice: i32) -> isize {
    syscall_body!(sys_madvise, {

        if addr as usize % axhal::mem::PAGE_SIZE_4K != 0 {
            return Err(LinuxError::EINVAL);
        }
        if length == 0 {
            return Err(LinuxError::EINVAL);
        }
        
        
        ax_println!("sys_madvise: addr={:#x}, length={}, advice={}", addr as usize, length, advice);
        Ok(0)
    })
}
