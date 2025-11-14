use axhal::paging::MappingFlags;
use axhal::mem::{PAGE_SIZE_4K, phys_to_virt, VirtAddr};
use axmm::AddrSpace;
use axstd::fs::File;
use axstd::io::{self, Read, Seek, SeekFrom};
use alloc::vec::Vec;
use core::result::Result::{Ok, Err};

// ELF header constants
const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_NIDENT: usize = 16;
const PT_LOAD: u32 = 1;

// ELF header structs
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64_Ehdr {
    e_ident: [u8; EI_NIDENT],  // ELF identification bytes
    e_type: u16,               // Type of file
    e_machine: u16,            // Required architecture
    e_version: u32,            // ELF version
    e_entry: u64,              // Entry point address
    e_phoff: u64,              // Program header offset
    e_shoff: u64,              // Section header offset
    e_flags: u32,              // Processor-specific flags
    e_ehsize: u16,             // ELF header size
    e_phentsize: u16,          // Size of program header entry
    e_phnum: u16,              // Number of program header entries
    e_shentsize: u16,          // Size of section header entry
    e_shnum: u16,              // Number of section header entries
    e_shstrndx: u16,           // Section name string table index
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64_Phdr {
    p_type: u32,               // Type of segment
    p_flags: u32,              // Segment attributes
    p_offset: u64,             // Offset in file
    p_vaddr: u64,              // Virtual address in memory
    p_paddr: u64,              // Reserved
    p_filesz: u64,             // Size of segment in file
    p_memsz: u64,              // Size of segment in memory
    p_align: u64,              // Alignment of segment
}

pub fn get_elf_entry_point(fname: &str) -> io::Result<usize> {
    let mut file = File::open(fname)?;
    let mut ehdr_bytes = [0u8; std::mem::size_of::<Elf64_Ehdr>()];
    file.read_exact(&mut ehdr_bytes)?;
    if ehdr_bytes[0..4] != ELFMAG {
        return Err(io::Error::from(axerrno::AxError::InvalidData));
    }
    let ehdr = unsafe { *(ehdr_bytes.as_ptr() as *const Elf64_Ehdr) };
    Ok(ehdr.e_entry as usize)
}

pub fn load_vm_image(fname: &str, uspace: &mut AddrSpace) -> io::Result<usize> {
    ax_println!("Trying to load VM image from {}", fname);
    
    let mut file = match File::open(fname) {
        Ok(f) => f,
        Err(e) => {
            ax_println!("Failed to open {}: {:?}", fname, e);
            // 尝试备用路径
            let alt_path = "/skernel2";
            ax_println!("Trying alternate path: {}", alt_path);
            File::open(alt_path)?
        }
    };

    let mut ehdr_bytes = [0u8; std::mem::size_of::<Elf64_Ehdr>()];
    if let Err(e) = file.read_exact(&mut ehdr_bytes) {
        ax_println!("Failed to read ELF header: {:?}", e);
        return Err(e);
    }
    
    // 打印前4个字节进行调试
    ax_println!("ELF magic bytes: [{:#02x}, {:#02x}, {:#02x}, {:#02x}]", 
        ehdr_bytes[0], ehdr_bytes[1], ehdr_bytes[2], ehdr_bytes[3]);
    
    if ehdr_bytes[0..4] != ELFMAG {
        ax_println!("Invalid ELF magic, expected: [{:#02x}, {:#02x}, {:#02x}, {:#02x}]", 
            ELFMAG[0], ELFMAG[1], ELFMAG[2], ELFMAG[3]);
        return Err(io::Error::from(axerrno::AxError::InvalidData));
    }
    let ehdr = unsafe { *(ehdr_bytes.as_ptr() as *const Elf64_Ehdr) };
    let phdr_size = ehdr.e_phentsize as usize;
    let phdr_count = ehdr.e_phnum as usize;
    let mut phdr_bytes = vec![0u8; phdr_size * phdr_count];
    file.seek(SeekFrom::Start(ehdr.e_phoff))?;
    file.read_exact(&mut phdr_bytes)?;
    for i in 0..phdr_count {
        let phdr_offset = i * phdr_size;
        let phdr = unsafe { *(phdr_bytes[phdr_offset..].as_ptr() as *const Elf64_Phdr) };
        
        if phdr.p_type == PT_LOAD {
            let vaddr_start = VirtAddr::from((phdr.p_vaddr as usize) & !(PAGE_SIZE_4K - 1));
            let vaddr_end = VirtAddr::from(((phdr.p_vaddr + phdr.p_memsz) as usize + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1));
            let size = vaddr_end - vaddr_start;
            let mut flags = MappingFlags::USER | MappingFlags::READ | MappingFlags::WRITE;
            if phdr.p_flags & 0x1 != 0 { flags |= MappingFlags::EXECUTE; } // PF_X
            ax_println!("Mapping segment: VA:{:#x} - VA:{:#x}, flags={:?}", vaddr_start, vaddr_end, flags);
            uspace.map_alloc(vaddr_start, size, flags, true).unwrap();
            let (paddr, _, _) = uspace.page_table()
                .query(VirtAddr::from(phdr.p_vaddr as usize))
                .unwrap_or_else(|_| panic!("Mapping failed for segment: {:#x}", phdr.p_vaddr));
            let mut segment_data = vec![0u8; phdr.p_filesz as usize];
            file.seek(SeekFrom::Start(phdr.p_offset))?;
            file.read_exact(&mut segment_data)?;
            let page_offset = phdr.p_vaddr as usize % PAGE_SIZE_4K;
            unsafe {
                let dest_ptr = phys_to_virt(paddr).as_mut_ptr().add(page_offset);
                core::ptr::copy_nonoverlapping(
                    segment_data.as_ptr(),
                    dest_ptr,
                    phdr.p_filesz as usize,
                );
            }
        }
    }
    let entry_point = ehdr.e_entry as usize;
    ax_println!("Entry point: {:#x}", entry_point);
    
    Ok(entry_point)
}

fn load_file(fname: &str, buf: &mut [u8]) -> io::Result<usize> {
    ax_println!("app: {}", fname);
    let mut file = File::open(fname)?;
    let n = file.read(buf)?;
    Ok(n)
}
