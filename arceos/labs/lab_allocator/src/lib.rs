//! Allocator algorithm in lab.

#![no_std]
#![allow(unused_variables)]

use allocator::{AllocError, AllocResult, BaseAllocator, ByteAllocator};
use core::alloc::Layout;
use core::ptr::NonNull;

const FREE_BLOCK_ALIGN: usize = core::mem::align_of::<FreeBlock>();
const HEADER_SIZE: usize = core::mem::size_of::<FreeBlock>();
const MIN_FREE_BLOCK_SIZE: usize = HEADER_SIZE;

#[repr(C)]
struct FreeBlock {
    size: usize,
    next: Option<NonNull<FreeBlock>>,
}

pub struct LabByteAllocator {
    head: Option<NonNull<FreeBlock>>,
    total: usize,
    used: usize,
}

impl LabByteAllocator {
    pub const fn new() -> Self {
        Self {
            head: None,
            total: 0,
            used: 0,
        }
    }

    fn reset(&mut self) {
        self.head = None;
        self.total = 0;
        self.used = 0;
    }

    fn align_up(value: usize, align: usize) -> usize {
        debug_assert!(align.is_power_of_two());
        (value + align - 1) & !(align - 1)
    }

    fn align_down(value: usize, align: usize) -> usize {
        debug_assert!(align.is_power_of_two());
        value & !(align - 1)
    }

    unsafe fn push_free_block(&mut self, start: usize, size: usize) {
        debug_assert!(size >= MIN_FREE_BLOCK_SIZE);
        debug_assert_eq!(start & (FREE_BLOCK_ALIGN - 1), 0);
        let ptr = start as *mut FreeBlock;
        ptr.write(FreeBlock { size, next: None });
        let block = NonNull::new_unchecked(ptr);
        self.insert_block(block);
    }

    unsafe fn insert_block(&mut self, block: NonNull<FreeBlock>) {
        let addr = block.as_ptr() as usize;
        match self.head {
            None => {
                self.head = Some(block);
            }
            Some(mut head_ptr) if addr < head_ptr.as_ptr() as usize => {
                (*block.as_ptr()).next = Some(head_ptr);
                self.head = Some(block);
            }
            Some(mut head_ptr) => {
                let mut current = head_ptr;
                while let Some(next) = (*current.as_ptr()).next {
                    if addr < next.as_ptr() as usize {
                        break;
                    }
                    current = next;
                }
                (*block.as_ptr()).next = (*current.as_ptr()).next;
                (*current.as_ptr()).next = Some(block);
            }
        }
        self.coalesce();
    }

    fn coalesce(&mut self) {
        let mut current_opt = self.head;
        while let Some(mut current) = current_opt {
            unsafe {
                let current_end = current.as_ptr() as usize + (*current.as_ptr()).size;
                if let Some(mut next) = (*current.as_ptr()).next {
                    let next_addr = next.as_ptr() as usize;
                    if current_end == next_addr {
                        (*current.as_ptr()).size += (*next.as_ptr()).size;
                        (*current.as_ptr()).next = (*next.as_ptr()).next;
                        continue;
                    }
                }
                current_opt = (*current.as_ptr()).next;
            }
        }
    }

    fn unlink_block(
        &mut self,
        prev: Option<NonNull<FreeBlock>>,
        target: NonNull<FreeBlock>,
    ) {
        unsafe {
            if let Some(mut prev_ptr) = prev {
                (*prev_ptr.as_ptr()).next = (*target.as_ptr()).next;
            } else {
                self.head = (*target.as_ptr()).next;
            }
        }
    }
}

impl BaseAllocator for LabByteAllocator {
    fn init(&mut self, start: usize, size: usize) {
        self.reset();
        self.add_memory(start, size)
            .unwrap_or_else(|_| panic!("invalid heap region"));
    }

    fn add_memory(&mut self, start: usize, size: usize) -> AllocResult {
        let end = start
            .checked_add(size)
            .ok_or(AllocError::InvalidParam)?;
        let mut aligned_start = Self::align_up(start, FREE_BLOCK_ALIGN);
        let aligned_end = Self::align_down(end, FREE_BLOCK_ALIGN);
        if aligned_end <= aligned_start {
            return Err(AllocError::InvalidParam);
        }
        let region_size = aligned_end - aligned_start;
        if region_size < MIN_FREE_BLOCK_SIZE {
            return Err(AllocError::InvalidParam);
        }
        unsafe {
            self.push_free_block(aligned_start, region_size);
        }
        self.total += region_size;
        Ok(())
    }
}

impl ByteAllocator for LabByteAllocator {
    fn alloc(&mut self, layout: Layout) -> AllocResult<NonNull<u8>> {
        let request_size = core::cmp::max(layout.size(), 1);
        let align = layout.align().max(FREE_BLOCK_ALIGN);
        let mut prev = None;
        let mut current = self.head;

        while let Some(block) = current {
            unsafe {
                let block_start = block.as_ptr() as usize;
                let block_size = (*block.as_ptr()).size;
                let block_end = block_start + block_size;

                let payload_start = Self::align_up(block_start + HEADER_SIZE, align);
                if payload_start < block_start + HEADER_SIZE {
                    return Err(AllocError::InvalidParam);
                }
                let mut alloc_end = payload_start
                    .checked_add(request_size)
                    .ok_or(AllocError::InvalidParam)?;
                alloc_end = Self::align_up(alloc_end, FREE_BLOCK_ALIGN);

                if alloc_end <= block_end {
                    self.unlink_block(prev, block);
                    let header_addr = payload_start - HEADER_SIZE;
                    let front_size = header_addr.saturating_sub(block_start);
                    if front_size >= MIN_FREE_BLOCK_SIZE {
                        self.push_free_block(block_start, front_size);
                    }
                    let tail_size = block_end.saturating_sub(alloc_end);
                    if tail_size >= MIN_FREE_BLOCK_SIZE {
                        self.push_free_block(alloc_end, tail_size);
                    }

                    let alloc_size = alloc_end - header_addr;
                    self.used += alloc_size;
                    let header = header_addr as *mut FreeBlock;
                    (*header).size = alloc_size;
                    return Ok(NonNull::new_unchecked(payload_start as *mut u8));
                }
            }

            prev = current;
            unsafe {
                current = (*block.as_ptr()).next;
            }
        }

        Err(AllocError::NoMemory)
    }

    fn dealloc(&mut self, pos: NonNull<u8>, layout: Layout) {
        let ptr = pos.as_ptr() as usize;
        assert!(ptr >= HEADER_SIZE);
        let header_addr = ptr - HEADER_SIZE;
        unsafe {
            let header = header_addr as *mut FreeBlock;
            let block_size = (*header).size;
            debug_assert!(block_size >= MIN_FREE_BLOCK_SIZE);
            self.used = self.used.saturating_sub(block_size);
            self.push_free_block(header_addr, block_size);
        }
    }

    fn total_bytes(&self) -> usize {
        self.total
    }

    fn used_bytes(&self) -> usize {
        self.used
    }

    fn available_bytes(&self) -> usize {
        self.total.saturating_sub(self.used)
    }
}
