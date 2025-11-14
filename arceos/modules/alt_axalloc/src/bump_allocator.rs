//! Simple bump pointer allocator implementation.

extern crate alloc;

use allocator::{AllocError, AllocResult, BaseAllocator, ByteAllocator, PageAllocator};
use core::alloc::Layout;
use core::ptr::NonNull;

/// A simple bump allocator.
pub struct EarlyAllocator<const PAGE_SIZE: usize> {
    heap_start: usize,
    heap_size: usize,
    next: usize,
    allocations: usize,
}

impl<const PAGE_SIZE: usize> EarlyAllocator<PAGE_SIZE> {
    /// Creates an empty [`EarlyAllocator`].
    pub const fn new() -> Self {
        Self {
            heap_start: 0,
            heap_size: 0,
            next: 0,
            allocations: 0,
        }
    }

    /// Initialize the allocator.
    pub fn init(&mut self, start_vaddr: usize, size: usize) {
        self.heap_start = start_vaddr;
        self.heap_size = size;
        self.next = start_vaddr;
    }
}

impl<const PAGE_SIZE: usize> BaseAllocator for EarlyAllocator<PAGE_SIZE> {
    fn init(&mut self, _start_vaddr: usize, _size: usize) {
        // Already implemented in `EarlyAllocator::init`
    }

    fn add_memory(&mut self, _start_vaddr: usize, _size: usize) -> AllocResult {
        Err(AllocError::NoMemory)
    }
}

impl<const PAGE_SIZE: usize> ByteAllocator for EarlyAllocator<PAGE_SIZE> {
    fn total_bytes(&self) -> usize {
        self.heap_size
    }
    fn alloc(&mut self, layout: Layout) -> AllocResult<NonNull<u8>> {
        let size = layout.size();
        let align = layout.align();

        // Calculate the aligned address
        let aligned_next = (self.next + align - 1) & !(align - 1);
        let end = aligned_next.checked_add(size).ok_or(AllocError::NoMemory)?;

        if end <= self.heap_start + self.heap_size {
            let ptr = aligned_next as *mut u8;
            self.next = end;
            self.allocations += 1;
            unsafe { Ok(NonNull::new_unchecked(ptr)) }
        } else {
            Err(AllocError::NoMemory)
        }
    }

    fn dealloc(&mut self, _pos: NonNull<u8>, _layout: Layout) {
        // In bump allocator, deallocation doesn't do anything meaningful
        self.allocations = self.allocations.saturating_sub(1);
    }

    fn used_bytes(&self) -> usize {
        self.next - self.heap_start
    }

    fn available_bytes(&self) -> usize {
        (self.heap_start + self.heap_size).saturating_sub(self.next)
    }
}

impl<const PAGE_SIZE: usize> PageAllocator for EarlyAllocator<PAGE_SIZE> {
    const PAGE_SIZE: usize = PAGE_SIZE;
    
    fn total_pages(&self) -> usize {
        self.heap_size / PAGE_SIZE
    }
    fn alloc_pages(&mut self, num_pages: usize, align_pow2: usize) -> AllocResult<usize> {
        let layout = Layout::from_size_align(
            num_pages * PAGE_SIZE, 
            1 << align_pow2
        ).map_err(|_| AllocError::InvalidParam)?;
        self.alloc(layout).map(|ptr| ptr.as_ptr() as usize)
    }

    fn dealloc_pages(&mut self, _pos: usize, _num_pages: usize) {
        // In bump allocator, deallocation doesn't do anything meaningful
    }

    fn used_pages(&self) -> usize {
        (self.used_bytes() + PAGE_SIZE - 1) / PAGE_SIZE
    }

    fn available_pages(&self) -> usize {
        self.available_bytes() / PAGE_SIZE
    }
}
