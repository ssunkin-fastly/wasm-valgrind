use std::cmp::*;

struct Valgrind {
    metadata: Vec<MemState>,
    stack_pointer: usize,
    max_stack_size: usize
}

#[derive(Debug, PartialEq)]
enum AccessError {
    DoubleMalloc {addr: usize, len: usize},
    InvalidRead {addr: usize, len: usize},
    InvalidWrite {addr: usize, len: usize},
    DoubleFree {addr: usize, len: usize},
    OutOfBounds {addr: usize, len: usize}
}

#[derive(Clone)]
enum MemState {
    Unallocated,
    ValidToWrite,
    ValidToReadWrite
}

impl Valgrind {
    fn new(mem_size: usize, max_stack_size: usize) -> Valgrind {
        let metadata = vec![MemState::Unallocated; mem_size];
        let stack_pointer = max_stack_size;
        Valgrind { metadata, stack_pointer, max_stack_size }
    }
    fn malloc(&mut self, addr: usize, len: usize) -> Result<(), AccessError> {
        if !self.is_in_bounds(addr, len) {
            return Err(AccessError::OutOfBounds {addr: addr, len: len});
        }
        for i in addr..addr+len {
            if let MemState::ValidToWrite = self.metadata[i] {
                return Err(AccessError::DoubleMalloc {addr: addr, len: len});
            }
            if let MemState::ValidToReadWrite = self.metadata[i] {
                return Err(AccessError::DoubleMalloc {addr: addr, len: len});
            }
            self.metadata[i] = MemState::ValidToWrite;
        }
        Ok(())
    }
    fn read(&mut self, addr: usize, len: usize) -> Result<(), AccessError> {
        if !self.is_in_bounds(addr, len) {
            return Err(AccessError::OutOfBounds {addr: addr, len: len});
        }
        for i in addr..addr+len {
            if let MemState::Unallocated = self.metadata[i] {
                return Err(AccessError::InvalidRead {addr: addr, len: len});
            }
            if let MemState::ValidToWrite = self.metadata[i] {
                return Err(AccessError::InvalidRead {addr: addr, len: len});
            }
        }
        Ok(())
    }
    fn write(&mut self, addr: usize, len: usize) -> Result<(), AccessError> {
        if !self.is_in_bounds(addr, len) {
            return Err(AccessError::OutOfBounds {addr: addr, len: len});
        }
        for i in addr..addr+len {
            if let MemState::Unallocated = self.metadata[i] {
                return Err(AccessError::InvalidWrite {addr: addr, len: len});
            }
            self.metadata[i] = MemState::ValidToReadWrite
        }
        Ok(())
    }
    fn free(&mut self, addr: usize, len: usize) -> Result<(), AccessError> {
        if !self.is_in_bounds(addr, len) {
            return Err(AccessError::OutOfBounds {addr: addr, len: len});
        }
        for i in addr..addr+len {
            if let MemState::Unallocated = self.metadata[i] {
                return Err(AccessError::DoubleFree {addr: addr, len: len});
            }
            self.metadata[i] = MemState::Unallocated;
        }
        Ok(())
    }
    fn is_in_bounds(&self, addr: usize, len: usize) -> bool {
        addr + len <= self.metadata.len() && self.max_stack_size < addr
    }
    fn shrink_stack(&mut self, num_bytes: usize) -> Result<(), AccessError> {
        if self.stack_pointer + num_bytes > self.max_stack_size {
            return Err(AccessError::OutOfBounds {addr: self.stack_pointer, len: num_bytes});
        }
        for i in self.stack_pointer..self.stack_pointer + num_bytes {
            self.metadata[i] = MemState::Unallocated;
        }
        self.stack_pointer = self.stack_pointer + num_bytes;
        Ok(())
    }
    fn grow_stack(&mut self, num_bytes: usize) -> Result<(), AccessError> {
        if self.stack_pointer < num_bytes {
            return Err(AccessError::OutOfBounds {addr: self.stack_pointer, len: num_bytes});
        }
        for i in self.stack_pointer - num_bytes..self.stack_pointer {
            self.metadata[i] = MemState::ValidToReadWrite;
        }
        self.stack_pointer = self.stack_pointer - num_bytes;
        Ok(())
    }
}

#[test]
fn basic_valgrind() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 0);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.read(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
}

#[test]
fn read_before_initializing() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 0);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.read(0x1000, 4), Err(AccessError::InvalidRead {addr: 0x1000, len: 4}));
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
}

#[test]
fn use_after_free() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 0);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.write(0x1000, 4), Err(AccessError::InvalidWrite {addr: 0x1000, len: 4}));
}


#[test]
fn double_free() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 0);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.free(0x1000, 32), Err(AccessError::DoubleFree {addr: 0x1000, len: 32}));
}

#[test]
fn out_of_bounds_malloc() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 0);

    assert_eq!(valgrind_state.malloc(640 * 1024, 1), Err(AccessError::OutOfBounds {addr: 640 * 1024, len: 1}));
    assert_eq!(valgrind_state.malloc(640 * 1024 - 10, 15), Err(AccessError::OutOfBounds {addr: 640 * 1024 - 10, len: 15}));
}

#[test]
fn out_of_bounds_read() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 0);

    assert!(valgrind_state.malloc(640 * 1024 - 24, 24).is_ok());
    assert_eq!(valgrind_state.read(640 * 1024 - 24, 25), Err(AccessError::OutOfBounds {addr: 640 * 1024 - 24, len: 25}));
}

#[test]
fn double_malloc() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 0);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.malloc(0x1000, 32), Err(AccessError::DoubleMalloc {addr: 0x1000, len: 32}));
    assert_eq!(valgrind_state.malloc(0x1002, 32), Err(AccessError::DoubleMalloc {addr: 0x1002, len: 32}));
}

#[test]
fn error_type() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 0);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.malloc(0x1000, 32), Err(AccessError::DoubleMalloc {addr: 0x1000, len: 32}));
    assert_eq!(valgrind_state.malloc(640 * 1024, 32), Err(AccessError::OutOfBounds {addr: 640 * 1024, len: 32}));
}

#[test]
fn stack_grow_shrink_no_error() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 1024);

    assert_eq!(valgrind_state.max_stack_size, 1024);
    assert!(valgrind_state.grow_stack(256).is_ok());
    assert_eq!(valgrind_state.stack_pointer, 768);
    assert!(valgrind_state.malloc(1024 * 2, 32).is_ok());
    assert!(valgrind_state.free(1024 * 2, 32).is_ok());
    assert!(valgrind_state.shrink_stack(128).is_ok());
    assert_eq!(valgrind_state.stack_pointer, 896);
}

#[test]
fn bad_stack_malloc() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 1024);

    assert!(valgrind_state.grow_stack(1024).is_ok());
    assert_eq!(valgrind_state.stack_pointer, 0);
    assert_eq!(valgrind_state.malloc(512, 32), Err(AccessError::OutOfBounds {addr: 512, len: 32}));
    assert_eq!(valgrind_state.malloc(1022, 32), Err(AccessError::OutOfBounds {addr: 1022, len: 32}));
}

#[test]
fn bad_stack_access() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 1024);

    assert!(valgrind_state.grow_stack(512).is_ok());
    assert_eq!(valgrind_state.stack_pointer, 512);
    assert_eq!(valgrind_state.read(256, 16), Err(AccessError::OutOfBounds {addr: 256, len: 16}));
    assert_eq!(valgrind_state.write(500, 32), Err(AccessError::OutOfBounds {addr: 500, len: 32}));
}

#[test]
fn stack_overflow() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 1024);

    assert!(valgrind_state.grow_stack(512).is_ok());
    assert_eq!(valgrind_state.grow_stack(524), Err(AccessError::OutOfBounds {addr: 512, len: 524}));
    assert_eq!(valgrind_state.stack_pointer, 512);
    assert_eq!(valgrind_state.read(256, 16), Err(AccessError::OutOfBounds {addr: 256, len: 16}));
    assert_eq!(valgrind_state.write(500, 32), Err(AccessError::OutOfBounds {addr: 500, len: 32}));
}

#[test]
fn stack_underflow() {
    let mut valgrind_state = Valgrind::new(640 * 1024, 1024);

    assert!(valgrind_state.grow_stack(32).is_ok());
    assert_eq!(valgrind_state.shrink_stack(64), Err(AccessError::OutOfBounds {addr: 992, len: 64}));
    assert_eq!(valgrind_state.stack_pointer, 992);
}