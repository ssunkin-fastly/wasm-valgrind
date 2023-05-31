// have accesserror return more info (addr of invalid access)
// memory w/ 3 states: unallocated, valid to write to, fully initialized
// set stack pointer or alloc stack / free stack; designates memory as stack

struct Valgrind {
    metadata: Vec<MemState>
}

#[derive(Debug, PartialEq)]
enum AccessError {
    DoubleMalloc {addr: usize, len: usize},
    InvalidReadWrite {addr: usize, len: usize},
    DoubleFree {addr: usize, len: usize},
    OutOfBounds {addr: usize, len: usize},
}

#[derive(Clone)]
enum MemState {
    Unallocated,
    ValidToWrite,
    ValidToReadWrite
}

impl Valgrind {
    fn new(mem_size: usize) -> Valgrind {
        let metadata = vec![MemState::Unallocated; mem_size];
        Valgrind { metadata }
    }
    fn malloc(&mut self, addr: usize, len: usize) -> Result<(), AccessError> {
        if !self.is_in_bounds(addr, len) {
            return Err(AccessError::OutOfBounds {addr: addr, len: len});
        }
        for i in addr..addr+len {
            // feels a bit redundant, would love to change logic to if !Unallocated then 
            // error but couldn't figure out how using 'if let' statements 
            if let MemState::ValidToWrite = self.metadata[i] {
                return Err(AccessError::DoubleMalloc {addr: addr, len: len});
            } if let MemState::ValidToReadWrite = self.metadata[i] {
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
                return Err(AccessError::InvalidReadWrite {addr: addr, len: len});
            } if let MemState::ValidToWrite = self.metadata[i] {
                return Err(AccessError::InvalidReadWrite {addr: addr, len: len});
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
                return Err(AccessError::InvalidReadWrite {addr: addr, len: len});
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
        addr + len <= self.metadata.len()
    }
}

#[test]
fn basic_valgrind() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.read(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
}

#[test]
fn read_before_initializing() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.read(0x1000, 4), Err(AccessError::InvalidReadWrite {addr: 0x1000, len: 4}));
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
}

#[test]
fn use_after_free() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.write(0x1000, 4), Err(AccessError::InvalidReadWrite {addr: 0x1000, len: 4}));
}


#[test]
fn double_free() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.free(0x1000, 32), Err(AccessError::DoubleFree {addr: 0x1000, len: 32}));
}

#[test]
fn out_of_bounds_malloc() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert_eq!(valgrind_state.malloc(640 * 1024, 1), Err(AccessError::OutOfBounds {addr: 640 * 1024, len: 1}));
    assert_eq!(valgrind_state.malloc(640 * 1024 - 10, 15), Err(AccessError::OutOfBounds {addr: 640 * 1024 - 10, len: 15}));
}

#[test]
fn out_of_bounds_read() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(640 * 1024 - 24, 24).is_ok());
    assert_eq!(valgrind_state.read(640 * 1024 - 24, 25), Err(AccessError::OutOfBounds {addr: 640 * 1024 - 24, len: 25}));
}

#[test]
fn double_malloc() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.malloc(0x1000, 32), Err(AccessError::DoubleMalloc {addr: 0x1000, len: 32}));
    assert_eq!(valgrind_state.malloc(0x1002, 32), Err(AccessError::DoubleMalloc {addr: 0x1002, len: 32}));
}

#[test]
fn error_type() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.malloc(0x1000, 32), Err(AccessError::DoubleMalloc {addr: 0x1000, len: 32}));
    assert_eq!(valgrind_state.malloc(640 * 1024, 32), Err(AccessError::OutOfBounds {addr: 640 * 1024, len: 32}));
}