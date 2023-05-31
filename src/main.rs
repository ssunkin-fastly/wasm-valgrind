fn main() {
    print!("Hello World");
}
// have accesserror return more info (addr of invalid access)
// memory w/ 3 states: unallocated, valid to write to, fully initialized
// set stack pointer or alloc stack / free stack; designates memory as stack

struct Valgrind {
    metadata: Vec<bool>
}

#[derive(Debug, PartialEq)]
enum AccessError {
    DoubleMalloc,
    InvalidReadWrite,
    DoubleFree,
    OutOfBounds
}

enum MemStates {
    Unallocated,
    ValidWrite,
    ValidReadWrite
}

impl Valgrind {
    fn new(mem_size: usize) -> Valgrind {
        let metadata = vec![false; mem_size];
        Valgrind { metadata }
    }
    fn malloc(&mut self, addr: usize, len: usize) -> Result<(), AccessError> {
        if !self.is_in_bounds(addr, len) {
            return Err(AccessError::OutOfBounds);
        }
        for i in addr..addr+len {
            if self.metadata[i] {
                return Err(AccessError::DoubleMalloc);
            }
            self.metadata[i] = true;
        }
        Ok(())
    }
    fn read(&mut self, addr: usize, len: usize) -> Result<(), AccessError> {
        self.write(addr, len)
    }
    fn write(&mut self, addr: usize, len: usize) -> Result<(), AccessError> {
        if !self.is_in_bounds(addr, len) {
            return Err(AccessError::OutOfBounds);
        }
        for i in addr..addr+len {
            if !self.metadata[i] {
                return Err(AccessError::InvalidReadWrite);
            }
        }
        Ok(())
    }
    fn free(&mut self, addr: usize, len: usize) -> Result<(), AccessError> {
        if !self.is_in_bounds(addr, len) {
            return Err(AccessError::OutOfBounds);
        }
        for i in addr..addr+len {
            if !self.metadata[i] {
                return Err(AccessError::DoubleFree);
            }
            self.metadata[i] = false;
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
    assert!(valgrind_state.read(0x1000, 4).is_ok());
    assert!(valgrind_state.write(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
}

#[test]
fn use_after_free() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert!(valgrind_state.read(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.write(0x1000, 4), Err(AccessError::InvalidReadWrite));
}


#[test]
fn double_free() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert!(valgrind_state.read(0x1000, 4).is_ok());
    assert!(valgrind_state.free(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.free(0x1000, 32), Err(AccessError::DoubleFree));
}

#[test]
fn out_of_bounds_malloc() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert_eq!(valgrind_state.malloc(640 * 1024, 1), Err(AccessError::OutOfBounds));
    assert_eq!(valgrind_state.malloc(640 * 1024 - 10, 15), Err(AccessError::OutOfBounds));
}

#[test]
fn out_of_bounds_read() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(640 * 1024 - 24, 24).is_ok());
    assert_eq!(valgrind_state.read(640 * 1024 - 24, 25), Err(AccessError::OutOfBounds));
}

#[test]
fn double_malloc() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.malloc(0x1000, 32), Err(AccessError::DoubleMalloc));
    assert_eq!(valgrind_state.malloc(0x1002, 32), Err(AccessError::DoubleMalloc));
}

#[test]
fn error_type() {
    let mut valgrind_state = Valgrind::new(640 * 1024);

    assert!(valgrind_state.malloc(0x1000, 32).is_ok());
    assert_eq!(valgrind_state.malloc(0x1000, 32), Err(AccessError::DoubleMalloc));
    assert_eq!(valgrind_state.malloc(640 * 1024, 32), Err(AccessError::OutOfBounds));
}