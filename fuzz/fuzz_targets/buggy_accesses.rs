#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use wasm_valgrind::Valgrind;
use wasm_valgrind::AccessError;

const TEST_MAX_ADDR: usize = 1024 * 640 - 1;
const TEST_MAX_STACK_SIZE: usize = 1024;

fuzz_target!(|data: &[u8]| {
    let u = &mut Unstructured::new(data);
    let mut valgrind_state = Valgrind::new(TEST_MAX_ADDR + 1, TEST_MAX_STACK_SIZE);
    let cmds = match BuggyCommandSequence::arbitrary(u) {
        Ok(val) => val,
        Err(_) => return,
    };
    assert_eq!(cmds.commands.len(), cmds.results.len());
    for (cmd, result) in cmds.commands.iter().zip(cmds.results.iter()) {
        let cmd: &Command = cmd;
        match cmd {
            &Command::Malloc { addr, len } => {
                assert_eq!(valgrind_state.malloc(addr, len), *result);
            }
            &Command::Free { addr } => {
                assert_eq!(valgrind_state.free(addr), *result);
            }
            &Command::Read { addr, len } => {
                assert!(valgrind_state.read(addr, len).is_ok());
            }
            &Command::Write { addr, len } => {
                assert!(valgrind_state.write(addr, len).is_ok());
            }
        }
    }
});

#[derive(Debug)]
pub struct Allocation {
    addr: usize,
    len: usize,
} //TODO: model the stack as an allocation

impl Allocation {
    fn no_overlaps(&self, other: &Allocation) -> bool {
        other.addr + other.len <= self.addr || self.addr + self.len <= other.addr 
    }
    fn is_in_bounds(&self) -> bool {
        TEST_MAX_STACK_SIZE <= self.addr && self.addr + self.len - 1 <= TEST_MAX_ADDR
    }
}

#[derive(Debug)]
pub enum Command {
    Malloc {addr: usize, len: usize},
    Read {addr: usize, len: usize},
    Write {addr: usize, len: usize},
    Free {addr: usize}
}

#[derive(Debug)]
struct BuggyCommandSequence {
    commands: Vec<Command>,
    results: Vec<Result<(), AccessError>>
}

struct BuggyCommandSequenceState {
    allocations: Vec<Allocation>,
}

impl BuggyCommandSequenceState {
    fn new() -> BuggyCommandSequenceState {
        let allocations = Vec::new();
        BuggyCommandSequenceState { allocations }
    }
    fn update(&mut self, cmd: &Command) {
        match cmd {
            &Command::Malloc { addr, len } => {
                let alloc = Allocation { addr, len };
                let validity = is_malloc_valid(&alloc, &self);
                if validity.is_ok() {
                    self.allocations.push(Allocation { addr, len });
                }
            }
            &Command::Free { addr } => {
                let validity = is_free_valid(addr, &self);
                if validity.is_ok() {
                    let index = self.allocations.iter().position(|alloc| alloc.addr == addr).unwrap();
                    self.allocations.remove(index);
                }
            }
            _ => {}
        }
    }
}


impl<'a> Arbitrary<'a> for BuggyCommandSequence {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<BuggyCommandSequence, libfuzzer_sys::arbitrary::Error> {
        let mut commands = vec![];
        let mut results = vec![];
        let mut state = BuggyCommandSequenceState::new();
        for _ in 0..u.int_in_range(1..=20)? {
            let cmd = match u.int_in_range(0..=1)? {
                0 => {
                    let malloc_addr = u.int_in_range(1..=TEST_MAX_ADDR)?;
                    let malloc_len = u.int_in_range(1..=TEST_MAX_ADDR)?;
                    let alloc = Allocation { addr: malloc_addr, len: malloc_len };
                    results.push(is_malloc_valid(&alloc, &state));
                    Command::Malloc { addr: malloc_addr, len: malloc_len }
                }
                1 => {
                    let choose_rand_addr = u.ratio(1, 2)?;
                    let mut unalloc_addr = 0;
                    if choose_rand_addr {
                        unalloc_addr = u.choose_index(TEST_MAX_ADDR)?;
                    } else {
                        let some_alloc = u.choose_index(state.allocations.len())?;
                        unalloc_addr = state.allocations[some_alloc].addr;
                    }
                    results.push(is_free_valid(unalloc_addr, &state));
                    Command::Free { addr: unalloc_addr }
                }
                _ => {
                    unreachable!()
                }
            };
            println!("{:?} allocs: {:?} resutls: {:?}", cmd, state.allocations, results);
            state.update(&cmd);
            commands.push(cmd);
        }
        Ok(BuggyCommandSequence { commands, results })
    }
}

fn no_allocs_in_range(state: &BuggyCommandSequenceState, other: &Allocation ) -> bool {
    state.allocations.iter().all(|alloc| alloc.no_overlaps(other))
}

fn is_malloc_valid(alloc: &Allocation, state: &BuggyCommandSequenceState) -> Result<(), AccessError> {
    if !alloc.is_in_bounds() {
        return Err(AccessError::OutOfBounds { addr: alloc.addr, len: alloc.len });
    } else if !no_allocs_in_range(&state, &alloc) {
        return Err(AccessError::DoubleMalloc { addr: alloc.addr, len: alloc.len });
    } else {
        return Ok(());
    }
}

fn is_free_valid(addr: usize, state: &BuggyCommandSequenceState) -> Result<(), AccessError> {
    if !state.allocations.iter().any(|alloc| alloc.addr == addr) {
        return Err(AccessError::InvalidFree { addr });
    } else { 
        return Ok(());
    }
}