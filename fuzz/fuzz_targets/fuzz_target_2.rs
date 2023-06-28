#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured, Error};
use wasm_valgrind::Valgrind;
use wasm_valgrind::AccessError;
// use fuzz_targets::fuzz_target_1::{Command};

fuzz_target!(|data: &[u8]| {
    let u = &mut Unstructured::new(data);
    let mut valgrind_state = Valgrind::new(640 * 1024, 1024);
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
    allocations: Vec<(usize, usize)>, // addr, len
}

impl BuggyCommandSequenceState {
    fn new() -> BuggyCommandSequenceState {
        let allocations = Vec::new();
        BuggyCommandSequenceState { allocations }
    }
    fn update(&mut self, cmd: &Command) {
        match cmd {
            &Command::Malloc { addr, len } => {
                let validity = is_malloc_valid(addr, len, &self);
                println!("malloc is valid? {}", validity.is_ok());
                if validity.is_ok() {
                    self.allocations.push((addr, len));
                }
            }
            &Command::Free { addr } => {
                let validity = is_free_valid(addr, &self);
                if validity == Ok(()) {
                    let index = self.allocations.iter().position(|x| x.0 == addr).unwrap(); // error if no dereference?
                    self.allocations.remove(index);
                }
            }
            _ => {}
        }
    }
}


impl<'a> Arbitrary<'a> for BuggyCommandSequence {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<BuggyCommandSequence, libfuzzer_sys::arbitrary::Error> {
        let max_addr = 1024 * 640 - 1;
        let mut commands = vec![];
        let mut results = vec![];
        let mut state = BuggyCommandSequenceState::new();
        for _ in 0..u.int_in_range(1..=20)? {
            let cmd = match u.int_in_range(0..=1)? {
                0 => {
                    let malloc_addr = u.int_in_range(1..=max_addr)?;
                    let malloc_len = u.int_in_range(1..=max_addr)?;
                    results.push(is_malloc_valid(malloc_addr, malloc_len, &state));
                    Command::Malloc { addr: malloc_addr, len: malloc_len }
                }
                1 => {
                    let choose_rand_addr = u.ratio(1, 2)?;
                    let mut unalloc_addr = 0;
                    if choose_rand_addr {
                        unalloc_addr = u.choose_index(max_addr)?;
                    } else {
                        let some_alloc = u.choose_index(state.allocations.len())?;
                        unalloc_addr = state.allocations[some_alloc].0;
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

fn no_allocs_in_range(state: &BuggyCommandSequenceState, start: usize, end: usize) -> bool {
    let ret = state.allocations.iter().all(|x| (start < x.0 && end < x.0) || (start > x.0 + x.1 - 1 && end > x.0 + x.1 - 1));
    println!("no allocs in range? {}", ret);
    return ret;
}

fn is_malloc_valid(addr: usize, len: usize, state: &BuggyCommandSequenceState) -> Result<(), AccessError> {
    let max_addr = 1024 * 640 - 1;
    let max_stack_size = 1024;
    let is_in_bounds = max_stack_size < addr && addr + len - 1 <= max_addr;
    println!("malloc in bounds? {}", is_in_bounds);
    if !is_in_bounds {
        return Err(AccessError::OutOfBounds { addr, len });
    } else if !no_allocs_in_range(&state, addr, addr + len - 1) {
        return Err(AccessError::DoubleMalloc { addr, len });
    } else {
        return Ok(());
    }
}

fn is_free_valid(addr: usize, state: &BuggyCommandSequenceState) -> Result<(), AccessError> {
    let max_addr = 1024 * 640 - 1;
    let max_stack_size = 1024;
    if !state.allocations.iter().any(|(alloc_addr, _)| *alloc_addr == addr) {
        return Err(AccessError::InvalidFree { addr });
    } else { 
        return Ok(());
    }
}