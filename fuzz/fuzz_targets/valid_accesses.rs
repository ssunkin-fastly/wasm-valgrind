#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured, Error};
use wasm_valgrind::Valgrind;

const TEST_MAX_ADDR: usize = 1024 * 640 - 1;
const TEST_MAX_STACK_SIZE: usize = 1024;

fuzz_target!(|data: &[u8]| {
    let u = &mut Unstructured::new(data);
    let mut valgrind_state = Valgrind::new(640 * 1024, 1024);
    let cmds = match CommandSequence::arbitrary(u) {
        Ok(val) => val,
        Err(_) => return,
    };
    println!("{:?}", cmds);
    for cmd in cmds.commands.iter() {
        let cmd: &Command = cmd;
        match cmd {
            &Command::Malloc { addr, len } => {
                assert!(valgrind_state.malloc(addr, len).is_ok());
            }
            &Command::Free { addr } => {
                assert!(valgrind_state.free(addr).is_ok());
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
pub struct CommandSequence {
    commands: Vec<Command>,
}

pub struct CommandSequenceState {
    allocations: Vec<(usize, usize)>, // (addr, len)
}

impl CommandSequenceState {
    fn new() -> CommandSequenceState {
        let allocations = Vec::new();
        CommandSequenceState { allocations }
    }
    fn update(&mut self, cmd: &Command) {
        match cmd {
            &Command::Malloc { addr, len } => {
                self.allocations.push((addr, len)); 
            }
            &Command::Free { addr } => {
                let index = self.allocations.iter().position(|(x, _)| *x == addr).unwrap();
                self.allocations.remove(index);
            }
            &Command::Write { addr, len } => {
                let index = self.allocations.iter().position(|(x, y)| *x <= addr && addr <= *y).unwrap();
                let write_to = self.allocations[index];
                /*
                ideas for how to change CommandsequenceState
                1. Add a new struct field that's read-write ok sections (might get complicated if they overlap)
                2. Each allocation is mapped to a list of ranges in which read-write is ok; merging/refactoring
                    these ranges could be tricky
                3. Each alloc is mapped to a dict of allocs that are either write only or read-write ok
                    - loop thru the allocs in a dict are for read/writes: read to check that all are read-write ok,
                      write to set given indices to read-write ok
                */
            }
            _ => {}
        }
    }
 }

impl<'a> Arbitrary<'a> for CommandSequence {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<CommandSequence, libfuzzer_sys::arbitrary::Error> {
        let mut commands = vec![];
        let mut state = CommandSequenceState::new();
        for _ in 0..u.arbitrary::<usize>()? {
            let cmd = match u.int_in_range(0..=1)? {
                0 => {
                    let malloc_range = pick_free_addr_range(&state, u)?;
                    Command::Malloc { addr: malloc_range.0, len: malloc_range.1 }
                }
                1 => {
                    let unalloc_index = u.choose_index(state.allocations.len())?;
                    let unalloc_addr = state.allocations[unalloc_index].0;
                    Command::Free { addr: unalloc_addr }
                }
                _ => {
                    unreachable!()
                }
            };
            println!("{:?} {:?}", cmd, state.allocations);
            state.update(&cmd);
            commands.push(cmd);
        }
        Ok(CommandSequence { commands })
    }
}

fn pick_free_addr_range(state: &CommandSequenceState, u: &mut Unstructured<'_>) -> Result<(usize, usize), Error> {
    let mut addr = u.int_in_range(1024..=TEST_MAX_ADDR)?;
    let mut attempts = 0;
    while is_addr_allocated(state, addr) {
        addr = u.int_in_range(1025..=TEST_MAX_ADDR)?;
        attempts += 1;
        if attempts == 10 {
            return Err(Error::NotEnoughData);
        }
    }
    let mut len = 1;
    if TEST_MAX_ADDR - addr > 1 {
        len = u.int_in_range(1..=TEST_MAX_ADDR - addr)?;
    }
    attempts = 0;
    while !no_allocs_in_range(state, addr, addr + len) {
        if TEST_MAX_ADDR - addr > 1 {
            len = u.int_in_range(1..=TEST_MAX_ADDR - addr)?;
        }
        attempts += 1;
        if attempts == 10 {
            return Err(Error::NotEnoughData);
        }
    }
    Ok((addr, len))
}

fn is_addr_allocated(state: &CommandSequenceState, addr: usize) -> bool {
    state.allocations.iter().any(|x| x.0 <= addr && addr < x.0 + x.1)
}

fn no_allocs_in_range(state: &CommandSequenceState, start: usize, end: usize) -> bool {
    state.allocations.iter().all(|x| (start < x.0 && end < x.0) || (start >= x.0 + x.1 && end >= x.0 + x.1))
}