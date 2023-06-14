#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured, Error};
use wasm_valgrind::Valgrind;

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
            &Command::Free { addr, len } => {
                assert!(valgrind_state.free(addr, len).is_ok());
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
    Free {addr: usize, len: usize}
}

#[derive(Debug)]
pub struct CommandSequence {
    commands: Vec<Command>
}

pub struct CommandSequenceState {
    allocations: Vec<(usize, usize)> // (addr, len)
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
            &Command::Free { addr, len } => {
                let index = self.allocations.iter().position(|x| *x == (addr, len)).unwrap(); // error if no dereference?
                self.allocations.remove(index);
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
                    let unalloc_range = state.allocations[unalloc_index];
                    Command::Free { addr: unalloc_range.0, len: unalloc_range.1 }
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

//theres a problem here...
fn pick_free_addr_range(state: &CommandSequenceState, u: &mut Unstructured<'_>) -> Result<(usize, usize), Error> {
    let max_addr = 1024 * 640 - 1;
    let mut addr = u.int_in_range(1025..=max_addr)?;
    let mut attempts = 0;
    while is_addr_allocated(state, addr) {
        addr = u.int_in_range(1025..=max_addr)?;
        attempts += 1;
        if attempts == 10 {
            return Err(Error::NotEnoughData);
        }
    }
    let mut len = 1;
    if max_addr - addr > 1 {
        len = u.int_in_range(1..=max_addr - addr)?;
    }
    attempts = 0;
    while !any_allocs_in_range(state, addr, addr + len) {
        if max_addr - addr > 1 {
            len = u.int_in_range(1..=max_addr - addr)?;
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

fn any_allocs_in_range(state: &CommandSequenceState, start: usize, end: usize) -> bool {
    state.allocations.iter().all(|x| (start < x.0 && end < x.0) || (start > x.0 + x.1 && end > x.0 + x.1))
}