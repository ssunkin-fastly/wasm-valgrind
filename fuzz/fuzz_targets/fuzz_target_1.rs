#![no_main]

// mod main;
// use crate::main::Valgrind;
// use crate::main::MemState;
//how to import Valgrind from main?

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut valgrind_state = Valgrind::new(640 * 1024, 1024);
    let commands = CommandSequence::arbitrary(u)?; //not sure about this syntax
    for cmd in commands.iter() {
        match cmd {
            Command::Malloc { addr, len } => {
                assert!(valgrind_state.malloc(addr, len).is_ok());
            }
            Command::Free { addr, len } => {
                assert!(valgrind_state.free(addr, len).is_ok());
            }
            Command::Read { addr, len } => {
                assert!(valgrind_state.read(addr, len).is_ok());
            }
            Command::Write { addr, len } => {
                assert!(valgrind_state.write(addr, len).is_ok());
            }
        }
    }
});

enum Command {
    Malloc {addr: usize, len: usize},
    Read {addr: usize, len: usize},
    Write {addr: usize, len: usize},
    Free {addr: usize, len: usize}
}

struct CommandSequence {
    commands: Vec<Command>
}

struct CommandSequenceState {
    metadata: Vec<MemState>
}

impl CommandSequenceState {
    fn new() {}
    fn update(cmd: Command) {}
 }

impl<'a> Arbitrary<'a> for CommandSequence {
    fn arbitrary(u: Unstructured<'a>) -> Result<CommandSequence> {
        let mut commands = vec![];
        let mut state = CommandSequenceState::new();
        for _ in 0..u.arbitrary::<usize>()? {
            let cmd = match u.int_in_range(0..=3)? {
                0 => {
                    let malloc_range = pick_free_addr_range(&state, &mut u)?;
                    Command::Malloc { start: malloc_range.0, len: malloc_range.1 }
                }
                1 => {
                    //free
                    let unalloc_range = pick_mallocd_addr_range(&state, &mut u)?;
                    Command::Free { start: unalloc_range.0, len: unalloc_range.1 }
                }
                2 => {
                    //read
                    let read_range = pick_valid_to_read(&state, &mut u)?;
                    Command::Read { start: read_range.0, len: read_range.1 }
                }
                3 => {
                    //write
                    let write_range = pick_mallocd_addr_range(&state, &mut u)?;
                    Command::Write { start: write_range.0, len: write_range.1}
                }
            };
            state.update(&cmd);
            commands.push(cmd);
        }
        Ok(CommandSequence { commands })
    }
}

//left unimplemented for now
fn pick_free_addr_range(state: &CommandSequenceState, u: &mut Arbitrary<'_>) -> Result<(u32, u32)> {}
fn pick_mallocd_addr_range(state: &CommandSequenceState, u: &mut Arbitrary<'_>) -> Result<(u32, u32)> {}
fn pick_valid_to_read(state: &CommandSequenceState, u: &mut Arbitrary<'_>) -> Result<(u32, u32)> {}



/*
questions:
    if there are two mallocs that are right next to each other, retrieving size
    of memory to free using this method will be inaccurate
    is there metadata in heap that can be somehow accessed instead to determine size
    of frees?
    https://stackoverflow.com/questions/1518711/how-does-free-know-how-much-to-free


*/