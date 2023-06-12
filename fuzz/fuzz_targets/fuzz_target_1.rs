#![no_main]

// mod main;
// use crate::main::Valgrind;
// use crate::main::MemState;
//how to import Valgrind from main?

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    //constant memsize & max_stack_size for now
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
    // valid addresses ranges that have been allocated
    // mapped to Vec of MemState for each byte in range
    allocations: HashMap<(usize, usize), Vec<MemState>> // range [a, b)
}

impl CommandSequenceState {
    //fixed mem size for now
    fn new() -> CommandSequenceState {
        let memsize = 1024 * 640;
        let mut allocations = HashMap::new();
        CommandSequenceState { allocations }
    }
    fn update(&mut self, cmd: Command) {
        match cmd {
            Command::Malloc { addr, len } => {
                //insert new entry
                //set ValidToWrite
                let range = (addr, addr+len);
                let memstate_vec = vec![MemState::ValidToWrite, len];
                self.allocations.insert(range, memstate_vec);
            }
            Command::Free { addr, len } => {
                //delete entry
                self.allocations.remove(&(addr, addr + len));
            }
            Command::Write { addr, len } => {
                //set ValidToReadWrite
                let alloc_range = self.allocations.keys().filter(|x| x.0 <= addr && addr < x.1).collect()[0]; // len(vec) should == 1
                let alloc_start = alloc_range.0;
                let write_data = self.allocations.entry(alloc_range); //pointer to memstate vec
                let vec_index = addr - alloc_start;
                for i in vec_index..vec_index + len {
                    (*write_data)[i] = MemState::ValidToReadWrite;
                }
            }
        }
    }
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

fn pick_free_addr_range(state: &CommandSequenceState, u: &mut Arbitrary<'_>) -> Result<(u32, u32)> {
    //does u.int_in_range() pick a new int if it's called multiple times
    let addr = u.int_in_range(1025, 1024 * 640);
    //if hashmap already contains 
}
fn pick_mallocd_addr_range(state: &CommandSequenceState, u: &mut Arbitrary<'_>) -> Result<(u32, u32)> {
    //pick any entry in CommandSequenceState.allocations and return (addr, len(key_vec))
}
fn pick_valid_to_read(state: &CommandSequenceState, u: &mut Arbitrary<'_>) -> Result<(u32, u32)> {
    //filter CommandSequenceState.allocations by which ones contain ValidToReadWrite data
    //and choose allocation from filter result
}