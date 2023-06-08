#![no_main]

mod main;
use crate::main::Valgrind;
use crate::main::MemState;
//how to import Valgrind from main? spent way too long trying to figure this out T^T

use libfuzzer_sys::fuzz_target;
use rand::Rng;
use std::iter::Iterator;
// use libfuzzer_sys::arbitrary::Arbitrary;

// #[derive(Arbitrary, Debug)]
enum ValgrindMethods {
    Malloc {addr: usize, len: usize},
    Read {addr: usize, len: usize},
    Write {addr: usize, len: usize},
    Free {addr: usize, len: usize}
}

fuzz_target!(|data: &[u8]| {
    //valgrind memsize is a constant for now, may be better to vary it?
    let mut rng = rand::thread_rng();
    let max_stack_size = rng.gen_range(1024..1024 * 640);
    let method_calls = gen_test_calls(Valgrind::new(1024 * 640, max_stack_size), data);
    for call in method_calls.iter() {
        match call {
            ValgrindMethods::Malloc { addr, len } => {
                assert!(valgrind_state.malloc(addr, len).is_ok());
            }
            ValgrindMethods::Free { addr, len } => {
                assert!(valgrind_state.free(addr, len).is_ok());
            }
            ValgrindMethods::Read { addr, len } => {
                assert!(valgrind_state.read(addr, len).is_ok());
            }
            ValgrindMethods::Write { addr, len } => {
                assert!(valgrind_state.write(addr, len).is_ok());
            }
        }
    }
});

fn gen_test_calls(mut valgrind_state: Valgrind, data: &[u8]) -> Vec<ValgrindMethods> {
    let method_calls = Vec::new();
    for i in data.iter() {
        match i % 4 {
            0 => {
                //malloc
                //iterate from max_stack_size to metadata.size, check if each index is unallocated
                // all these while loops feel so crude :(
                let mut rng = rand::thread_rng();
                let malloc_size = rng.gen_range(1..valgrind_state.metadata.len() - valgrind_state.max_stack_size);
                let addr = valgrind_state.max_stack_size + 1;
                while addr < valgrind_state.metadata.len() && valgrind_state.metadata[addr] != MemState::Unallocated {
                    addr += 1;
                }
                if addr < valgrind_state.metadata.len() {
                    method_calls.push(ValgrindMethods::Malloc {addr: addr, len: malloc_size});
                }
            }
            1 => {
                //free
                let itr = valgrind_state.metadata.iter();
                let pos = itr.position(|&x| x != MemState::Unallocated);
                while pos != None && pos.unwrap() <= valgrind_state.metadata.len() {
                    // keep updating position
                    pos += itr.position(|&x| x != MemState::Unallocated);
                }
                if pos != None {
                    // if there are two mallocs that are right next to each other, retrieving size
                    // of memory to free using this method will be inaccurate
                    // is there metadata in heap that can be somehow accessed instead to determine size
                    // of frees?
                    // https://stackoverflow.com/questions/1518711/how-does-free-know-how-much-to-free
                    let addr = pos.unwrap();
                    let upper = addr + 1;
                    while upper < valgrind_state.metadata.len() && valgrind_state.metadata[upper] != MemState::Unallocated {
                        upper += 1;
                    }
                    method_calls.push(ValgrindMethods::Free { addr: addr, len: upper - addr });
                }
            }
            2 => {
                //read
                let itr = valgrind_state.metadata.iter();
                let pos = itr.position(|&x| x == MemState::ValidToReadWrite);
                while pos != None && pos.unwrap() <= valgrind_state.metadata.len() {
                    pos += itr.position(|&x| x == MemState::ValidToReadWrite);
                }
                if pos != None {
                    let addr = pos.unwrap();
                    let upper = addr + 1;
                    while upper < valgrind_state.metadata.len() && valgrind_state.metadata[upper] != MemState::Unallocated {
                        upper += 1;
                    }
                    // read from rand num bytes w/in approved size
                    let mut rng = rand::thread_rng();
                    let num_bytes = rng.gen_range(1, upper - addr);
                    method_calls.push(ValgrindMethods::Read { addr: addr, len: num_bytes });
                }
            }
            3 => {
                let itr = valgrind_state.metadata.iter();
                let pos = itr.position(|&x| x != MemState::Unallocated);
                while pos != None && pos.unwrap() <= valgrind_state.metadata.len() {
                    pos += itr.position(|&x| x != MemState::Unallocated);
                }
                if pos != None {
                    
                    let addr = pos.unwrap();
                    let upper = addr + 1;
                    while upper < valgrind_state.metadata.len() && valgrind_state.metadata[upper] != MemState::Unallocated {
                        upper += 1;
                    }
                    // write to rand num bytes w/in approved size
                    let mut rng = rand::thread_rng();
                    let num_bytes = rng.gen_range(1, upper - addr);
                    method_calls.push(ValgrindMethods::Read { addr: addr, len: read_num_bytes });
                }
            }
        }
    }
    method_calls
}

// fn find_valid_pos(memstate: MemState) -> usize {
//     let itr = valgrind_state.metadata.iter();
//     let pos = itr.position(|&x| x != memstate);
//     while pos != None && pos.unwrap() <= valgrind_state.metadata.len() {
//         // keep updating position
//         pos += itr.position(|&x| x != MemState::Unallocated);
//     }
//     pos
// }