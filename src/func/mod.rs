use std::{collections::hash_map::Entry, os::fd::AsRawFd};

use libbpf_rs::{Map, ObjectBuilder, OpenMap};
use log::debug;

use crate::{state::CallerType, utils::CallerUtils};

#[macro_export]
macro_rules! ensure_program_mut_by_state {
    ($state: expr, $program: expr) => {
        match $state.object_map.get_mut(&$program) {
            Some(v) => v,
            None => {
                log::debug!("Invalid program: {}", $program);
                return -1;
            }
        }
    };
}
#[macro_export]
macro_rules! ensure_program_mut_by_caller {
    ($caller: expr, $program: expr) => {
        ensure_program_mut_by_state!($caller.data_mut(), $program)
    };
}

#[macro_export]
macro_rules! ensure_c_str {
    ($caller: expr, $var_name: expr) => {
        match $caller.read_zero_terminated_str($var_name as usize) {
            Ok(v) => v.to_string(),
            Err(err) => {
                log::debug!("Failed to read `{}`: {}", stringify!($var_name), err);
                return -1;
            }
        }
    };
}

pub type WasmPointer = u32;
pub type BpfObjectType = u64;
pub type WasmString = u32;
pub fn wasm_load_bpf_object(
    mut caller: CallerType,
    obj_buf: WasmPointer,
    obj_buf_size: u32,
) -> u64 {
    debug!("Load bpf object caller");
    let memory = caller.get_memory().expect("Expected exported `memory`");
    let mut buf = vec![0u8];
    if let Err(err) = memory.read(
        &mut caller,
        obj_buf as usize + obj_buf_size as usize - 1,
        &mut buf[..],
    ) {
        debug!(
            "Invalid pointer passed from wasm guest {}, size={}, err={}",
            obj_buf, obj_buf_size, err
        );
        return 0;
    }
    let open_object = match ObjectBuilder::default().open_memory(
        "",
        &memory.data(&mut caller)[obj_buf as usize..(obj_buf + obj_buf_size) as usize],
    ) {
        Ok(v) => v,
        Err(err) => {
            debug!("Failed to open bpf object: {}", err);
            return 0;
        }
    };
    let object = match open_object.load() {
        Ok(v) => v,
        Err(err) => {
            debug!("Failed to load bpf object: {}", err);
            return 0;
        }
    };
    let mut state = caller.data_mut();
    let next_id = state.next_object_id;
    state.next_object_id += 1;
    state.object_map.insert(next_id, object);
    debug!("Load bpf object done, id={}", next_id);
    return next_id;
}

pub fn wasm_close_bpf_object(mut caller: CallerType, program: BpfObjectType) -> i32 {
    debug!("Close bpf object: {}", program);
    let state = caller.data_mut();
    match state.object_map.entry(program) {
        Entry::Occupied(v) => {
            v.remove();
            return 0;
        }
        Entry::Vacant(_) => {
            debug!("Invalid bpf object id: {}", program);
            return -1;
        }
    };
}

pub fn wasm_attach_bpf_program(
    mut caller: CallerType,
    program: BpfObjectType,
    name: WasmString,
    attach_target: WasmString, // Allow null pointers
) -> i32 {
    debug!("wasm attach bpf program");
    let name_str = ensure_c_str!(caller, name);

    let attach_target_str = if attach_target == 0 {
        None
    } else {
        Some(ensure_c_str!(caller, attach_target))
    };
    let state = caller.data_mut();
    let object = ensure_program_mut_by_state!(state, program);

    let program = match object.prog_mut(&name_str) {
        Some(v) => v,
        None => {
            debug!("No program named `{}` found", name_str);
            return -1;
        }
    };
    if let Some(attach_target) = attach_target_str {
        let section_name = program.section();
        // TODO: support more attach type
        if section_name == "sockops" {
            let cgroup_file = match std::fs::OpenOptions::new().read(true).open(&attach_target) {
                Ok(v) => v,
                Err(err) => {
                    debug!(
                        "Failed to open cgroup `{}` for attaching: {}",
                        attach_target, err
                    );
                    return -1;
                }
            };
            let fd = cgroup_file.as_raw_fd();
            state.opened_files.push(cgroup_file);
            let link = match program.attach_cgroup(fd) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to attach program to cgroup: {}", err);
                    return -1;
                }
            };
            state.opened_links.push(link);
            return 0;
        }
    }
    let link = match program.attach() {
        Ok(v) => v,
        Err(err) => {
            debug!("Failed to attach link: {}", err);
            return -1;
        }
    };
    state.opened_links.push(link);
    return 0;
}
pub fn wasm_bpf_buffer_poll(
    mut caller: CallerType,
    program: BpfObjectType,
    fd: i32,
    sample_func: WasmPointer,
    ctx: WasmPointer,
    data: WasmPointer,
    max_size: i32,
    timeout_ms: i32,
) -> i32 {
    let state = caller.data_mut();
    let object = ensure_program_mut_by_state!(state, program);

    todo!();
}
pub fn wasm_bpf_map_fd_by_name(
    mut caller: CallerType,
    program: BpfObjectType,
    name: WasmString,
) -> i32 {
    let map_name = ensure_c_str!(caller, name);
    let object = ensure_program_mut_by_caller!(caller, program);

    let map = match object.map(&map_name) {
        Some(v) => v,
        None => {
            debug!("Invalid map name: {}", map_name);
            return -1;
        }
    };

    return map.fd();
}

pub fn wasm_bpf_map_operate(
    mut caller: CallerType,
    fd: i32,
    cmd: i32,
    key: WasmPointer,
    value: WasmPointer,
    next_key: WasmPointer, // receives the next_key; Since size of key isn't controlled by us, so it's a bit harder to ensure the safety
    flags: u64,
) -> i32 {
    // OpenMap::
    todo!();
}
