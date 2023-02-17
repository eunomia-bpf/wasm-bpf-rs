use libbpf_rs::ObjectBuilder;
use log::debug;

use crate::{state::CallerType, utils::CallerUtils};

pub type WasmPointer = u32;
pub type BpfObjectType = u64;
pub type WasmString = u32;
pub fn wasm_load_bpf_object(
    mut caller: CallerType,
    obj_buf: WasmPointer,
    obj_buf_size: u32,
) -> u64 {
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
    return next_id;
}
pub fn wasm_close_bpf_object(mut caller: CallerType, program: BpfObjectType) -> i32 {
    todo!();
}

pub fn wasm_attach_bpf_program(
    mut caller: CallerType,
    program: BpfObjectType,
    name: WasmString,
    attach_target: WasmString,
) -> i32 {
    todo!();
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
    todo!();
}
pub fn wasm_bpf_map_fd_by_name(
    mut caller: CallerType,
    program: BpfObjectType,
    name: WasmString,
) -> i32 {
    todo!();
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
    todo!();
}

#[macro_export]
macro_rules! add_bind_function_with_module {
    ($linker: expr, $module: expr, $func: expr) => {{
        use anyhow::{anyhow, Context};
        $linker
            .func_wrap($module, stringify!($func), $func)
            .with_context(|| anyhow!("Failed to register host function `{}`", stringify!($func)))
    }};
}

#[macro_export]
macro_rules! add_bind_function {
    ($linker: expr, $func: expr) => {
        add_bind_function_with_module!($linker, "env", $func)
    };
}
