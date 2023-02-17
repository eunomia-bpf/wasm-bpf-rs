use anyhow::{anyhow, Context};
use clap::Parser;
use flexi_logger::Logger;
use log_format::my_log_format;
use state::AppState;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;

use crate::func::{load::wasm_load_bpf_object, close::wasm_close_bpf_object, attach::wasm_attach_bpf_program, poll::wasm_bpf_buffer_poll, fd_by_name::wasm_bpf_map_fd_by_name, map_operate::wasm_bpf_map_operate};



mod func;
mod log_format;
mod state;
mod utils;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = "A WebAssembly runtime for eBPF user-space programs.")]
struct CommandArgs {
    #[arg(help = "The WebAssembly Module file to run")]
    wasm_module_file: String,
    #[arg(long, help = "Display more logs")]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let args = CommandArgs::parse();

    Logger::try_with_str(if args.verbose { "debug" } else { "info" })?
        .format(my_log_format)
        .start()?;

    let engine = Engine::default();
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::add_to_linker(&mut linker, |s: &mut AppState| &mut s.wasi)
        .with_context(|| anyhow!("Failed to add wasmtime_wasi to linker"))?;
    let wasi = WasiCtxBuilder::new()
        .inherit_stdio()
        .inherit_args()
        .with_context(|| anyhow!("Failed to build Wasi Context"))?
        .build();
    let mut store = Store::new(&engine, AppState::new(wasi));
    let module = Module::from_file(&engine, args.wasm_module_file)
        .with_context(|| anyhow!("Failed to read wasm module file"))?;

    add_bind_function!(linker, wasm_load_bpf_object)?;
    add_bind_function!(linker, wasm_close_bpf_object)?;
    add_bind_function!(linker, wasm_attach_bpf_program)?;
    add_bind_function!(linker, wasm_bpf_buffer_poll)?;
    add_bind_function!(linker, wasm_bpf_map_fd_by_name)?;
    add_bind_function!(linker, wasm_bpf_map_operate)?;

    linker
        .module(&mut store, "", &module)
        .with_context(|| anyhow!("Failed to link module"))?;

    linker
        .get(&mut store, "", "_start")
        .with_context(|| anyhow!("Failed to get _start function"))?
        .into_func()
        .with_context(|| anyhow!("Failed to cast to func"))?
        .typed::<(), ()>(&mut store)?
        .call(&mut store, ())?;
    return Ok(());
}
