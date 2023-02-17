use std::collections::HashMap;

use libbpf_rs::Object;
use wasmtime::Caller;
use wasmtime_wasi::WasiCtx;

const FIRST_OBJECT_ID: u64 = 1;

pub struct AppState {
    pub wasi: WasiCtx,
    pub next_object_id: u64,
    pub object_map: HashMap<u64, Object>,
}

impl AppState {
    pub fn new(wasi: WasiCtx) -> Self {
        Self {
            wasi,
            next_object_id: FIRST_OBJECT_ID,
            object_map: Default::default(),
        }
    }
}

pub type CallerType<'a> = Caller<'a, AppState>;
