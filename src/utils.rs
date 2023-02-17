use crate::AppState;
use anyhow::{anyhow, bail, Context};
use wasmtime::{Caller, Memory, Table};

const INDIRECT_TABLE_NAME: &str = "__indirect_function_table";

pub trait CallerUtils {
    fn get_memory(&mut self) -> anyhow::Result<Memory>;
    fn get_indirect_call_table(&mut self) -> anyhow::Result<Table>;
    // Terminated zero won't be put in the returned Vec
    fn read_wasm_string(&mut self, offset: usize) -> anyhow::Result<Vec<u8>>;
}

impl CallerUtils for Caller<'_, AppState> {
    fn get_memory(&mut self) -> anyhow::Result<Memory> {
        match self
            .get_export("memory")
            .with_context(|| anyhow!("No export named `memory` found!"))?
        {
            wasmtime::Extern::Memory(t) => Ok(t),
            _ => bail!("The type of exported instance `memory` is not `Memory`"),
        }
    }

    fn get_indirect_call_table(&mut self) -> anyhow::Result<Table> {
        let table = self.get_export(INDIRECT_TABLE_NAME).with_context(||anyhow!("No export named `{}` found. And `--export-table` to you linker to emit such export.",INDIRECT_TABLE_NAME))?;
        let table = table.into_table().with_context(|| {
            anyhow!(
                "The type of export named `{}` is not table!",
                INDIRECT_TABLE_NAME
            )
        })?;
        return Ok(table);
    }
    fn read_wasm_string(&mut self, offset: usize) -> anyhow::Result<Vec<u8>> {
        let memory = self.get_memory()?;
        let mut buf = vec![];
        let mut at = offset;
        let mut curr = vec![0u8];
        loop {
            memory.read(&mut *self, at, &mut curr).with_context(|| {
                anyhow!(
                    "Failed to access byte at {}, may be memory index out of bound",
                    at
                )
            })?;
            if curr[0] == 0 {
                break;
            } else {
                at += 1;
                buf.push(curr[0]);
            }
        }
        return Ok(buf);
    }
}
