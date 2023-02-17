# wasm-bpf-rs

A WebAssembly runtime for ebpf user-space programs.

**Not finished yet. USE WITH CAUTION**

```console
A WebAssembly runtime for eBPF user-space programs.

Usage: wasm-bpf-rs [OPTIONS] <WASM_MODULE_FILE>

Arguments:
  <WASM_MODULE_FILE>
          The WebAssembly Module file to run

Options:
      --verbose
          Display more logs

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## What can it do?

- Run WASM modules, safe and safer
- WASI support. You can use many native APIs in your WASM program
- Several eBPF related functions provides. You can interact with eBPF in your program.