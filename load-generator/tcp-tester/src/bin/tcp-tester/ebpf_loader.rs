use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;

pub fn load_ebpf_program() -> Result<Ebpf, String> {
    #[cfg(debug_assertions)]
    let bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("BPF_OBJECT_PATH")
    )));
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("BPF_OBJECT_PATH")
    )));
    match bpf {
        Ok(mut ebpf_program) => {
            if let Err(error) = EbpfLogger::init(&mut ebpf_program) {
                panic!("failed to initialize eBPF logger: {}", error);
            };
            Ok(ebpf_program)
        }
        Err(error) => Err(error.to_string()),
    }
}
