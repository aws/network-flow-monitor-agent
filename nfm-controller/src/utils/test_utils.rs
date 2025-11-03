use std::{fs::File, io::Write};

pub struct TemporaryFile {
    pub(crate) path: String,
}

impl TemporaryFile {
    pub fn new(file_name: &str) -> Self {
        let path = format!("/tmp/{}", file_name);
        {
            let mut file = File::create(&path).unwrap();
            file.write(b"NFM test file. Safe to remove.").unwrap();
        }
        TemporaryFile { path }
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).unwrap();
    }
}
