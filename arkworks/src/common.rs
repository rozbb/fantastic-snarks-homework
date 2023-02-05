use ark_serialize::CanonicalSerialize;

use ark_serialize::CanonicalDeserialize;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

pub const PEDERSEN_PARAMS_FILENAME: &str = "pedersen_params.bin";
pub const TESTCASE_GOOD_FILENAME: &str = "proof_package_good.bin";
pub const TESTCASE_BAD_FILENAME: &str = "proof_package_bad.bin";

pub fn write_to_file<S: CanonicalSerialize>(path_str: &str, data: &S) {
    // Convert string to FS path
    let path = Path::new(path_str);

    // Open the file
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .expect(&format!("could not open {path_str} for writing"));

    // Serialize the data
    let mut buf = Vec::new();
    data.serialize_compressed(&mut buf)
        .expect(&format!("failed to serialize to {path_str}"));

    // Write to file
    f.write(&buf).expect("failed to write to {path_str}");
}

pub fn read_from_file<S: CanonicalDeserialize>(path_str: &str) -> S {
    // Convert string to FS path
    let path = Path::new(path_str);

    // Open the file
    let mut f = OpenOptions::new()
        .read(true)
        .open(path)
        .expect(&format!("could not open {path_str} for reading"));

    // Read from file
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .expect(&format!("failed to read from {path_str}"));

    // Deserialize the data
    S::deserialize_compressed(buf.as_slice())
        .expect(&format!("failed to deserialize from {path_str}"))
}
