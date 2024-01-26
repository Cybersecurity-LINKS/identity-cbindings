/* 
 * cbindgen User Guide 
 * at https://github.com/mozilla/cbindgen/blob/master/docs.md 
 */

extern crate cbindgen;
use std::env;
use std::path::Path;
use cbindgen::{Config, Builder};

fn main() {
    let crate_env = env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_path = Path::new(&crate_env);
    let config = Config::from_root_or_default(crate_path);
    Builder::new().with_crate(crate_path.to_str().unwrap())
        .with_config(config)
        .generate()
        .expect("Cannot generate header file!")
        .write_to_file("header-binding/identity.h");
}
