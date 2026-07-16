fn main() {
    println!("cargo:rustc-check-cfg=cfg(loom)");
    println!("cargo:rerun-if-env-changed=CALYBRIS_LOOM");
    if std::env::var_os("CALYBRIS_LOOM").is_some() {
        println!("cargo:rustc-cfg=loom");
    }
}
