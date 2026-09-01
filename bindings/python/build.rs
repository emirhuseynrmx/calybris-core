use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest as _, Sha256};

fn main() {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory");
    let target = Path::new(&manifest).join("../..");
    println!(
        "cargo:rerun-if-changed={}",
        target.join("Cargo.lock").display()
    );
    println!("cargo:rerun-if-changed={}", target.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        target.join(".git/HEAD").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        target.join(".git/index").display()
    );
    for name in [
        "CALYBRIS_RELEASE_BUILD",
        "CALYBRIS_RELEASE_COMMIT_SHA",
        "CALYBRIS_RELEASE_TREE_SHA",
        "CALYBRIS_RELEASE_SOURCE_DIGEST",
        "CALYBRIS_RELEASE_LOCK_SHA256",
        "CALYBRIS_RELEASE_DIRTY",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let git_commit = git(&target, &["rev-parse", "HEAD"]).filter(|value| is_hex(value, 40));
    let git_tree = git(&target, &["rev-parse", "HEAD^{tree}"]).filter(|value| is_hex(value, 40));
    let commit = release_env("COMMIT_SHA")
        .filter(|value| is_hex(value, 40))
        .or(git_commit)
        .or_else(|| cargo_vcs_commit(&target))
        .unwrap_or_default();
    let tree = release_env("TREE_SHA")
        .filter(|value| is_hex(value, 40))
        .or(git_tree)
        .unwrap_or_default();
    let dirty = match release_env("DIRTY").as_deref() {
        Some("true") => true,
        Some("false") => false,
        Some(value) => panic!("CALYBRIS_RELEASE_DIRTY must be true or false, got {value:?}"),
        None => git(
            &target,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )
        .is_none_or(|status| !status.is_empty()),
    };
    let source_digest = release_env("SOURCE_DIGEST")
        .filter(|value| is_hex(value, 40) || is_hex(value, 64))
        .unwrap_or_else(|| source_digest(&target, &tree, dirty));
    let lock = std::fs::read(target.join("Cargo.lock")).unwrap_or_default();
    let computed_lock_digest = encode_hex(&Sha256::digest(lock));
    let lock_digest = release_env("LOCK_SHA256")
        .filter(|value| is_hex(value, 64))
        .unwrap_or(computed_lock_digest);
    let identity_verified = is_hex(&commit, 40)
        && is_hex(&tree, 40)
        && (is_hex(&source_digest, 40) || is_hex(&source_digest, 64))
        && is_hex(&lock_digest, 64);
    if std::env::var_os("CALYBRIS_RELEASE_BUILD").is_some() && (!identity_verified || dirty) {
        panic!(
            "release build requires exact clean commit/tree/source/lock identity; \
             inject verified CALYBRIS_RELEASE_* values when Git metadata is unavailable"
        );
    }

    println!("cargo:rustc-env=CALYBRIS_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=CALYBRIS_BUILD_TREE={tree}");
    println!("cargo:rustc-env=CALYBRIS_BUILD_SOURCE_DIGEST={source_digest}");
    println!("cargo:rustc-env=CALYBRIS_BUILD_LOCK_SHA256={lock_digest}");
    println!("cargo:rustc-env=CALYBRIS_BUILD_DIRTY={dirty}");
    println!("cargo:rustc-env=CALYBRIS_BUILD_IDENTITY_VERIFIED={identity_verified}");
}

fn source_digest(root: &Path, tree: &str, dirty: bool) -> String {
    if !dirty && is_hex(tree, 40) {
        return tree.to_owned();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"calybris.worktree.v1\0");
    hasher.update(tree.as_bytes());
    if let Some(diff) = git_bytes(root, &["diff", "--binary", "HEAD", "--"]) {
        hasher.update((diff.len() as u64).to_le_bytes());
        hasher.update(diff);
        if let Some(untracked) =
            git_bytes(root, &["ls-files", "--others", "--exclude-standard", "-z"])
        {
            bind_untracked(root, &mut hasher, &untracked);
        }
    } else {
        bind_source_manifest(root, &mut hasher);
    }
    encode_hex(&hasher.finalize())
}

fn bind_untracked(root: &Path, hasher: &mut Sha256, untracked: &[u8]) {
    for path in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path);
        if let Ok(path) = std::str::from_utf8(path) {
            let bytes = std::fs::read(root.join(path)).unwrap_or_default();
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
    }
}

fn bind_source_manifest(root: &Path, hasher: &mut Sha256) {
    let mut files = Vec::new();
    for name in ["Cargo.toml", "Cargo.lock", "build.rs", "pyproject.toml"] {
        let path = root.join(name);
        if path.is_file() {
            files.push(path);
        }
    }
    for name in [
        "src",
        "bindings/python",
        "python/calybris",
        "scripts",
        "tests",
        "proptest-regressions",
    ] {
        collect_source_files(&root.join(name), &mut files);
    }
    files.sort();
    for path in files {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let name = relative.to_string_lossy().replace('\\', "/");
        let bytes = std::fs::read(&path).unwrap_or_default();
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
}

fn collect_source_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let denied = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    matches!(name, "target" | "dist" | "work" | "__pycache__")
                        || name.starts_with(".pytest")
                        || name.ends_with(".egg-info")
                });
            if !denied {
                collect_source_files(&path, files);
            }
        } else if path.is_file() {
            let denied = path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|ext| {
                    matches!(
                        ext.to_ascii_lowercase().as_str(),
                        "pyd" | "pdb" | "dll" | "so" | "dylib" | "whl" | "pyc"
                    )
                });
            if !denied {
                files.push(path);
            }
        }
    }
}

fn git_bytes(root: &Path, arguments: &[&str]) -> Option<Vec<u8>> {
    Command::new("git")
        .arg("-c")
        .arg(format!("safe.directory={}", root.display()))
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout)
}

fn git(root: &Path, arguments: &[&str]) -> Option<String> {
    Command::new("git")
        .arg("-c")
        .arg(format!("safe.directory={}", root.display()))
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn release_env(name: &str) -> Option<String> {
    std::env::var(format!("CALYBRIS_RELEASE_{name}"))
        .ok()
        .filter(|value| !value.is_empty())
}

fn cargo_vcs_commit(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join(".cargo_vcs_info.json")).ok()?;
    let marker = "\"sha1\"";
    let start = text.find(marker)? + marker.len();
    let remainder = &text[start..];
    let quote = remainder.find('"')? + 1;
    let candidate = remainder.get(quote..quote + 40)?;
    is_hex(candidate, 40).then(|| candidate.to_owned())
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode_hex(input: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}
