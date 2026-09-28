fn main() {
    // Windows 10 1903+：把进程 ANSI 代码页固定为 UTF-8，中文日志才不会被当成 GBK。
    // 仅设 SetConsoleOutputCP 不够（管道重定向 / 部分终端仍按系统代码页解码）。
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        use embed_manifest::{embed_manifest, new_manifest};
        use embed_manifest::manifest::ActiveCodePage;
        embed_manifest(new_manifest("gateway-proxy").active_code_page(ActiveCodePage::Utf8))
            .expect("嵌入 Windows UTF-8 manifest 失败");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
