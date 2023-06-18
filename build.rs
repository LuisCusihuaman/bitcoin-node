fn main() {
    glib_build_tools::compile_resources(
        &["src/wallet/resources"],
        "src/wallet/resources/resources.gresource.xml",
        "wallet-rustica.gresource",
    );
}
