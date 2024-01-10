extern "C" {
    fn syft_main();
}

pub fn syft_export() {
    unsafe {
        syft_main();
    }
}
