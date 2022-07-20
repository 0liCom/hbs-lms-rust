# How to run this Rust code in pqm4

## Changes in Code

C-Bindings have been added in `src/lib.rs`, marked by comments.
Four functions performing the NIST-API mandated operations have been implemented.
External functions `hal_send_str` and `randombytes` are included as symbols for printing and generating random keys, but not essential for code operations.

By default, the code compiles with SHA256-256.
To change this, the `Hasher` type in `src/lib.rs` needs to be switched for some other Hasher from the `hasher` submodule before building the library.

Currently, the signed message is written in `do_crypto_sign` is exported as:
- 4 bytes signature size (little endian)
- the message
- the signature

This may not follow any standard definition, so consider changing this before using the C-bindings for interaction with other code.
Also, no proper security checks are implemented to validate the pointers or size values handed to the C-bindings.

## Building

Make sure, that an arm compiler toolchain is installed on your system.
The target `thumbv7em-none-eabihf` needs to be installed in rustup.
Do this with:
```bash
$ rustup target install thumbv7em-none-eabihf
```

Then run the Makefile to build the static library (as Release build):
```bash
$ make cortex_m4
```

This will place the library in
```
./target/thumbv7em-none-eabihf/release/libhbs_lms.a
```

## Setting up pqm4

Clone the pqm4-repository and install all the hardware-specific dependencies as described in the pqm4-Readme.
Before making any changes to the pqm4-codebase, build any other required testing binaries.
After making the following changes, the build process might no longer complete seamlessly or produce different binaries.

Start by copying the folder `hbs_lms_rust` from this repository into `pqm4/crypto_sign`.
This folder contains all the necessary C code to let pqm4 build a binary.
Always make sure the size limits defined in the Rust code (e.g., in `src/constants.rs`) match with those defined in `hbs_lms_rust/m4/api.h`.

Next, the linker needs to be instructed to link the code with the `libhbs_lms.a` library.
Do this adding the following line (with the correct path) to `pqm4/mk/crypto.mk`:
```makefile
LDLIBS += -lhbs_lms -L/path/to/libhbs_lms.a
```

Now run:
```bash
$ make -j4 PLATFORM=your-target-platform
```
with the target platform of your choice (e.g. `mps2-an386`) in the `pqm4` directory (no `make clean` required).
The ELF-binaries are built in the `pqm4/elf` directory.
This make command will likely fail for the `elf/crypto_sign_hbs_lms_rust_m4f_testvectors.elf` binary target because of an issue in the Rust toolchain.
If the other binaries (e.g., those with suffix "_stack" and "_hashing") compiled for `hbs_lms_rust`, you can ignore the issue.
Otherwise, re-run the make command, so that some dispatched child-process completes building these binaries.

Follow the `pqm4` Readme-instructions to execute the binaries.

To re-build the binaries, for example because you made some changes in the statically linked `libhbs_lms.a`, simply remove them from the `pqm4/elf` directory, e.g. using
```bash
$ rm elf/crypto_sign_hbs_lms_rust_m4f_*
```
and then re-run the make command.
Make sure, the path set in `pqm4/mk/crypto.mk` is still pointing to the correct library.
