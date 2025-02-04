# SHA256 Hash Digest Implementation

This project implements SHA256 hashing algorithm.

It consists of two directories:

- `lib` contains a version using external library [OpenSSL](https://openssl-library.org/)
- `nolib` contains a standalone implementation

`nolib` version supports printing context values for debugging with `-d` flag

## How to build

1. `nolib` version

You can just compile `sha.c` with `main.c` together. If you want to use CMake:

```bash
cmake -B build -S .
cmake --build build
```

2. `lib` version

Use CMake with [vcpkg](https://vcpkg.io) package manager:

```pwsh
cmake --preset=vcpkg
cmake --build out/build/vcpkg
```

You may also use any other package manager of your choice (including system package manager like `apt`). Configure it to handle `OpenSSL` dependency and use it with CMake.