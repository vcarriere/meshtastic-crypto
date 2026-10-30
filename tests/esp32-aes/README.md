Run `sh tests/esp32-aes/run.sh` with a C++11 compiler and OpenSSL development headers/library.

These host tests exercise the actual ESP32 adapter against a typed SDK substitute using
OpenSSL ECB, including [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
F.1.1 and F.1.5 vectors. The substitute deliberately changes context size, alignment,
field positions and mode constants, and rejects AES-192 as ESP32-S3 does.
Both SDK header locations and the no-decrypt build are tested with optimization and LTO.

This verifies adapter behavior, not Espressif's AES implementation, interrupts or a physical chip.
An optimized target build and hardware known-answer tests are separate checks.
