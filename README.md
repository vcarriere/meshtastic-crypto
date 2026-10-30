Custom fork of rweather/Crypto to integrate with STM32 platform RNG

ESP32 adapter maintenance fork based on [meshtastic/Crypto](https://github.com/meshtastic/Crypto)
at `1c817c2f27aa4593e07d0f7e13b3dbf8d980bcae`, originally from
[Rhys Weatherley's Arduino Cryptography Library](https://github.com/rweather/arduinolibs).
Original Southern Storm Software copyright and MIT license notices remain in the source files.

The ESP32 AES adapter uses the SDK's context, declarations, lifecycle and mode constants.
Key setup reports SDK errors; AES-192 support depends on the chip. Non-ESP32 code is unchanged.
Host adapter tests are in `tests/esp32-aes`; they do not establish hardware operation.
