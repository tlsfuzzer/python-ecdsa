# Security Policy

## Supported Versions

Only the latest released version is supported.
Alpha and beta releases are always unsupported with security fixes.

The project uses semantic versioning, as such, minor version changes are API compatible.

| Version  | Supported          |
| -------- | ------------------ |
| 0.18.x   | :white_check_mark: |
| < 0.18   | :x:                |

## Support Scope

This library was not designed with security in mind. If you are processing data that needs
to be protected we suggest you use a quality wrapper around OpenSSL.
[`pyca/cryptography`](https://cryptography.io/) is one example of such a wrapper.
The primary use-case of this library is as a portable library for interoperability testing
and as a teaching tool.

**This library does not protect against side-channel attacks.**

Do not allow attackers to measure how long it takes you to generate a key pair or sign a message.
Do not allow attackers to run code on the same physical machine when key pair generation or
signing is taking place (this includes virtual machines).
Do not allow attackers to measure how much power your computer uses while generating the key pair
or signing a message. Do not allow attackers to measure RF interference coming from your computer
while generating a key pair or signing a message. Note: just loading the private key will cause
key pair generation. Other operations or attack vectors may also be vulnerable to attacks. 
For a sophisticated attacker observing just one operation with a private key will be sufficient
to completely reconstruct the private key.

Fixes for side-channel vulerabilities will not be developed.

Please also note that any Pure-python cryptographic library will be vulnerable to the same
side-channel attacks. This is because Python does not provide side-channel secure primitives
(with the exception of [`hmac.compare_digest()`](https://docs.python.org/3/library/hmac.html#hmac.compare_digest)),
making side-channel secure programming impossible.

This library depends upon a strong source of random numbers. Do not use it on a system
where `os.urandom()` does not provide cryptographically secure random numbers.

## Reporting a Vulnerability

If you find a security vulnerability in this library, you can report it using the "Report a vulnerability" button on the Security tab in github UI.
Alternatively, you can contact the project maintainer at hkario at redhat dot com.
