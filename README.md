# ASP.NET Core Data Protection in Python

This module implements a subset of [ASP.NET Core Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction) in Python. Specifically it supports Unprotecting (decrypting) data Protected (encrypted) with `AES_256_CBC` and `HMACSHA256` keys.

This implementation was in support of a larger research project, documented in a [blog post](https://research.ivision.com/bitwarden-server-hashcat-plugin-3-dataprotection) (see also the [introductory post](https://research.ivision.com/bitwarden-server-hashcat-plugin-1-bitwarden)). This library is research-quality code and is not suitable for production usage. The code is released under an MIT license; we will link to a maintained fork if you create one.
