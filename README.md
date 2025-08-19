# SM3.NET
![License](https://img.shields.io/badge/license-MIT-blue.svg)

Pure C# implementation of the SM3 (ShangMi 3) cryptographic hash algorithm (GBT.32905-2016).

## Features
- 100% managed code with no dependencies
- Implements full SM3 specification (GBT.32905-2016)
- Optimized with unsafe code and stack allocation
- Tested against official test vectors
- Simple API: single static method
- Cross-platform: Windows, Linux, macOS

## Usage
```csharp
byte[] data = Encoding.UTF8.GetBytes("abc");
byte[] hash = SM3.ComputeHash(data); // 66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0

string hexHash = SM3.ComputeHash("hello, world"); // 02DF30DFF15F2CCB72BFFDCB44E68D4D09974036DC7A6927E556FBEF421C7F34
```
