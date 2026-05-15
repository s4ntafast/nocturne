# nocturne

Named after one of my favorite games, "nocturne" is a bin2bin x86-64 PE code virtualizer and binary rewriter.

# Features
* Native Call Bridge
* 30+ VM Handlers
* Built-in junk code obfuscation
* Thread-safe per-invocation VM state

# Usage
To use the Nocturne virtualizer, copy and include "nocturne_sdk.hpp" from `core/` into your project.

```cpp
#include "nocturne_sdk.hpp"

VIRTUALIZE int secret(int x) {
	if (x % 2 == 0) {
		return x / 2;
	} else {
		return x * 3 + 1;
	}
}
VIRTUALIZE_MARK(secret);
```
Afterwards, run the virtualizer executable.
```bash
cli.exe <input.exe> <output.exe> auto
```
Example:
```bash
cli.exe example.exe example_protected.exe auto
```
Or, you if you want to virtualize specific segments of a binary without the SDK:
```bash
cli.exe <input.exe> <output.exe> <start_rva> <function_size>
```
Example:
```bash
cli.exe calc.exe calc_vmp.exe 0x1600 0x264
```

# Screenshots
Before Virtualization:
<img width="999" height="656" alt="image" src="https://github.com/user-attachments/assets/7b035cf6-b0e8-4db3-badf-0597e9a5bf33" />

After Virtualization:

<img width="633" height="230" alt="image" src="https://github.com/user-attachments/assets/bbeaa4d1-60d3-4001-9540-3ab6cc8230b3" />


Obfuscated dispatcher loop:
<img width="1200" height="600" alt="image" src="https://github.com/user-attachments/assets/fff1a19e-8d60-40ee-92c4-099fce60d1d9" />

# Dependencies
```
LIEF
Zydis
```

# Disclaimer
First and foremost, this is mostly a POC project. Please don't expect it to be **too** stable. With that being said, I will be progressively adding more features/fixes to this as time goes on.
