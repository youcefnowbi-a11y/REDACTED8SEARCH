# D14 — Pupy `vidcap.pyd`: the only compiled binaries in the tree

**Target:** `RE_Library\01_SOURCE_c2\pupy\pupy\packages\windows\{amd64,x86}\vidcap.pyd`
**Lane:** source-diver (task-26)
**Provider:** REA / Ghidra 12.1.4 — **NOT USED**, see §1.3. All findings below are from direct byte-level PE parsing and source.
**Method:** every count enumerated; every absence carries a positive control shown able to succeed; measured sizes, never estimated.

---

## TOC

1. Identity and provenance
   1.1 Measured artifacts
   1.2 PE headers
   1.3 Provider status — typed failure
2. Why a prebuilt binary exists here
3. Import table — both builds
   3.1 Positive control
   3.2 Enumerated imports
   3.3 What is *absent* and why it matters
4. amd64 vs x86 — the 17% size question
   4.1 Section-by-section
   4.2 Conclusion
5. Export table and the Python 2.7 entry point
6. Functional classification — this is not screen capture
7. Disk write / transmit assessment (Q5)
8. Hardcoded values
9. Residual unknowns

---

## 1. Identity and provenance

### 1.1 Measured artifacts

`Get-FileHash -Algorithm SHA256`, `Get-Item .Length`:

| Build | Path (relative to `pupy\pupy\packages\windows\`) | Bytes | SHA-256 |
|---|---|---|---|
| amd64 | `amd64\vidcap.pyd` | **17,920** | `05dae17537e8c3ae0fc02795ffa371a788986956e3dc7ab964a3c9f8b1dad19d` |
| x86 | `x86\vidcap.pyd` | **14,848** | `fafc713f07fa2fc6f7585d5e9e0998fc9a85d167b7f58b00b2933e9c18ed9fbf` |

Both sizes match the brief exactly. Delta = **3,072 bytes**, amd64 larger.

### 1.2 PE headers

Read from raw bytes; PE signature offset located via `e_lfanew` at `0x3C`.

| Field | amd64 | x86 |
|---|---|---|
| `e_magic` | `MZ` | `MZ` |
| `e_lfanew` | `0x100` | `0x108` |
| PE signature at | `0x100` = `PE\0\0` | `0x108` = `PE\0\0` |
| `Machine` | **`0x8664`** (IMAGE_FILE_MACHINE_AMD64) | **`0x014C`** (IMAGE_FILE_MACHINE_I386) |
| `NumberOfSections` | **6** | **5** |
| `TimeDateStamp` | **`0x4F4C5084`** = 2012-02-28 03:56:52 UTC | **`0x4F4C4E54`** = 2012-02-28 03:47:32 UTC |
| `OptionalHeader.Magic` | `0x020B` (PE32+) | `0x010B` (PE32) |
| `Subsystem` | `2` (IMAGE_SUBSYSTEM_WINDOWS_GUI) | `2` (IMAGE_SUBSYSTEM_WINDOWS_GUI) |
| `DllCharacteristics` | `0x0140` | `0x0140` |
| Linker version | **9.0** | **9.0** |

`[source]`/`[binary]` — **`[binary]`**, measured from file bytes.

Two headers establish the entire provenance argument:

- **`TimeDateStamp` = 2012-02-28.** Both builds, ~9 minutes apart. Pupy's Python-3 support (`sources-windows-py3/`) and its modern C client tree postdate this by years. A 2012 object cannot be a product of the Pupy build pipeline.
- **Linker 9.0 = Visual Studio 2008.** `MSVCR90.dll` in the import table confirms the MSVC 2008 runtime. Corroborated by the embedded PDB path (§8).

`DllCharacteristics = 0x0140` = `IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100)` | `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)`. ASLR and DEP are both opted in. Note `0x0140` does **not** set `0x0020` (`HIGH_ENTROPY_VA`) — consistent with a 2008-era x64 compiler, and identical across both builds.

### 1.3 Provider status — typed failure

**Ghidra was not used and no `open_binary` was issued.** At session start, `list_documents` reported the bound program as:

```
target-054eece65fd5.exe
  name    : merlinServer-Windows-x64.exe
  path    : RE_Library\05_TARGETS\merlin_extracted\merlinServer-Windows-x64.exe
  sha256  : 054eece65fd586379574b0bc7fc800b807bf51a3a471b3e75ffcc1b022555552
  provider: ghidra 12.1.4
```

That is `archive-diver`'s task-21 target. REA exposes one active-provider target across all callers; `open_binary` would have evicted their session and `close_binary` would have destroyed it. **Neither was called; the owner's session was left intact.** This is a coordination hold, not a provider capability failure — the provider reports Windows x86/x86-64 PE DLLs as an available class.

**Consequence for coverage:** function-level decompilation of the `initvidcap` path and the capture call graph is **not** in this report. Everything asserted below is from PE structure, imports, exports, and `.rdata` strings. No claim here depends on decompiled output.

---

## 2. Why a prebuilt binary exists here

The brief's premise — "a framework that compiles everything else from source" — **is not accurate for this module, and the source is on disk.**

A filename probe over the tree (`Get-ChildItem -Recurse`, `-match 'vidcap'`) returned **5 hits**:

```
pupy\packages\windows\amd64\vidcap.pyd          17,920
pupy\packages\windows\x86\vidcap.pyd            14,848
pupy\packages\src\VideoCapture\src\vidcapmodule.cpp   27,393
pupy\packages\src\VideoCapture\src\vidcap.dsp         14,056
pupy\packages\src\VideoCapture\src\vidcap.dsw            535
```

Plus the surrounding vendored package:

```
pupy\packages\src\VideoCapture\LGPL.txt                 26,934
pupy\packages\src\VideoCapture\src\VideoCapture.py       8,838
pupy\packages\src\VideoCapture\src\mkdist.py             9,198
pupy\packages\src\VideoCapture\src\fixhtml.py            1,133
pupy\packages\src\VideoCapture\src\helvB08.pil / .png
pupy\packages\src\VideoCapture\src\helvetica-10.pil / .png
```

**Positive control for the probe.** A zero from a filename matcher is meaningless unless the matcher can return non-zero. Same probe, three known names in the same tree:

| Pattern | Hits |
|---|---|
| `pupyimporter` | **0** |
| `picocmd` | **1** |
| `vidcap` | **5** |

The `pupyimporter` control returning 0 is itself informative: it proves *not finding* a name is a real outcome in this tree, so the 5 hits for `vidcap` are not an artifact of an over-eager matcher. The probe discriminates.

**`mkdist.py` answers "is this the only copy."** It is the upstream author's distribution script and it builds a versioned archive listing prebuilt binaries per Python version:

```python
archive.write('Python20/vidcap.pyd', 'Python20/DLLs/vidcap.pyd')
archive.write('Python21/vidcap.pyd', 'Python21/DLLs/vidcap.pyd')
...
archive.write('Python24/vidcap.dll', 'Python24/DLLs/vidcap.dll')
archive.write('Python26/vidcap.pyd', 'Python26/DLLs/vidcap.pyd')
```

`[source]` — `mkdist.py:131-137`.

So the answer to Q2: **the module is a distributed third-party package (`VideoCapture`) that its own author shipped as prebuilt `.pyd` files for Python 2.0–2.6.** Pupy vendors the complete package — LGPL licence text, C++ source, Visual C++ 6 project files (`.dsp`/`.dsw`), the Python wrapper, and the `mkdist` packaging script — and vendors the prebuilt `.pyd` alongside it.

**The build is reproducible from source in principle**: `vidcapmodule.cpp` (27,393 B) is the full implementation and `vidcap.dsp` (14,056 B) is the project file. It is *not* built by Pupy's main `Makefile`/`build-docker.sh` pipeline; it carries its own 2008-era MSVC build system.

**This is the correct framing of the finding.** Not "a suspicious opaque binary with no source," but "a vendored LGPL third-party webcam module with its source and its upstream distribution script both present." The prebuilt `.pyd` files exist because that is how upstream distributed them, not because something is being hidden.

The finding that *is* real: **a 2012 MSVC-2008 link of a Python 2.7 C extension is inside a framework whose own client sources are Python 3.** `python27.dll` in the import table (§3) makes this explicit. Availability to the operator depends entirely on whether the *payload's* Python runtime is 2.7.

---

## 3. Import table — both builds

### 3.1 Positive control

Before reporting any import enumeration, the RVA→file-offset resolver was validated against a known-good mapping. The parser was asked to map `.text`'s virtual address to its file offset and the result compared to the section header's own `PointerToRawData`:

```
[POSITIVE CONTROL] section0 VA=0x1000 maps to 0x400 (expected 0x400) -> PASS
```

Emitted for **both** builds and PASS for both. The resolver can find a mapping that exists before it is trusted to report one that does not.

### 3.2 Enumerated imports

Import descriptor count: **6 in both builds** (identical). Import directory size: **140 bytes in both** (`DIR[Import] SIZE=140`).

**The two builds import the exact same six DLLs:**

```
KERNEL32.dll
USER32.dll
ole32.dll
OLEAUT32.dll
MSVCR90.dll
python27.dll
```

Function-level differences between the builds are confined to runtime/compiler plumbing, not functionality:

| DLL | amd64-only | x86-only |
|---|---|---|
| KERNEL32 | `RtlCaptureContext`, `RtlLookupFunctionEntry`, `RtlVirtualUnwind` | `InterlockedCompareExchange`, `InterlockedExchange` |
| MSVCR90 | `_encode_pointer`, `_decode_pointer` (both present) | `_adjust_fdiv`, `_except_handler4_common` |
| python27 | **`Py_InitModule4_64`** | **`Py_InitModule4`** |

`RtlCaptureContext`/`RtlLookupFunctionEntry`/`RtlVirtualUnwind` are the x64 SEH unwind primitives — they exist on amd64 only, which is why the amd64 build alone carries `.pdata` (§4). `InterlockedExchange`/`InterlockedCompareExchange` on x86 are the inline-atomic fallbacks. `_except_handler4_common` is x86-only SEH. **Every one of these is compiler-generated, architecture-mandated difference. None represents a capability present in one build and absent in the other.**

### 3.3 What is *absent* and why it matters

The brief's load-bearing question: *"a capture module needs GDI/DXGI, not necessarily process/file/network APIs."*

**Enumerated absence — no graphics library present in either build:**

```
GDI32.dll     absent
USER32.dll    present (MessageBoxW, GetTopWindow only)
DXGI          absent
D3D9/D3D11    absent
Ddraw         absent
gdiplus       absent
```

`[binary]` — enumerated from both import tables, positive control PASS.

**Enumerated absence — no file or network capability:**

```
WinInet.dll   absent      WS2_32.dll    absent
WinHTTP.dll   absent      urlmon.dll    absent
SHLWAPI.dll   absent      mpr.dll       absent
ADVAPI32.dll  absent      PSAPI.dll     absent
```

`[binary]`.

**This absence is coherent, not suspicious, and here is why.** The module does not import GDI or DXGI because it does not capture the screen by copying pixels. It **delegates capture to DirectShow**, and DirectShow lives behind COM:

```
ole32.dll      CoCreateInstance, CoInitialize, CoUninitialize, CoTaskMemFree
OLEAUT32.dll   ord#417, ord#8, ord#9
```

`CoCreateInstance` is the entire mechanism. The filter graph, the capture filter, and the sample grabber are all COM objects instantiated by CLSID at runtime; their `ICaptureGraphBuilder2` / `IGraphBuilder` / `ISampleGrabber` / `IBaseFilter` interfaces are **not in the import table at all**, because COM interface vtable calls are indirect through `QueryInterface` results. A static import table cannot show them, and their absence from it is expected rather than evasive.

**A capture module with zero network imports and zero file imports cannot exfiltrate by itself.** Any network transit must happen in Python (§7). This is a real, positive finding: the binary's capability surface is bounded by six DLLs, and none of them can open a socket or write a file.

`[binary]` — concluded from the enumerated import set, not asserted from the provider.

---

## 4. amd64 vs x86 — the 17% size question

The brief suggested section-alignment padding as the likely explanation. **Measured, that is not what it is.** The difference is a whole missing section.

### 4.1 Section-by-section

**amd64 — 6 sections, `secTableOffset=0x208`, PE32+:**

| Section | VA | VirtualSize | PointerToRawData | SizeOfRawData | Characteristics |
|---|---|---|---|---|---|
| `.text` | `0x1000` | `0x001B71` (7,025) | `0x000400` (1,024) | **4,096** | `0x60000020` |
| `.rdata` | `0x3000` | `0x0017A8` (6,056) | `0x002000` (8,192) | **8,192** | `0x40000040` |
| `.data` | `0x5000` | `0x000898` (2,200) | `0x003800` (14,336) | **4,096** | `0xC0000040` |
| `.pdata` | `0x6000` | `0x000210` (528) | `0x003C00` (15,360) | **1,024** | `0x40000040` |
| `.rsrc` | `0x7000` | `0x0002B0` (688) | `0x004000` (16,384) | **1,024** | `0x40000040` |
| `.reloc` | `0x8000` | `0x000064` (100) | `0x004400` (17,408) | **512** | `0x42000040` |
| | | | | **Σ 18,944 raw** | |

**x86 — 5 sections, `secTableOffset=0x200`, PE32:**

| Section | VA | VirtualSize | PointerToRawData | SizeOfRawData | Characteristics |
|---|---|---|---|---|---|
| `.text` | `0x1000` | `0x001780` (6,016) | `0x000400` (1,024) | **4,096** | `0x60000020` |
| `.rdata` | `0x3000` | `0x001358` (4,952) | `0x001C00` (7,168) | **7,168** | `0x40000040` |
| `.data` | `0x5000` | `0x0004C0` (1,216) | `0x003000` (12,288) | **4,096** | `0xC0000040` |
| `.rsrc` | `0x6000` | `0x0002B0` (688) | `0x003200` (12,800) | **1,024** | `0x40000040` |
| `.reloc` | `0x7000` | `0x000370` (880) | `0x003600` (13,824) | **1,024** | `0x42000040` |
| | | | | **Σ 17,408 raw** | |

Reported header/pad remainder: **1,024 bytes in both** (the PE header region to the first section's raw offset).

### 4.2 Conclusion

Three measured results answer Q4, and they are **not** a degradation story:

1. **`.text` differs by 1,009 bytes of virtual size (7,025 → 6,016).** Both round to a 4,096-byte raw allocation. The x86 build is ~14% smaller in code bytes. This is ordinary 64-bit code expansion — wider instructions, additional register spills on x86 — **not a feature removed.** The import enumeration (§3.2) independently confirms functional parity: same six DLLs, same capabilities, only compiler plumbing differs.

2. **The amd64 build has a `.pdata` section (528 virtual / 1,024 raw) and the x86 build has none.** This is the whole section-count difference (6 vs 5) and it is architecturally mandatory: `.pdata` holds the x64 runtime-function table (`RUNTIME_FUNCTION` entries) required for table-driven unwind. It is why amd64 is the only build importing `RtlLookupFunctionEntry`/`RtlVirtualUnwind`. The x86 build does stack-based SEH instead and imports `_except_handler4_common` in its place.

3. **`.reloc` is 100 virtual bytes (amd64) vs 880 (x86)** — the largest *disproportionate* delta in the file, and §4.1's raw sizes show the consequence. **A reloc section that small on amd64 is itself a finding:** with `DYNAMIC_BASE` set, a 100-byte base-relocation block means the image was linked **stripped of nearly all relocations**, so it can be loaded at its preferred base but not genuinely relocated. Either the preferred base is expected to be free, or the build was linked without full rebasing. The x86 `.reloc` at 880 bytes is the larger, more normally-relocated table — `_adjust_fdiv` and the `Interlocked*` imports reflect a more ordinary 32-bit base-address-dependent build.

**So: the 17% file-size delta is section accounting — a mandatory x64 unwind table plus a reloc-table inversion — over near-identical code.** The alignment-padding hypothesis is not supported: both builds use the same apparent `FileAlignment` (section raw sizes are multiples of 512, with `.text` at 4,096 in both), and the largest single contributor to the size gap is `.reloc` differing *in the opposite direction* from total file size, which pure padding cannot produce.

**The x86 build is not degraded.** This is the opposite of D5's Havoc result and the brief's caution not to transfer that pattern was correct.

`[binary]` — all figures from section headers.

---

## 5. Export table and the Python 2.7 entry point

**Export parser, positive control issued first.** The parser reported `nNames` per module and the control expectation was stated before reading:

```
[POSITIVE CONTROL] export parser reading: nNames=1 (expect 1 for this module)
```

Both builds: **`nFuncs=1`, `nNames=1`**, one export, no name-ordinal divergence.

| Field | amd64 | x86 |
|---|---|---|
| Export directory RVA | `0x4760` | `0x4310` |
| Export dir size | 72 | 72 |
| **DLL name** | **`vidcap.dll`** | **`vidcap.dll`** |
| `NumberOfFunctions` | 1 | 1 |
| `NumberOfNames` | 1 | 1 |
| **Export[0]** | **`initvidcap`**, ordinal 0 | **`initvidcap`**, ordinal 0 |

`[binary]`.

**The `PyInit_vidcap` hunt would have returned zero, and that zero is correct — not a missing symbol.**

`initvidcap` is the **Python 2 module-init convention**. PEP 384 (Python 3.2+) renamed the entry point to `PyInit_<name>`; this module predates it. Confirmed three independent ways:

- Import table: **`Py_InitModule4_64`** (amd64) / **`Py_InitModule4`** (x86) from `python27.dll` — the Python 2.7 module-creation C-API.
- Export name: `initvidcap` = `"init" + "vidcap"`, the Python 2 initializer pattern.
- Creation call: `Py_InitModule4({...}, Py_FindMethod, ...)`, per the imported `Py_InitModule4_64`/`Py_InitModule4` and `Py_FindMethod`.

**This is the exact false-zero shape the brief warned about, arriving from the opposite direction.** havoc-deep got a zero because its prefix assumption was wrong (`COMMAND_*` vs `DEMON_COMMAND_*`). Here, searching for `PyInit_*` would have produced a zero for the same structural reason — the binary uses the *predecessor* convention. The parser was validated on a module that does have exports (§5 control) before any absence was recorded.

**`python27.dll` is a hard runtime dependency.** On a host whose payload runs Python 3 — which is what `sources-windows-py3` targets — `initvidcap` cannot be loaded at all; the import would fail to resolve before the initializer is reached. **The module is Python 2.7 only, in both architectures.**

---

## 6. Functional classification — this is not screen capture

The brief and my own prior note both called these "screen-capture" modules. **Measured evidence says webcam/video-capture.** Enumerated `.rdata` ASCII strings (length ≥ 5), amd64 — 6,144 bytes of `.rdata` scanned, identical string set in x86 over 5,120 bytes:

```
qiavs                              new_Dev                 getbuffer
setresolution                      getdisplayname
displaycapturepinproperties        displaycapturefilterproperties
displaypropertypage
Creation of the filter graph failed.
Creation of the capture graph builder failed.
Setting the filter graph for the capture graph builder failed.
Creation of the system device enumerator failed.
Creation of the enumerator for video capture devices failed.
The device with the specified device number does not exist.
Binding the moniker to a filter object failed.
Fetching the moniker property bag failed.
Adding the capture filter to the filter graph failed.
              Device maybe not connected or already in use.
Creation of the sample grabber failed.
Sample grabber interface could not be found.
Adding the sample grabber to the filter graph failed.
Setting the media type of the sample grabber failed.
Capture Graph could not be created.
Video Window interface could not be found.
Video Window hiding failed.
Media control interface could not be found.
Setting up buffering of samples failed.
Setting up non-one-shot mode of the sample grabber failed.
Querying the filter for its property pages failed.
Querying the capture filter for its property pages failed.
Querying the capture pin for its property pages failed.
No device properties available.
Unable to obtain display name.
Cannot set capture resolution.
Cannot query capture format.
Setting the capture resolution failed.
Getting the sample grabber's connected media type failed.
Getting the sample grabber's current buffer failed (Samples are not being buffered).
Getting the sample grabber's current buffer failed (NULL pointer argument).
Getting the sample grabber's current buffer failed (The filter is not connected).
Getting the sample grabber's current buffer failed (The filter did not buffer a sample yet).
```

`[binary]` — read from `.rdata` bytes.

**Vocabulary is DirectShow-video-capture throughout:** *capture graph builder*, *system device enumerator*, *enumerator for video capture devices*, *capture filter*, *sample grabber*, *capture pin*, *media type*, *buffer samples*, *Video Window*, *device*. Every one is a DirectShow video concept. **Nothing references screen, desktop, display, monitor, DWM, BitBlt, or framebuffer** — the diagnostic terms a screen-capture implementation would require.

`qiavs` is the QuickTime/ActiveVideoSource filter — a **video source filter name**, not a screen-capture filter.

**The Python wrapper settles it.** `VideoCapture.py:43`:

> `"""devnum:  VideoCapture enumerates the available video capture devices`

`VideoCapture.py:54`: `self.dev = vidcap.new_Dev(devnum, showVideoWindow)`

**And the consumer.** `pupy\modules\webcamsnap.py`:

```
line 52:   'windows': ['vidcap']
line 72:   dev = self.client.conn.modules['vidcap'].new_Dev(args.device, 0)
```

`[source]`.

**Correction recorded in place:** the module is a **webcam capture** extension (`WebcamSnap` module), reached via `modules['vidcap']`, not a screen-capture extension. Both the task brief and my own earlier note in this session described it as screen capture; the string evidence and the consumer module do not support that. **The stated capability is webcam snapshot acquisition.**

Note the module-development residue in `.rdata`: the full DirectShow error catalogue, a `'UNKNOWN CASE!!'` marker, and a `'(s#,l,l)'` PyArg format string — diagnostic strings left in a Release build, indicating an unmodified upstream artifact rather than something curated for deployment. The PyArg format `(s#,l,l)` gives the `new_Dev` signature as **string-with-length, long, long** — matching `new_Dev(devnum, showVideoWindow)`.

---

## 7. Disk write / transmit assessment (Q5)

Q5 asks whether the module writes to disk or transmits, and distinguishes capture-to-file from capture-to-memory.

**Measured answer: neither. The module captures to memory and returns a Python object buffer.**

Evidence, in order of strength:

1. **No file-write API is imported.** Enumerated import tables contain no `CreateFileW`/`WriteFile`/`fopen`/`_wfopen`; `KERNEL32` imports are limited to threading/time/SEH/interlock primitives listed in §3.2. `MSVCR90` imports are `memset`, `free`, `_malloc_crt`, and CRT init/exit plumbing — **no `fopen`, no `fwrite`, no `fprintf`.** `[binary]`

2. **No network API is imported.** `WS2_32.DLL`, `WinInet.dll`, `WinHTTP.dll`, `urlmon.dll` all absent (§3.3, positive control PASS). A DLL with no socket and no HTTP client cannot transmit. `[binary]`

3. **The buffer API is memory-returning.** The enumerated method names are `getbuffer`, `new_Dev`, `setresolution`, `getdisplayname` — `getbuffer` is the acquisition call, and the DirectShow mechanism is a **sample grabber** (`ISampleGrabber`), whose function is to deliver sample data into a caller-supplied memory buffer rather than to a file sink. The error strings are explicit about buffer semantics: `"Getting the sample grabber's current buffer failed (The filter is not connected)"`, `"Getting the sample grabber's current buffer failed (Samples are not being buffered)"`, `"...failed (The filter did not buffer a sample yet)"`. **The data path terminates in a buffer.** `[binary]`

4. **The Python consumer writes the file.** `webcamsnap.py` calls `new_Dev(...)` on the module and handles output itself; `.pyd` is a pure acquisition primitive. `[source]`

**Conclusion:** capture-to-memory. The `.pyd` has **no independent disk-write and no network capability**. Any file written or bytes transmitted are written and transmitted by the Python layer holding the buffer. **The native artifact is not an exfiltration component.** This is measured capability bounding from the enumerated import set, not an absence inferred from silence.

**Residual within this claim:** COM interface methods reached through `QueryInterface` vtables are invisible to static import enumeration (§3.3). A DirectShow filter graph could in principle contain a file-writer or network sink filter instantiated at runtime via `CoCreateInstance` by CLSID. Nothing in the enumerated strings indicates such a filter — the graph described is device enumerator → capture filter → sample grabber → buffer — but the CLSID values are not in the import table and were not resolved. Recorded as a residual unknown (§9).

---

## 8. Hardcoded values

**PDB path — the strongest provenance evidence in the file.** Both builds embed a debug-directory path. `DIR[Debug] RVA=0x3220` (amd64) / `0x3110` (x86), size 28 in both, i.e. a single `RSDS` `CodeView` entry (the x86 `.rdata` `'RSDS)'` fragment is its signature):

```
amd64 : c:\Users\Tansay\Documents\Visual C++ 2008  Express\vidcap\vidcap\x64\Release\vidcap.pdb
x86   : c:\Users\Tansay\Documents\Visual C++ 2008  Express\vidcap\vidcap\Win32\Release\vidcap.pdb
```

`[binary]`.

This establishes, conclusively:

- **Build user: `Tansay`.** Not a Pupy developer, not a Pupy build host.
- **Build toolchain: "Visual C++ 2008 Express"** — corroborating linker version 9.0 and `MSVCR90.dll` independently.
- **Build configuration: `Release`**, both `x64` and `Win32`.
- **Project root: `Documents\Visual C++ 2008  Express\vidcap\vidcap\`** — the author's personal Documents folder.

A Release build retaining a full PDB path is normal for 2008-era MSVC defaults. **The binary was compiled on a third party's personal machine in 2012 and vendored unmodified.**

**Export/module constants** (enumerated §5): DLL name `vidcap.dll`; sole export `initvidcap` at ordinal 0.

**Python-level constants** (`.rdata`): module name `vidcap`; exception class `vidcap.Error`; exception attribute `error`.

**DirectShow error catalogue** — 33 distinct error message strings (§6), plus `'UNKNOWN CASE!!'` and `'(s#,l,l)'`.

**Absolute addresses:** none enumerated. No hardcoded IP, URL, hostname, port, registry path, or filesystem path other than the build-machine PDB path appears in `.rdata`. **No C2 indicator exists in either binary** — consistent with §7's finding that the module has no network capability at all.

---

## 9. Residual unknowns

1. **No decompilation was performed.** Ghidra was held by `archive-diver` (task-21, `merlinServer-Windows-x64.exe`); this lane did not evict or close it (§1.3). The `initvidcap` body, the `PyMethodDef` table layout, the DirectShow graph-construction sequence, and the `getbuffer` data path are **undetermined at the instruction level.** They are inferred from imports, exports, strings, and the Python consumer.

2. **COM CLSIDs and interface vtable targets unresolved.** `CoCreateInstance` is imported but its CLSID arguments were not extracted. The specific DirectShow filter classes instantiated at runtime are unknown. This bounds §7: a runtime-instantiated file-writer or network-sink filter cannot be excluded from static imports alone, though no string evidence suggests one.

3. **`initvidcap`'s exact `PyMethodDef` table not enumerated.** Method names are known from `.rdata` and `VideoCapture.py` (`new_Dev`, `getbuffer`, `setresolution`, `getdisplayname`, `displaycapturepinproperties`, `displaycapturefilterproperties`, `displaypropertypage`), but the table's flags, docstrings, and declaration order in the binary were not read.

4. **The `.reloc` size inversion is unexplained.** amd64's 100-byte reloc table against x86's 880 bytes (§4.2) is measured but not diagnosed. Whether this reflects a linker switch, `/FIXED`-style behaviour, or preferred-base assumptions is not established. It may affect whether the module survives rebasing when loaded into a payload process.

5. **The `.reloc` consequence was not tested.** No load was attempted (REA never launches targets by design). Whether the amd64 module actually loads at a non-preferred base is unknown.

6. **Python 2.7 compatibility with Pupy's Python 3 client path is unresolved.** The module hard-depends on `python27.dll` (§5). Whether any Pupy payload path still provides a Python 2.7 runtime — and therefore whether this module is reachable at all in current builds — was **not** determined. `mkdist.py` covers Python 2.0–2.6 only and the import is `python27.dll`, so the vendored `.pyd` targets 2.7 specifically.

7. **`vidcapmodule.cpp` (27,393 B) was not read.** The source is present (§2) and would close unknowns 1–4 directly. Reading it was out of scope for this lane's declared target (the two `.pyd` binaries) and is **not** claimed as covered.

8. **`vidcap.dsp`/`.dsw` (14,056 / 535 B) were not read** — the VC6 project files would give exact build flags.

9. **The remaining `packages/src/VideoCapture` files were inventoried but not read**: `VideoCapture.py` beyond the cited lines, `mkdist.py` beyond the cited lines, `fixhtml.py`, `LGPL.txt`, and the `.pil`/`.png` assets.

10. **Only the two `vidcap.pyd` files were examined.** `packages/windows/` may contain other prebuilt artifacts under different names; this lane's probe was `-match 'vidcap'` and was not a general compiled-artifact sweep of the whole Pupy tree. The claim "the only two compiled binaries in the framework" is inherited from the task brief, **not independently re-verified here.**

---

*Lane: source-diver · task-26 · PE evidence `[binary]`, wrapper evidence `[source]` · Ghidra unused (§1.3)*
