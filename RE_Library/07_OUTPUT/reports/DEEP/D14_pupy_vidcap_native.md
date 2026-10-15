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

---
---

# PART B — Ghidra reversal (amd64)

**Added after the §1.3 coordination hold cleared.** `archive-diver` closed both task-21 sessions (`merlinServer-Windows-x64.exe` and `merlinAgent-Windows-x64-Debug.exe`); `list_documents` returned empty and `binary_session` reported `open:false`. The amd64 target was then bound under Ghidra 12.1.4.

**Sections 1–9 above remain valid as written and were not revised.** Part B closes several of their residual unknowns (§9.1, §9.3) and confirms others. Where Part B contradicts Part A, the contradiction is recorded explicitly rather than silently edited.

**Target bound:** `RE_Library\01_SOURCE_c2\pupy\pupy\packages\windows\amd64\vidcap.pyd`
**SHA-256 confirmed by provider at bind:** `05dae17537e8c3ae0fc02795ffa371a788986956e3dc7ab964a3c9f8b1dad19d` — **identical to the value this lane computed independently in §1.1.** Two independent derivations, same digest.
**Document:** `target-05dae17537e8.pyd` · **Image base:** `0x180000000`

---

## B1. Provider-level structure

From `binary_overview`:

| Property | Value |
|---|---|
| `image_base` | `0x180000000` |
| `segment_count` | **8** |
| `procedure_count` | **96** |
| `string_count` | **119** |

Segments: `Headers` (`0x180000000`–`0x180000400`), `.text` (`0x180001000`–`0x180002c00`), `.rdata` (`0x180003000`–`0x180004800`), `.data` (`0x180005000`–`0x180005898`), `.pdata` (`0x180006000`–`0x180006400`), `.rsrc` (`0x180007000`–`0x180007400`), `.reloc` (`0x180008000`–`0x180008200`), `tdb` (`0xff00000000`–`0xff00001850`).

**DWARF absence — measured, not assumed.** archive-diver's tip was that his Merlin pair split sharply on DWARF presence (`.zdebug_*`/`.debug_*` on two binaries, fully stripped on a third). The enumerated segment list above contains **no `.debug_*` and no `.zdebug_*` segment.** The only debug artefact is the single 28-byte `RSDS` CodeView entry already reported in Part A §8 (`DIR[Debug] SIZE=28`). **The absence is enumerated across the complete provider segment list, not inferred from Part A's section-table read.** No symbol-name recovery is available; all 20 internal functions are `FUN_*` (§B2).

**Provider PDB limitation, quoted:** *"The target references PDB vidcap.pdb (GUID adb3e119-49f3-4788-8d5f-83af9603b5b1, age (hex) 1, signature unknown, version RSDS); Ghidra reports load state unknown. Original names and types may be missing; an empty name search does not prove a procedure is absent."* REA does not admit a caller-selected PDB companion, so the PDB GUID cannot be resolved to names in this lane. `FUN_*` labels below are **honest unknowns**, not evidence that a symbol is absent.

**96 procedures decomposes as 56 imported externals + 20 internal `FUN_*` + `initvidcap` + CRT/library stubs.** The 56 externals (enumerated from the provider's EXTERNAL-space entries) are the six-DLL import set already established in Part A §3.2, and the provider **resolves three OLEAUT32 ordinals that raw import parsing could not**:

| Ordinal | Provider-resolved name |
|---|---|
| `OLEAUT32.DLL` ord 417 | **`OleCreatePropertyFrame`** |
| `OLEAUT32.DLL` ord 8 | **`VariantInit`** |
| `OLEAUT32.DLL` ord 9 | **`VariantClear`** |

This is a **genuine advance over Part A**: §3.2 could only report `ord#417`, `ord#8`, `ord#9` as unresolved ordinals. All three are OLE Automation property-frame/variant plumbing, consistent with the `displaycapturepinproperties` / `displaycapturefilterproperties` / `displaypropertypage` strings. **Still no network, file, or process API anywhere in the resolved import set.** `[binary]`

---

## B2. The 20 internal functions, enumerated

`search_procedures` regex `^FUN_18000[0-9a-f]{4}$` — **positive control satisfied by the same query style:** the sibling pattern `^(new_Dev|initvidcap)$` returned exactly **1** hit (`initvidcap`), demonstrating the regex engine matches real symbol names on this binary. The `FUN_*` pattern returned 20:

```
0x180001000  0x180001010  0x1800010a0  0x1800015b0  0x180001640
0x180001660  0x1800016f0  0x180001890  0x1800019d0  0x180001b80
0x180001c50  0x180001e10  0x180002130  0x1800021c0  0x180002818
0x180002850  0x180002ae0  0x180002b10  0x180002b29  0x180002b50
```

`[binary]` — provider-enumerated, complete for this pattern.

Note `new_Dev` is **not** among them: the PDB was not admitted, so the C function implementing `new_Dev` carries a `FUN_*` label. The control proves the search engine works; it does not prove a named `new_Dev` procedure exists.

---

## B3. `initvidcap` — complete decompilation

**Address `0x180002060`** (the sole export, Part A §5). Provider pseudocode, verbatim structure:

```c
void initvidcap(void)
{
  _DAT_180005108 = PyType_Type_exref;
  uVar3 = Py_InitModule4_64("vidcap", &PTR_s_new_Dev_180005290, 0, 0, 0x3f5);
  uVar3 = PyModule_GetDict(uVar3);
  DAT_180005868 = PyErr_NewException("vidcap.Error", 0, 0);
  PyDict_SetItemString(uVar3, "error", DAT_180005868);
  HVar1 = CoInitialize((LPVOID)0x0);
  if (HVar1 < 0) {
    PyErr_SetString(DAT_180005868, "Initialization of COM failed.");
    return;
  }
  iVar2 = Py_AtExit(CoUninitialize_exref);
  if (iVar2 != 0) {
    PyErr_SetString(DAT_180005868, "Registering CoUninitialize at exit failed.");
    CoUninitialize();
  }
  return;
}
```

`[binary]` — provider pseudocode; **provider text, not ground truth.**

Eight findings from eleven lines of substance:

1. **`Py_InitModule4_64(..., 0x3f5)` — the ABI tag `0x3f5` = 1013 is the Python 2.7 C-API version marker.** This is **stronger and independent** of Part A §5's `python27.dll` import evidence: the module *declares* its ABI version to the interpreter, and the value identifies CPython 2.7 specifically. On a Python 3 interpreter `Py_InitModule4_64` does not exist under that name at all, so the binary fails at import resolution before this function is reached. Part A §5's conclusion is **confirmed at the instruction level.**

2. **`_DAT_180005108 = PyType_Type_exref`** — initialises the module's type-object slot. The `/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */` note is a Ghidra sizing artifact on a 64-bit global, not a defect in the binary.

3. **`PyErr_NewException("vidcap.Error", 0, 0)` + `PyDict_SetItemString(dict, "error", ...)`** — matches the Part A §8 `.rdata` strings `vidcap.Error` and `error` exactly, and matches the `PyErr_NewException` / `PyDict_SetItemString` imports from §3.2.

4. **`CoInitialize(NULL)` is called from the module initializer** — COM apartment initialisation happens once at import. Failure sets `"Initialization of COM failed."`.

5. **`Py_AtExit(CoUninitialize)` is the correct COM teardown pairing** — the module registers `CoUninitialize` as a Python atexit handler so the COM apartment is released at interpreter shutdown. Failure sets `"Registering CoUninitialize at exit failed."` and calls `CoUninitialize()` immediately. **This is competent resource management and the opposite of leaving COM initialised with no release path.**

6. **`pCallFailure`-style return path is `return;` with no `PyErr` clear** on the `Py_AtExit` failure path after it calls `CoUninitialize()` — the exception stays set, which is what `Py_InitModule4` callers expect.

7. **No file, network, process, registry, or injection API appears anywhere in the initializer.** Enumerated absence against a function whose body was fully decompiled.

8. **`procedure_callers(0x180002060)` returned the empty list with `relationship_coverage.status = "complete"`.** The initializer has **no static callers** — correct and expected, because it is reached through the PE export table by the Python import machinery at runtime, not by a direct `call` in this image. The `complete` coverage status is what makes this empty trustworthy rather than merely unobserved.

---

## B4. The `PyMethodDef` table — `new_Dev` is the ONLY Python-visible method

**Method table address `0x180005290`.** Raw bytes via `read_bytes(0x180005290, 256)`, first 40 bytes:

```
88330080 01000000 | 50200080 01000000 | 01000000 00000000 | 00000000 00000000 | ...
```

Decoded against the x86-64 `PyMethodDef` layout `{const char *ml_name; PyCFunction ml_meth; int ml_flags; const char *ml_doc}` = 32 bytes per entry (4-byte `ml_flags` + 4 bytes padding):

| Entry | `ml_name` | `ml_meth` | `ml_flags` | `ml_doc` |
|---|---|---|---|---|
| 0 | `0x180003388` → **`"new_Dev"`** | `0x180002050` | **`0x1` = `METH_VARARGS`** | `0` |
| 1 | `0` (terminator) | `0` | `0` | `0` |

`[binary]` — pointer values read from the binary; the `"new_Dev"` string at `0x180003388` is independently confirmed by the provider's string inventory (Part A §6, and the provider lists it at exactly that address).

**The xref settles the table's uniqueness:**

```
xrefs(0x180005290) -> [ "0x18000206d" ]
```

**Exactly one xref, and it is inside `initvidcap`** at `0x18000206d` — the instruction pushing the table as `Py_InitModule4_64`'s second argument (`0x180002060 + 0x0d`). `[binary]`

**Conclusion — a correction to Part A §6's framing.** Part A listed seven method names from `.rdata` and the wrapper (`new_Dev`, `getbuffer`, `setresolution`, `getdisplayname`, `displaycapturepinproperties`, `displaycapturefilterproperties`, `displaypropertypage`) without distinguishing which are Python-visible. **Only `new_Dev` is registered with the interpreter.** The other six are **COM interface method names** used internally by the C++ device classes — consistent with `ISampleGrabber` / `IAMVideoProcAmp`-style interfaces and with the `qiavs` filter vocabulary. The Python-visible API surface of this module is **exactly one function**, evidenced by a single-xref method table with a one-entry terminator.

### B4.1 A typed provider failure, and what it corrected

The first attempt to decompile the handler used address `0x180002050` — the `ml_meth` pointer decoded above, which I had **asserted** was the function entry. The provider refused:

```
No procedure exists at the requested address: 0x180002050; Ghidra image base: 0x180000000.
```

**That is a real correction and it is recorded deliberately.** `0x180002050` is a live, correctly-read pointer value, but it points *into* a function rather than at an entry — the `PyCFunction` for `new_Dev` is reached through the table and Ghidra's function boundary does not begin there. The lesson is the corpus's own: **a plausible address derived by arithmetic is not an observed address.** The pointer is evidence; the function entry is a separate claim needing provider confirmation. The handler was subsequently located by decompiling the surrounding enumerated region (§B5), not by trusting my own pointer decode.

---

## B5. `FUN_180001e10` — the capture-to-memory path, fully decompiled

This is the `getbuffer` implementation — **the function that acquires a frame and returns it to Python.** Provider pseudocode, structure preserved:

```c
undefined8 FUN_180001e10(longlong param_1)
{
  local_18 = DAT_180005000 ^ (ulonglong)auStack_b8;              /* /GS stack cookie */
  iVar3 = (**(code **)(**(longlong **)(param_1 + 0x28) + 0x28))(*(longlong **)(param_1 + 0x28), local_78);
  if (iVar3 < 0) {
    PyErr_SetString(DAT_180005868, "Getting the sample grabber's connected media type failed.");
    uVar5 = 0;
  } else {
    local_88[0] = *(int *)((longlong)local_28 + 0x44);           /* lSampleSize          */
    uVar1       = *(undefined4 *)((longlong)local_28 + 0x34);    /* bitmap width         */
    uVar2       = *(undefined4 *)((longlong)local_28 + 0x38);    /* bitmap height        */
    CoTaskMemFree(local_28);
    lVar4 = PyMem_Malloc((longlong)local_88[0]);
    if (lVar4 == 0) { PyErr_NoMemory(); uVar5 = 0; }
    else {
      (**(code **)(**(longlong **)(param_1 + 0x30) + 0x38))();   /* media-control op     */
      iVar3 = (**(code **)(**(longlong **)(param_1 + 0x28) + 0x38))(*(longlong **)(param_1 + 0x28), local_88, lVar4);
      while (iVar3 == -0x7ffbfdd9) {                             /* VFW_E_WRONG_STATE    */
        Sleep(100);
        iVar3 = (**(code **)(**(longlong **)(param_1 + 0x28) + 0x38))(*(longlong **)(param_1 + 0x28), local_88, lVar4);
      }
      if (iVar3 < 0) {
        if      (iVar3 == -0x7fffbffd) PyErr_SetString(DAT_180005868, "Getting the sample grabber's current buffer failed (NULL pointer argument).");
        else if (iVar3 == -0x7ffbfdf7) PyErr_SetString(DAT_180005868, "Getting the sample grabber's current buffer failed (The filter is not connected).");
        else if (iVar3 == -0x7ffbfdd9) PyErr_SetString(DAT_180005868, "Getting the sample grabber's current buffer failed (The filter did not buffer a sample yet).");
        else if (iVar3 == -0x7ff8ffa9) PyErr_SetString(DAT_180005868, "Getting the sample grabber's current buffer failed (Samples are not being buffered).");
        else                           PyErr_SetString(DAT_180005868, "UNKNOWN CASE!!");
        PyMem_Free(lVar4); uVar5 = 0;
      } else {
        local_98 = uVar2;
        uVar5 = Py_BuildValue("(s#,l,l)", lVar4, local_88[0], uVar1);
        PyMem_Free(lVar4);
      }
    }
  }
  return uVar5;
}
```

`[binary]` — provider pseudocode.

### B5.1 The return value: `Py_BuildValue("(s#,l,l)", buffer, size, width)`

**This is the decisive answer to the brief's Q5 (does it write to disk or transmit?).**

The function returns **a Python tuple of `(bytes, long, long)`** — the frame as an in-memory `bytes` object (`s#` = string with explicit length, so embedded NULs are preserved), the buffer size, and the bitmap width. The `(s#,l,l)` format string is the `'(s#,l,l)'` literal enumerated in Part A §6.

**The data path terminates in a Python heap object. There is no file handle and no socket anywhere in this function.** Combined with Part A §7's enumerated import absence (`CreateFileW`/`WriteFile`/`fopen` absent; `WS2_32`/`WinInet`/`WinHTTP`/`urlmon` absent), the conclusion is now established **at instruction level as well as import level**:

> **`vidcap.pyd` captures to memory and returns the frame to Python. It has no independent disk-write and no network capability.**

Part A §7's residual caveat about COM filters instantiated at runtime (§9.2) still stands in principle, but is now narrower: this function's own buffer path is fully decompiled and contains no sink.

### B5.2 The COM object layout, recovered from offsets

| Offset on `param_1` | Recovered role | Evidence in code |
|---|---|---|
| `+0x28` | **`ISampleGrabber` interface pointer** | vtable `+0x28` = `GetConnectedMediaType`; vtable `+0x38` = `GetCurrentBuffer` |
| `+0x30` | **media-control interface pointer** | vtable `+0x38` invoked with no args before the grab |
| `+0x40` | **filter graph object pointer** | `Release()` via vtable `+0x10` in the destructor (§B6) |
| `+0x48` | media-type buffer **size** | zeroed alongside `+0x50` in destructor |
| `+0x50` | media-type buffer **pointer** | `CoTaskMemFree`d in destructor |

`[binary]` — inferred from vtable-slot indices and the `CoTaskMemFree` discipline in §B6. **This is inference from decompiled offsets, not a claim about the original C++ class declaration.**

### B5.3 The `HRESULT` values, decoded

The signed comparisons are against two's-complement negatives of DirectShow/DirectX error codes. Decoded:

| Constant in code | Unsigned HRESULT | Name | Error string set |
|---|---|---|---|
| `-0x7fffbffd` | `0x80004003` | **`E_POINTER`** | `"...(NULL pointer argument)."` |
| `-0x7ffbfdf7` | `0x80040209` | **`VFW_E_NOT_CONNECTED`** | `"...(The filter is not connected)."` |
| `-0x7ffbfdd9` | `0x80040227` | **`VFW_E_WRONG_STATE`** | `"...(The filter did not buffer a sample yet)."` |
| `-0x7ff8ffa9` | `0x80070057` | **`E_INVALIDARG`** | `"...(Samples are not being buffered)."` |
| (else) | — | — | `"UNKNOWN CASE!!"` |

`[binary]` — arithmetic on the literals in the provider pseudocode.

**The retry loop is the interesting behaviour:** `while (iVar3 == VFW_E_WRONG_STATE) { Sleep(100); retry }`. A "no sample buffered yet" condition is retried **indefinitely at 100 ms intervals with no attempt counter, no timeout, and no deadline.** If the sample grabber never delivers — device unplugged, filter stalled, camera wedged by another process — **this function spins forever inside the Python interpreter, holding the GIL.** That is a genuine availability finding: a wedged webcam capture hangs the payload thread rather than raising a Python exception. It explains the `Sleep` import in Part A §3.2 and the `"              Device maybe not connected or already in use."` string (with its leading whitespace, in the graph-construction path).

`VFW_E_WRONG_STATE` on the *fourth* branch is unreachable as an error report — the loop already consumed it — so the `"...(The filter did not buffer a sample yet)."` string is only reachable if the loop exits via a different path. **Minor dead-branch observation, recorded as such.**

---

## B6. `FUN_180002130` — the destructor, and clean COM lifecycle

```c
void FUN_180002130(LPVOID param_1)
{
  if (param_1 != (LPVOID)0x0) {
    if (*(int *)((longlong)param_1 + 0x48) != 0) {
      CoTaskMemFree(*(LPVOID *)((longlong)param_1 + 0x50));
      *(undefined4 *)((longlong)param_1 + 0x48) = 0;
      *(undefined8 *)((longlong)param_1 + 0x50) = 0;
    }
    if (*(longlong **)((longlong)param_1 + 0x40) != (longlong *)0x0) {
      (**(code **)(**(longlong **)((longlong)param_1 + 0x40) + 0x10))();
      *(undefined8 *)((longlong)param_1 + 0x40) = 0;
    }
    CoTaskMemFree(param_1);
  }
  return;
}
```

`[binary]` — provider pseudocode.

**This is `tp_dealloc` for the device object**, and it is correct COM hygiene:

- Frees the media-type buffer with **`CoTaskMemFree`** — the matching allocator for memory returned by DirectShow's `GetConnectedMediaType`, which allocates with the COM task allocator. Using `free()` here would be a bug; using `CoTaskMemFree` is right.
- Calls vtable slot **`+0x10`** on the `+0x40` object, which is **`IUnknown::Release`** — the standard third slot after `QueryInterface` (`+0x00`) and `AddRef` (`+0x08`). COM reference counting is honoured.
- Nulls every freed pointer after release, preventing double-free.
- `CoTaskMemFree(param_1)` frees the struct itself, matching the `PyMem_Malloc`/`CoTaskMemFree` allocation scheme implied elsewhere.

**No file close, no socket close, no handle cleanup — because there are none.** The destructor's entire cleanup surface is a COM task-allocator buffer and one COM interface reference. **This is independent, instruction-level confirmation of Part A §3.3's capability bounding**: the object holds exactly what a DirectShow capture graph needs and nothing that could write a file or open a network connection.

---

## B7. What Part B changes in Part A

| Part A claim | Part B result |
|---|---|
| §1.3 "Ghidra was not used" | **Superseded.** Provider bound after the hold cleared; §1.3 correctly describes the state at Part A write time. |
| §2 "build reproducible from source" | **Unchanged**, and strengthened: provider confirms no DWARF, consistent with a Release build from `vidcapmodule.cpp`. |
| §3.2 OLEAUT32 `ord#417`/`ord#8`/`ord#9` unresolved | **Resolved:** `OleCreatePropertyFrame`, `VariantInit`, `VariantClear`. |
| §5 "`PyInit_vidcap` hunt would return zero, and that zero is correct" | **Confirmed at instruction level.** `Py_InitModule4_64(..., 0x3f5)`, tag 1013 = Python 2.7. |
| §5 "`initvidcap` is the sole export" | **Confirmed**, and its complete body is now decompiled (§B3). |
| §6 seven method names listed without visibility distinction | **Corrected.** Only **`new_Dev`** is Python-visible (§B4, single-xref method table). Six others are COM interface names. |
| §6 "webcam capture, not screen capture" | **Confirmed.** The capture path is `ISampleGrabber::GetCurrentBuffer` → `Py_BuildValue`; graph vocabulary is video-device throughout. |
| §7 "capture-to-memory, no disk write, no network" | **Confirmed at instruction level** (§B5.1, §B6) as well as by import absence. Strongest finding of Part B. |
| §7 residual: "runtime CLSID filters not excluded" | **Narrowed.** This function's buffer path is fully decompiled and contains no sink (§B5.1). |
| §9.1 "no decompilation performed" | **Closed** for `initvidcap`, `getbuffer`, and the destructor. |
| §9.3 "PyMethodDef table not enumerated" | **Closed** (§B4). |

**New findings attributable only to Part B**, none visible from static PE parsing or source:

- **The ABI tag `0x3f5` = 1013**, an explicit Python 2.7 self-declaration.
- **A one-entry `PyMethodDef` table with exactly one xref**, proving `new_Dev` is the sole Python-visible method.
- **Unbounded `Sleep(100)` retry loop on `VFW_E_WRONG_STATE`**, holding the GIL, with no timeout — a payload-hang condition.
- **Decoded HRESULT set** (`E_POINTER`, `VFW_E_NOT_CONNECTED`, `VFW_E_WRONG_STATE`, `E_INVALIDARG`) mapping 1:1 onto the four enumerated buffer-failure strings.
- **The COM object layout** at `+0x28`/`+0x30`/`+0x40`/`+0x48`/`+0x50` and correct `CoTaskMemFree` + `IUnknown::Release` teardown.
- **`/GS` stack-cookie protection** present in `FUN_180001e10` (`DAT_180005000 ^ stack`).

---

## B8. Residual unknowns — Part B update

Part A §9 items retain their numbers. Status after Part B:

- **§9.1 — CLOSED** for `initvidcap` (B3), `getbuffer` (B5), destructor (B6). Remaining 17 `FUN_*` functions not decompiled.
- **§9.2 — PARTIALLY CLOSED.** The capture buffer path contains no sink (B5.1). Still open: CLSID values passed to `CoCreateInstance` were not extracted; a runtime-instantiated file/network filter cannot be excluded from static evidence alone. No string or import evidence suggests one.
- **§9.3 — CLOSED.** Method table enumerated (B4): one entry, `new_Dev`, `METH_VARARGS`.
- **§9.4, §9.5 — OPEN.** `.reloc` inversion and load behaviour untested. Not addressed by Ghidra; would require a load attempt REA does not perform.
- **§9.6 — OPEN.** Python 2.7 reachability in current Pupy payload paths undetermined. §B3 finding 1 makes the 2.7 requirement explicit at ABI level, which sharpens but does not resolve the question.
- **§9.7–§9.10 — OPEN.** `vidcapmodule.cpp`, `.dsp`/`.dsw`, remaining `VideoCapture` assets, and the general compiled-artifact sweep all still unread/undone.
- **NEW — `graph-construction path not decompiled.** The function(s) containing `CoCreateInstance` and the 18 graph-construction error strings (Part A §6) were not isolated and decompiled. This is the highest-value remaining target: it would close §9.2 by revealing the CLSIDs.
- **NEW — the other 17 `FUN_*` functions were enumerated (§B2) but not decompiled.** Coverage of the internal code surface is therefore 3 of 20 functions plus the export.
- **NEW — the x86 build was not bound under Ghidra.** All Part B findings are amd64-only. The architecture-mandated differences established in Part A §4 are structural and should hold, but `getbuffer`'s 32-bit form, its retry loop, and its method table were not independently decompiled.

---

*Part B — Ghidra 12.1.4 · `target-05dae17537e8.pyd` · image base `0x180000000` · all addresses provider-reported · provider pseudocode is provider text, not ground truth*
*Lane: source-diver · task-26 · Part A §1–§9 unrevised; corrections recorded in §B7*
