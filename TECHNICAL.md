# Technical notes: GZW 0.5 ODIN voice on Wine/Proton

This document describes the exact failure, the two hooks, the tested builds,
and how to verify or extend the patch. It is aimed at people who want to
review the workaround, not at normal users. It documents tool version 1.1.0,
which adds automatic Steam/Proton prefix detection; see §2 for installation
and use.

---

## 1. Summary

Gray Zone Warfare 0.5's ODIN voice SDK creates an IPv4 (`AF_INET`) UDP
socket and then makes two option calls that Wine rejects:

1. `getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &value, &len)`
   * Wine: `WSAEOPNOTSUPP` (`10045`)
   * The SDK treats this as fatal and closes the voice room.
2. `setsockopt(s, IPPROTO_IP, IP_ECN, ...)`
   * Wine: `WSAENOPROTOOPT` (`10042`)
   * The SDK again treats the error as fatal.

The workaround makes exactly those two calls succeed:

* `IPV6_V6ONLY` on an IPv4 socket returns `0` and writes `V6ONLY = 0`.
* `IP_ECN` on `IPPROTO_IP` returns `0` and does nothing.

No other socket option is changed. The patch lives in Wine's
`ws2_32.dll`; no game file is touched.

Observed game log lines:

```
room connection closed: OS Error 10045
room connection closed: OS Error 10042
```

The first was captured before any patch. The second appeared only after the
`10045` path was intercepted, which is why this workaround has two hooks.

---

## 2. How to use

The script is `gzw_voip_fix-autodetect.py`. It is a single-file Python 3
program with no third-party dependencies.

### 2.1 Before you start

* Linux with Steam and Gray Zone Warfare installed (Steam app id `2479810`).
* Launch the game once under Proton so its prefix exists. The tool does not
  create a prefix.
* Python 3.8 or newer.
* Exit the game before patching. The tool scans `/proc` for
  `GZWClientSteam*` and refuses to patch while the game is running.
* Your user must be able to write to the Proton prefix (normally it can,
  because Steam created it).

### 2.2 Automatic prefix detection

With no path arguments, the script searches these Steam roots:

* `~/.local/share/Steam`
* `~/.steam/steam` and `~/.steam/root`
* `~/.var/app/com.valvesoftware.Steam/.local/share/Steam` (Flatpak)
* `~/snap/steam/common/.local/share/Steam` and
  `~/snap/steam/current/.local/share/Steam` (Snap)

For every root it also reads `steamapps/libraryfolders.vdf` and adds the
other Steam libraries listed there. It then looks for
`steamapps/appmanifest_2479810.acf` and selects
`steamapps/compatdata/2479810/pfx`. If no manifest is found, it falls back to
the first existing `steamapps/compatdata/2479810/pfx` directory.

The DLL is read from
`drive_c/windows/system32/ws2_32.dll` inside that prefix. `--prefix`
overrides auto-detection, and `--dll` bypasses prefix lookup entirely.
`--appid` changes the app id used for detection (default `2479810`).

### 2.3 Check the current state

```bash
python3 gzw_voip_fix-autodetect.py --check
```

Example output:

```
DLL:      /home/user/.local/share/Steam/steamapps/compatdata/2479810/pfx/drive_c/windows/system32/ws2_32.dll
SHA-256:  <hex digest>
Status:   CLEAN
```

`--check` only reads the file. The status is `CLEAN` (both hook sites
original), `PATCHED` (both hooks present), `PARTIAL` (mixed or unknown hook
state), or `ERROR` (the file could not be parsed as the expected DLL).

### 2.4 Patch

```bash
python3 gzw_voip_fix-autodetect.py
```

On success the tool prints `Patched successfully: <path>`. Run `--check`
again and expect `Status: PATCHED`, then start the game.

The original DLL is copied next to it as
`ws2_32.dll.gzw-voip-backup` before the first write. If a
`GZWClientSteam*` process is running, patching stops with an error; exit the
game and retry. `--force` bypasses that process check.

There is no confirmation prompt: a bare invocation (without `--check` or
`--revert`) writes the patch immediately. The parser also accepts
`--dry-run` and `--yes`, but in v1.1.0 neither option is implemented.

### 2.5 Revert

```bash
python3 gzw_voip_fix-autodetect.py --revert
```

This restores `ws2_32.dll.gzw-voip-backup`, or the older
`ws2_32.dll.v6only-backup` if that is the only backup present. The restore is
byte-for-byte. It does not check hashes or whether the game is running, so
exit the game first.

### 2.6 Manual path selection

Use `--prefix` if auto-detection picks the wrong Steam library, or `--dll` to
target a specific file:

```bash
python3 gzw_voip_fix-autodetect.py --check --prefix ~/.local/share/Steam/steamapps/compatdata/2479810/pfx
python3 gzw_voip_fix-autodetect.py --prefix ~/.local/share/Steam/steamapps/compatdata/2479810/pfx
python3 gzw_voip_fix-autodetect.py --dll /path/to/ws2_32.dll
```

`--prefix` normally points at the `pfx` directory. The script also accepts
the parent `compatdata/2479810` directory and then checks
`pfx/drive_c/windows/system32/ws2_32.dll`.

### 2.7 Proton updates and stale backups

A Proton update replaces `ws2_32.dll`, usually with a clean file, while the
old `.gzw-voip-backup` remains. Version 1.1.0 only creates a backup when none
exists and does not rotate or validate it. Before patching a newly updated
Proton, remove or rename the old backup so a fresh one is created. Otherwise
`--revert` can restore a DLL from the previous Proton build.

---

## 3. Why this is a Wine issue, not the microphone or the Proton package, or any issue related to GZW

The failure occurs while the voice room is being set up, before audio is
sent. The error codes come from Wine's Winsock implementation, not from the
game's audio device code:

* `10045` = `WSAEOPNOTSUPP` ("Operation not supported").
* `10042` = `WSAENOPROTOOPT` ("Bad protocol option").

Reverting the CachyOS Proton build to GE-Proton did not change the failure;
all installed builds use Wine 11.0 and show the same Winsock behaviour. A
Wine-side fix is therefore the right layer.

An `LD_PRELOAD` shim was tested and abandoned: Steam's runtime strips
`LD_PRELOAD` before launching Wine, and Proton's inherited-environment dump
contains no `LD_PRELOAD`. The patch has to be inside the DLL that Wine loads.

---

## 4. Function discovery

### 4.1 `server_getsockopt`

The `IPV6_V6ONLY` request is reached through a small thunk. In all tested
Wine 11.0 builds, the thunk contains:

```
ba 5c 04 12 00    mov edx, 0x12045c     ; IPV6_V6ONLY request code
e9 <rel32>        jmp ...
```

The `e9` leads to a trampoline, which in turn jumps to
`server_getsockopt`. The tool follows both jumps and verifies the target's
prologue:

```
55 56 53 48 83 ec 60    push rbp; push rsi; push rbx; sub rsp, 0x60
```

Note: `0x12045c` is Wine's internal NT request code for the option, not the
public Winsock `IPV6_V6ONLY` value (27). The hook is at the server routine, so
it sees the internal code.

The signature and the prologue together are the gate. If a future build
changes the request code (the `0x12045c` immediate), the signature changes
and the tool refuses to patch. That is intentional: the hook's first
instruction compares `edx` with that exact value.

Why hook `server_getsockopt` instead of the public `getsockopt` export? The
export is a thin wrapper/tail call; the server routine is the actual default
handler for the option. Hooking at the server routine catches the call the
trace showed and avoids relying on the wrapper's prologue.

### 4.2 `setsockopt`

`setsockopt` is a PE export, so no signature is needed. The tool reads the
export directory, finds the function RVA, and parses its prologue. The
prologue varies between builds:

| Build type | Prologue (first bytes) | 5-byte hook boundary |
| --- | --- | --- |
| CachyOS with debug info | `55 41 57 41 56 41 55 41` | `55 41 57 41 56` |
| GE / Valve / stripped | `55 41 56 41 55 41 54 57` | `55 41 56 41 55` |

The parser accepts whole pushes (`push rbp`, `push r8`…`r15`) and a following
`sub rsp, imm8/imm32` or `lea rbp, [rsp+…]` until it has at least five whole
bytes. The hook is installed at the entry and padded with `nop` if the
original prefix is longer than five bytes. The copied prefix is replayed in
the cave before jumping back, so the original stack frame is preserved.

---

## 5. The two caves

Both caves are written into zero/`0xCC` padding at the end of `.text`. They
are position-independent: only relative `jmp`/`jne` instructions are used.

### 5.1 `IPV6_V6ONLY` cave

```
81 fa 5c 04 12 00          cmp edx, 0x12045c
0f 85 11 00 00 00          jne .orig                 ; cave+0x1d
41 c7 00 00 00 00 00       mov dword ptr [r8], 0     ; optval  = 0
41 c7 01 04 00 00 00       mov dword ptr [r9], 4     ; optlen  = 4
31 c0                      xor eax, eax              ; success
c3                         ret
55 56 53 48 83 ec 60       .orig: original prologue
e9 <rel32>                 jmp server_getsockopt+7
```

* `edx` is the option/ioctl code at entry.
* `r8` is the `optval` pointer; `r9` is the `optlen` pointer.
* For the matching option the cave returns success, with an `int 0` and a
  length of 4. For anything else it replays the original seven-byte prologue
  and returns to `server_getsockopt+7`.
* Cave length: `29 + 7 + 5 = 41` bytes.
* `jne` displacement: target `0x1d`, next instruction `0x0c`, so `0x11`.
* Back-jump: `rel = (func_rva + 7) - (cave_rva + 41)`.

### 5.2 `IP_ECN` cave

```
83 fa 00                   cmp edx, 0                ; IPPROTO_IP
0f 85 0d 00 00 00          jne .orig                 ; cave+0x16
41 83 f8 32                cmp r8d, 0x32             ; IP_ECN (50)
0f 85 03 00 00 00          jne .orig                 ; cave+0x16
31 c0                      xor eax, eax              ; success
c3                         ret
<pro2>                     .orig: original prologue (5 bytes in tested builds)
e9 <rel32>                 jmp setsockopt+len(pro2)
```

* `edx` is the level; `r8d` is the option name.
* For `IPPROTO_IP` + `IP_ECN` the cave returns success without changing the
  socket. For anything else it replays the original prologue and jumps back.
* Cave length: `22 + len(pro2) + 5`; 32 bytes when `pro2` is 5 bytes.
* First `jne`: target `0x16`, next `0x09`, displacement `0x0d`.
* Second `jne`: target `0x16`, next `0x13`, displacement `0x03`.
* Back-jump: `rel = (func_rva + len(pro2)) - (cave_rva + 32)` for the tested
  5-byte prologue; the code computes it from `len(pro2)`.

### 5.3 Hooks

At `server_getsockopt`:

```
e9 <rel32> 90 90      ; 7 bytes; rel = cave1_rva - (func_rva + 5)
```

At `setsockopt`:

```
e9 <rel32>            ; 5 bytes; rel = cave2_rva - (func_rva + 5)
```

The tool pads the hook with `nop` up to the original prologue length. The
cave's original-prologue copy and back-jump preserve normal execution for
non-matching calls.

---

## 6. Cave placement and `.text` `VirtualSize`

Wine's `ws2_32.dll` has a useful property in all tested builds: the `.text`
section's `Misc_VirtualSize` is smaller than its `SizeOfRawData`, and the
bytes in between are zero padding. Those bytes are in the file but not
mapped by the loader until the virtual size covers them.

The tool:

1. Starts at `align_up(.text.VirtualAddress + .text.VirtualSize, 16)`.
2. Scans forward for a run of at least `cave1 + 16 + cave2` bytes where every
   byte is `0x00` or `0xCC`.
3. Ensures the end of cave2 is before both:
   * the end of `.text`'s raw data, and
   * the next section's virtual address.
4. Writes cave1 at the start, cave2 at the next 16-byte boundary.
5. Sets `.text.Misc_VirtualSize = cave_end - .text.VirtualAddress`.

The raw file size, `SizeOfRawData`, `SizeOfImage`, and all other sections are
unchanged. `.text` is executable (`IMAGE_SCN_MEM_EXECUTE`); the tool checks
that before patching. The PE checksum is not updated; Wine's loader does not
require it for this DLL (the in-game test with the manual patch ran with the
old checksum). No relocations are needed because the caves use only rel32
branches inside the same image.

There is no `.pdata`/`.xdata` entry for the caves. The cave code is tiny and
does not raise exceptions; an exception occurring precisely inside a cave
would be the only case where unwinding could be less reliable. This is an
accepted limitation of a user-side workaround.

---

## 7. Tested builds

Original hashes and the exact values the tool finds. Version 1.1.0 changes
only target discovery and the CLI, not the bytes written to the DLL, so the
same patched hashes apply:

| Build | Original SHA-256 | `server_getsockopt` RVA | `setsockopt` RVA | `setsockopt` prologue | `.text` pad start | cave1 | cave2 | new `.text` VirtualSize | v1.0.0/v1.1.0 patched SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| proton-cachyos-11.0-20261015-slr-x86_64_v3 (debug) | `4e577deb…` | `0x19140` | `0x19ed0` | `55 41 57 41 56` | `0x1d200` | `0x1d200` | `0x1d230` | `0x1c250` | `e6800833…` |
| GE-Proton 11-1 / 11-5 / 11-10 | `83f42bc5…` | `0x12b00` | `0x12f90` | `55 41 56 41 55` | `0x15440` | `0x15440` | `0x15470` | `0x14490` | `70ceaa2d…` |
| proton-cachyos-11.0-20260521 | `83f42bc5…` | `0x12b00` | `0x12f90` | `55 41 56 41 55` | `0x15440` | `0x15440` | `0x15470` | `0x14490` | `70ceaa2d…` |
| Proton - Experimental | `651ae83a…` | `0x12900` | `0x12d90` | `55 41 56 41 55` | `0x15140` | `0x15140` | `0x15170` | `0x14190` | `03c90f15…` |
| Proton 11.0 | `6fed136e…` | `0x12840` | `0x12cd0` | `55 41 56 41 55` | `0x15080` | `0x15080` | `0x150b0` | `0x140d0` | `0e06b7e9…` |
| Proton Hotfix | `bd2ba13d…` | `0x12900` | `0x12d90` | `55 41 56 41 55` | `0x15140` | `0x15140` | `0x15170` | `0x14190` | `3a71a92c…` |

Full original hashes:

```
4e577deb96e723bd84d829265b515d8f76afda8ab4c4b40e3eb7c92cf6e7b48c
83f42bc5c7cef4ba34eabd506237f6ec1b0e3a767be1b7a730ba815d87ba2041
651ae83aeb0299c5fc95ad1ce24a952b1e001a8c3fccdae426a2b9b836cd8c89
6fed136eaa4a50ec3ce4c0516baaef8ed503831bf18115e8c55ae62f9a6de35a
bd2ba13dc9ba332e1c3fffa04dfa5cbd67cde44d58c1e5b69ed61cf664bade61
```

Full v1.0.0/v1.1.0 patched hashes:

```
e68008335d79258a755c4dd14036808c4f3bf30c501767f27832854d326c8851
70ceaa2d1230ae04a5d4ce2ee2a202895d2f104762cc197447568310919d182b
03c90f15f5998f064aef7e75dc6dbdb38a2a6d523320bd99220d146badca9695
0e06b7e96f39b06722d7620fb2386ed308c9d304888344317fea081ffc1dbf2f
3a71a92c97fa014174a7c9ce00fbefad763a84b47716e81e4f786d675765970c
```

The patched hashes depend on the tool version and cave placement. They are
useful for reproducing this exact release, not as a requirement for future
builds.

All tested builds share:

* `server_getsockopt` prologue `55 56 53 48 83 ec 60`
* signature `ba 5c 04 12 00 e9`
* `.text` zero padding large enough for both caves

---

## 8. Verification

### 8.1 With the tool

```bash
python3 gzw_voip_fix-autodetect.py --check
```

Expected on a patched DLL:

```
DLL:      /path/to/compatdata/2479810/pfx/drive_c/windows/system32/ws2_32.dll
SHA-256:  <hex digest>
Status:   PATCHED
```

The status is `CLEAN`, `PATCHED`, `PARTIAL`, or `ERROR`; `--check` does not
print the per-function RVAs or cave addresses. Use `objdump` (§8.2) when the
individual hooks need to be inspected.

`--revert` restores the backup byte-for-byte. Version 1.1.0 does not compare
the backup against the current DLL or against recorded hashes; it also does
not check whether the game is running. Exit the game and verify the restored
SHA-256 separately if needed.

### 8.2 With objdump

Image base is `0x180000000`. For the debug build:

```bash
objdump -d --start-address=0x180019140 --stop-address=0x180019148 ws2_32.dll
objdump -d --start-address=0x18001d200 --stop-address=0x18001d250 ws2_32.dll
objdump -d --start-address=0x180019ed0 --stop-address=0x180019ed8 ws2_32.dll
```

Expected:

```
180019140:  e9 bb 40 00 00        jmp 18001d200
180019145:  90                    nop
180019146:  90                    nop

18001d200:  81 fa 5c 04 12 00     cmp $0x12045c,%edx
18001d206:  0f 85 11 00 00 00     jne 18001d21d
18001d20c:  41 c7 00 00 00 00 00  movl $0x0,(%r8)
18001d213:  41 c7 01 04 00 00 00  movl $0x4,(%r9)
18001d21a:  31 c0                 xor %eax,%eax
18001d21c:  c3                    ret
18001d21d:  55                    push %rbp
...
18001d224:  e9 1e bf ff ff        jmp 180019147

180019ed0:  e9 5b 33 00 00        jmp 18001d230
...
18001d230:  83 fa 00              cmp $0x0,%edx
18001d233:  0f 85 0d 00 00 00     jne 18001d246
18001d239:  41 83 f8 32           cmp $0x32,%r8d
18001d23d:  0f 85 03 00 00 00     jne 18001d246
18001d243:  31 c0                 xor %eax,%eax
18001d245:  c3                    ret
18001d246:  55                    push %rbp
...
18001d24b:  e9 85 cc ff ff        jmp 180019ed5
```

For other builds, add `0x180000000` to the RVAs in the table.


## 8. Limitations and risks

* **Wine 11.0 layout only.** The signature, prologues, request code, and
  available padding are verified. A different Wine version may fail safely;
  do not bypass the checks with `--force`.
* **`IP_ECN` is a no-op.** The SDK only needs the call to succeed; the
  patch does not enable ECN semantics. A caller that actually relies on ECN
  would not get it.
* **`IPV6_V6ONLY` returns success for the matching request, even on an IPv4
  socket.** This is what the tested game accepts. A caller that expects
  `WSAENOPROTOOPT` on IPv4 would see different behaviour.
* **Per-prefix, not per-game.** The patched file lives in
  `compatdata/<appid>/pfx` and affects every program run in that Wine prefix.
  GZW normally has its own prefix, so in practice only GZW is affected; a
  shared or manually selected prefix also changes Winsock behaviour for
  other programs in it.
* **Steam auto-detection only.** Built-in discovery covers native Steam,
  Flatpak Steam, and Snap Steam. Heroic, Lutris, and other custom Wine
  prefixes need `--prefix` or `--dll`.  Why anyone would install with one of
  these is beyond me... but you folks do weird things sometimes.
* **Stale backups are not detected.** v1.1.0 creates a backup only when one
  does not already exist. After a Proton update, remove or rename the old
  `.gzw-voip-backup` before patching, or `--revert` may restore an older
  build's DLL.
* **No backup validation.** `--revert` restores the backup file as-is. It
  does not compare SHA-256 hashes, inspect metadata, or check whether the
  game is running.
* **`--dry-run` and `--yes` are placeholders.** Both are accepted by the
  argument parser, but v1.1.0 does not implement either behaviour; a bare
  patch invocation writes immediately.
* **No exception unwind entry for the caves.** Low risk; see §6.
* **EAC / anti-cheat.** No game files are touched, but this is an unofficial
  modification of the Wine installation. Revert if you are concerned.
* **No Windows support.** This is specifically for Wine/Proton.
* **The game can have other voice problems.** This tool fixes two Winsock
  errors; it cannot fix microphone selection, muted input, server-side voice,
  or a future ODIN protocol change.
* This is for the 11* series of proton.

---


## 11. Reproducing the trace

The patch does not need `WINEDEBUG` or any launch option. If you want to see
the calls for a new build, launch GZW once with:

```bash
WINEDEBUG=+winsock %command%
```

Then search the Steam/Wine log for:

```
IPV6_V6ONLY
Unknown IPPROTO_IP optname
10045
10042
```

The two errors in the game log (`GZW.log`) are the quickest confirmation.

---

## 12. License

The patcher and this document are MIT-licensed; see [LICENSE](LICENSE).
Wine is LGPL. No Wine source code is included in this repository; the tool
contains only the small byte sequences needed to interoperate with the
installed DLL.
