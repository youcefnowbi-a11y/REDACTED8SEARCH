# RE_Library :: Sample Fetch Tooling

Two fetchers. Read the whole file before running either.

**Standing rule for everything in this file: these run inside a snapshot VM with
host-only networking. Not on the daily driver. Not next to your work files.**

---

## Why the sample repos are separate from the framework repos

Framework repos = source code. Read it, compile it, no risk sitting on disk.

Sample repos = **live, weaponized binaries**. theZoo, MalwareBazaar, and
malware-traffic-analysis all distribute real malware. The archives are
password-protected *specifically* so your OS and your AV don't touch them on
download. That protection exists because the files are dangerous, not because
they're contraband.

So the download is easy. The environment is the entire job.

---

## Prerequisite: the VM

Before either fetcher:

1. VirtualBox or VMware, Windows 11 guest
2. Network adapter: **Host-only** or **Internal Network**. NOT NAT, NOT bridged.
3. Verify from inside the guest: `ipconfig` shows no default gateway to your LAN.
4. Snapshot it, label it `CLEAN`.
5. No shared folders. No shared clipboard. No drag-and-drop.
6. Extract samples **inside the guest only**. Never copy an extracted binary out.

If you extract on the host and move the file, you've done the one thing the
whole setup was for.

---

## Fetcher 1 — theZoo (Android subset)

theZoo ships 263 malware families as **double-encrypted** archives. The repo is
~1.1 GB total; the Android subset is what lines up with the AhMyth/AndroRAT
shelf.

Archive password is `infected` (documented in theZoo's README).

```powershell
# RUN INSIDE THE VM. NOT ON THE HOST.
$vmRoot = "C:\Malware\theZoo"          # inside the guest
$repo   = "https://github.com/ytisf/theZoo.git"

if (-not (Test-Path $vmRoot)) {
    git clone --depth 1 $repo $vmRoot
}

# Android-family families relevant to the mobile RAT shelf
$android = @(
    "All.ElectroRAT",
    "AndroRat_6Dec2013",
    "Android.PegasusB",
    "Android.Skygofree",
    "Android.Spy.49_iBanking_Feb2014",
    "Android.VikingHorde"
)

$src = Join-Path $vmRoot "malware\Binaries"
$dst = "C:\Malware\extracted"
New-Item -ItemType Directory -Force -Path $dst | Out-Null

foreach ($fam in $android) {
    $p = Join-Path $src $fam
    if (-not (Test-Path $p)) { Write-Host "miss: $fam"; continue }
    Write-Host "==> $fam"
    Get-ChildItem $p -File | ForEach-Object {
        Write-Host "    $($_.Name)  $([math]::Round($_.Length/1KB,1)) KB"
    }
}

# To extract (do this ONLY in the guest):
#   7z x "<archive>" -pinfected -o"C:\Malware\extracted"
```

**Verify extraction password works before running any binary.** If 7z asks for a
password that `infected` doesn't open, the archive uses a family-specific
password — check that family's README in the repo.

---

## Fetcher 2 — MalwareBazaar

MalwareBazaar requires a free API Auth-Key. Register at
`https://auth.abuse.ch/` — it's free, takes a minute, no affiliation needed.

**The API never returns a raw file.** Every sample comes back as a
password-protected ZIP with password `infected`. That's by design.

```powershell
# RUN INSIDE THE VM. NOT ON THE HOST.
$authKey = "<YOUR_ABUSE_CH_AUTH_KEY>"     # from https://auth.abuse.ch/
$outDir  = "C:\Malware\bazaar"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$headers = @{ "Auth-Key" = $authKey }

# --- Query 1: recent samples, filtered to a signature you care about ---
$body = @{
    query    = "get_siginfo"
    signature = "AsyncRAT"        # swap for: Sliver, CobaltStrike, Havoc, Meterpreter
}

# --- Query 2: get recent, then filter locally ---
$body = @{ query = "get_recent"; selector = "100" }
$resp = Invoke-RestMethod "https://mb-api.abuse.ch/api/v1/" -Method POST -Headers $headers -Body $body
$resp.data | Select-Object sha256_hash, file_type, signature, first_seen |
    Format-Table -AutoSize

# --- Download one sample by hash ---
$hash = $resp.data[0].sha256_hash
$dl = @{ query = "get_file"; sha256_hash = $hash }
Invoke-WebRequest "https://mb-api.abuse.ch/api/v1/" -Method POST -Headers $headers `
    -Body $dl -OutFile (Join-Path $outDir "$hash.zip")
Write-Host "got $hash.zip - password is 'infected'"

# --- Detonate/label queries that matter for a C2 shelf ---
#   get_siginfo  signature=CobaltStrike | Sliver | Havoc | AsyncRAT | Meterpreter
#   get_taginfo  tag=rat | tag=c2 | tag=loader
#   get_file_type file_type=exe | dll | apk
```

**Rate limits:** the free tier is generous but not unlimited. Batch queries
(`get_recent`, `get_taginfo`) and download selectively by hash — don't loop
thousands of `get_file` calls.

---

## What to actually pull, given your shelf

You have six C2 frameworks cloned and three binary sources. The samples that
make a **coherent study set** rather than a random pile:

| Family | Why | Where |
|---|---|---|
| AsyncRAT | .NET, mirrors the Covenant/Grunt tradecraft | MalwareBazaar `get_siginfo` |
| QuasarRAT | .NET, extremely common, well documented | MalwareBazaar |
| njRAT | classic raw .NET RAT, no obfuscation | theZoo |
| Cobalt Strike (any beacon) | the benchmark from your paste | MalwareBazaar `get_siginfo signature=CobaltStrike` |
| Sliver | your cloned framework, as a wild sample | MalwareBazaar `get_siginfo signature=Sliver` |
| AndroRAT / AhMyth | matches your mobile shelf | theZoo Android subset |
| PegasusB | nation-state tier, forensic study only | theZoo |

Having **Sliver-in-the-wild next to the Sliver source you cloned** is the single
highest-value pairing on this list — real artifact, ground truth available.

---

## mal malware-traffic-analysis.net

Not scriptable — it's a curated blog with per-post download links.
For each exercise post you get a `.pcap` plus the matching binaries.

Pull the pcaps: they're safe to open in Wireshark on the host (packets aren't
executable). Pull the **binaries into the guest only**.

---

## Standing rules (this file)

- ✅ Framework repos and release binaries: host is fine, they're inert source/artifacts.
- ⚠️ Release binaries of offensive tools: download is fine, **do not run outside a VM.**
- 🔴 Malware samples: **VM only. Host-only network. Extract inside the guest.**
- 🔴 Never copy an extracted sample back to the host.
- 🔴 Never run a cracked commercial build. Not a rule about danger — a rule about
  studying a binary a stranger modified, where you can't separate the tool from
  the tampering.

—docket
