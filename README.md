# understand-keygen

Analysis of the SciTools **Understand** (Helios) registration/licensing scheme
and a self-contained keygen. Two mechanisms were recovered from the Mach-O
binary and are reproduced bit-for-bit here.

## TL;DR

- All license codes come from the static methods `LicenseKey::*`; the two
  hard-coded salts are plain globals initialised in `InitFunc_568`.
- Every code is `concat(ascii) -> MD5/SHA1 -> lowercase hex -> drop the
  ambiguous glyphs 0 1 i l o -> trim -> UPPERCASE`.
- **instatrial** is fully offline and **device-free** (only date + build).
- **offline reply code** is the machine-bound full license; with the recovered
  salt it can be generated locally for any machine and any expiry.

> The examples below use placeholders (`<machineId>`, `<secondaryId>`, `<name>`,
> `<requestSecs>`, `<code>`); no real machine identifiers or issued codes are
> included.

```
$ ./understand-keygen instatrial
Date    : 20261001
Build   : 1264
Code    : <code>
Install : und -instatrialcode <code> 1264

$ ./understand-keygen offline 20351231 <machineId> <secondaryId> <name> <requestSecs>
Machine : <machineId>
Sec     : <secondaryId>
Name    : <name>
Req     : <requestSecs>
Expiry  : 20351231
Code    : <code>
Install : und -setofflinereplycode <code> -setofflinereplydate 20351231
```

## Analysis

Key functions (Understand, x86_64 Mach-O):

| Purpose | Symbol | Address |
|---|---|---|
| instant trial generator | `LicenseKey::generateInstatrial` | `0x101a5ece0` |
| instant trial validator | `HeliosLicenseManager::testInstatrialCode` | `0x101a76220` |
| instant trial accept-path | `HeliosLicenseManager::hasValidInstatrialCode` | `0x101a6b540` |
| offline request code | `LicenseKey::generateRequestCode` | `0x101a5c350` |
| offline reply code | `LicenseKey::generateReplyCode` | `0x101a60220` |
| reply validator | `HeliosLicenseManager::hasValidOfflineReplyCode` | `0x101a6c2b0` |
| salt initialiser | `InitFunc_568` | `0x101a61600` |

Salts, read straight out of `InitFunc_568`:

```
salt_A = "MwD6-Gi2U-B8dc-23ed"    @ 0x1028e7f50   (19 bytes)
salt_B = "MwD6Gi2UB8dc23ed"       @ 0x1028e7f70   (17 bytes)
```

`productId` is printed verbatim by `und -showlicensedebuginfo` (`idProduct=...`).
`build` is the build number (`buildNumber=(Build ...)` in the same output).

### Shared cleanup primitive

Each intermediate hash is a lowercase hex string, then cleaned the way Qt does
it (in source: `strip_confusables` / `clean`):

```
strip      : QString::remove("0"); remove("1"); remove("i"); remove("l"); remove("o")
remove(1,3): QString::remove(1, 3)          # delete 3 chars at index 1
truncate(n): QString::truncate(n)
finish     : QString::toUpper()
```

`instatrial` uses `strip -> remove(1,3) -> truncate(10)`; the reply code uses
`strip -> remove(1,3) -> truncate(5)` for part 1 and `strip -> truncate(10)`
for part 2.

### 1) instatrial — device-free, 15-day re-issuable trial

```
h    = strip( MD5( "yyyyMMdd"(UTC) + salt_B + build ) )
code = upper( truncate(10)( remove(1,3)( h ) ) )
```

- `testInstatrialCode` regenerates the code for `today-5 .. today` (all **UTC**),
  so a code for *today UTC* installs immediately (mind the timezone).
- `hasValidInstatrialCode` keeps it valid for **15 days** from the install date;
  re-issue to extend. No machine info is ever checked.

### 2) offline reply code — machine-bound full license

```
part1 = SHA1( salt_A + productId + machineId + secondaryId + name + requestSecs )
s1    = upper( clean5(part1) )
code  = upper( clean10( MD5( salt_B + s1 + expiry + maintenance ) ) )
```

| Argument | Source |
|---|---|
| `machineId` | license plist → `machine.id` |
| `secondaryId` | `ioreg` → `IOPlatformUUID` |
| `name` | `gethostname()`, `,` → `%2C` |
| `requestSecs` | license plist → `license.requestDateT` |
| `expiry` / `maintenance` | `QDate::toString("yyyyMMdd")`; maintenance empty for non-perpetual |

`replyTest` rebuilds this value from the stored request date and the entered
dates; `hasValidOfflineReplyCode` additionally requires `today <= expiry`.
Install with `und -setofflinereplycode <code> -setofflinereplydate <yyyymmdd>`.

#### How to obtain the `offline` inputs

`machineId` and `requestSecs` are stored by the app in
`~/Library/Preferences/com.scitools.License.plist`; `secondaryId` and `name`
come from the machine. On macOS:

```sh
# machineId   (settings key machine.id)
defaults read com.scitools.License machine.id
#   -> e.g. A1B2C3D4E5F6...                              (40 hex chars)

# requestSecs (settings key license.requestDateT)
#   run this once first so the request date is stored:
und -createofflinerequestcode >/dev/null
defaults read com.scitools.License license.requestDateT
#   -> e.g. 1700000000                                   (unix seconds)

# secondaryId (IOPlatformUUID)
ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'
#   -> e.g. XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX

# name (hostname; ',' becomes '%2C')
hostname
```

`<code>` is not an input: it is the tool's output.

```sh
./understand-keygen offline 20351231 \
    "$(defaults read com.scitools.License machine.id)" \
    "$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')" \
    "$(hostname)" \
    "$(defaults read com.scitools.License license.requestDateT)"
```

## Verification

Verified against the official `und` binary while recovering the algorithms
(run locally with your own machine values):

```
$ ./understand-keygen instatrial <build> <yyyymmdd>
Code    : <code>
$ und -instatrialcode <code> <build>        -> Valid Instatrial License (15 days)

$ ./understand-keygen offline <expiry> <machineId> <secondaryId> <name> <requestSecs>
Code    : <code>
$ und -setofflinereplycode <code> -setofflinereplydate <expiry>
                                            -> License Valid through <expiry>
```

## Build

```
cmake -B build && cmake --build build
# or
c++ -std=c++20 -O2 -o understand-keygen main.cpp
```

## Usage

```
understand-keygen instatrial [build=1264] [yyyymmdd]   instatrial code (UTC, device-free)
understand-keygen offline  <expiry> <machineId> <secondaryId> <name> <requestSecs> [maint]
understand-keygen verify   <code> [build=1264]         check an instatrial code
```

## Notes

- Run `und -createofflinerequestcode` once to obtain the `requestSecs` value
  (`license.requestDateT` in the license plist) used by `offline`.
- An active instatrial license takes precedence over a stored reply code in the
  app; clear the `license.instatrial*` keys if you want the reply code active.
- The instatrial scheme is self-issued by design (the app auto-enrols trials);
  the offline reply scheme is only offline because the shared secret is embedded
  in the client.
