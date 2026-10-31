# GLEDOPTO Zigbee neighbor-table analysis

Offline reverse engineering of two GLEDOPTO OTA images found a reproducible **conditional neighbor-table handling defect**. If a synthetic table already contains multiple entries for the same eight-byte address with differing short addresses, the cleanup loop may delete an unrelated entry after the table is compacted. Whether that precondition occurs during normal operation is **unknown**. No observed device outage has been attributed to this defect.

The analyzed images are for **GL-G-001P and GL-D-005P**, not GL-G-002P. A GL-G-002P reported the same build string, `11076801`, but a different date code. The shared build string does not establish byte identity or prove the defect exists on that device. No firmware was modified or installed as part of these tests.

## Reproduction in brief

With target `(A, 0x1111)` and a synthetic table:

```
[(A, 0x2222), (B, 0x3333), (A, 0x4444), (C, 0x5555)]
```

The GL-G-001P original code removes the first A and then removes B, leaving `[(A, 0x4444), (C, 0x5555)]`. The second removal uses index 0 although the comparison is against A at index 1. The same test against the second firmware produces the same result. Additional control cases check a single match, a matching short address and adjacent duplicates.

In the first image, the loop starts at flash address `0x3a91c`. The removal function at `0x3a734` compacts 14-byte entries; the loop decrements its index at `0x3a952` but advances its pointer at `0x3a95c`. The second image has the corresponding loop at `0x3a934`; 69 of the 70 bytes are identical, with one byte differing in a relative call to the comparison function. Both actual removal paths and the actual comparison and memory-copy routines execute in Unicorn.

## Scope and limits

- Tests inject synthetic RAM and start in a single routine. The final helper at `0x2c2be` or `0x2c2d6` is stubbed; no radio traffic, interrupts or whole device state are modeled.
- Full reachability from a valid initial table has not been established. An examined update path looks up the eight-byte address and invokes cleanup before writing the address. A separate creation path initializes a new entry with eight zero bytes. These observations do not show that two entries with the same valid address can actually arise.
- A changed short address is not proof that the necessary duplicate condition arises. The effect of any erroneous removal on routing and real-world reliability is not established.
- No GL-G-002P firmware image, flash dump or device-side hash was available for comparison. The result must not be assumed to apply to GL-G-002P.
- This repository contains no vendor firmware, patched images or flashing instructions.

## Inputs and integrity

Obtain the files separately from the community OTA repository and place them beside the scripts using the exact names below. They are third-party images; SHA-256 pins the analyzed bytes, not vendor provenance.

| Local filename | Source | SHA-256 |
|---|---|---|
| `GL-G-001P.ota` | [GL-G-001P OTA](https://github.com/Koenkk/zigbee-OTA/blob/master/images/Gledopto/GL-G-001P_V11076801_OTAV12_20211028.ota) | `5426ec7e0da55cb899ebc32c5a00ab9de745c750d73b8007c86ed94bb35551cd` |
| `GL-D-005P.ota` | [GL-D-005P OTA](https://github.com/Koenkk/zigbee-OTA/blob/master/images/Gledopto/GL-D-005P_V11076801_OTAV12_20211108_60%25.ota) | `ef7285b12f9bc8d1b4effecb3ed4ad87216b0dae355b12b964194deebcf9b57f` |

The G-001P image contains build `11076801`, date code `20211028`; the D-005P image contains the same build string and date code `20211109`. These strings do not uniquely identify a complete image.

## Run

Python 3 and `unicorn==2.1.4` are required. Scripts verify input hashes and critical instruction bytes and print the cases and observed removal indices as JSON.

```
python -m pip install -r requirements.txt
python test_neighbor.py
python test_neighbor_d005p.py
```

Saved outputs are in `neighbor-test-results.json` and `neighbor-test-d005p.json`. Failure to satisfy an assertion or load an exact matching image aborts the test. These scripts are offline-only.

## Other observations

The first image's On/Off handler returns early when the requested state already matches its stored attribute. This is consistent with [Silicon Labs reference behavior](https://github.com/SiliconLabs/gecko_sdk/blob/gsdk_4.4/protocol/zigbee/app/framework/plugin/on-off/on-off.c), and is not a demonstrated bug. A network-steering path leaves the network if key verification fails, also consistent with [later Silicon Labs reference code](https://github.com/SiliconLabs/gecko_sdk/blob/gsdk_4.4/protocol/zigbee/app/framework/plugin/network-steering/network-steering.c); the examined firmware's exact SDK version was not established.
