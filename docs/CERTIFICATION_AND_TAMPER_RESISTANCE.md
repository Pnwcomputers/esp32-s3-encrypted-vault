# Certification & Tamper Resistance

The Waveshare ESP32-S3-LCD-1.47 vault is a development prototype. It has no
cryptographic module validation or independently tested physical tamper rating.
USB write protection controls host writes. The removable microSD still exposes
PIN-wrapped key material to offline guessing. The ESP32-S3 also processes
plaintext while the vault is unlocked, so protection claims must distinguish
a detached card, a locked unit and a powered, unlocked unit.
See the [threat model](THREAT_MODEL.md) and [USB drive behavior](USB_DRIVE.md).

## Physical Design

| Control | Prototype or production design | Acceptance evidence |
| --- | --- | --- |
| Tamper evidence | Fit a captive microSD cover and enclose the board, debug headers and reset/boot controls. Apply serialized seals across case seams and card access. Keep the LCD readable for trusted pairing and USB accessible. | Photograph each sealed unit, record serials and check that ordinary opening leaves detectable evidence. Validate readability, connector clearance, cooling and both radios with the final enclosure. |
| Tamper detection | Prototype an enclosure switch or loop on a revision-verified spare input. Treat open circuits, disconnected sensors and indeterminate readings as faults. Define detection while powered and inspection procedures after a power loss. | Record behavior for normal use, a cable or sensor fault, an opened case, repeated resets and power removal. Without backup power a software sensor cannot monitor an unplugged unit. |
| Tamper response | Latch the event and block unlock, including SoftAP and Bluetooth. For an active USB export, stop serving plaintext, revoke sessions and clear the live keys and plaintext buffers. Require a documented inspection and authenticated recovery procedure. | Verify the response in each storage state, including an active write, journal replay and read-only export. Interrupting dirty writes can lose acknowledged data, so test recovery with disposable media. Begin with lockout and session zeroization to limit data loss from false trips. |
| Resistance to probing | For a higher assurance target, budget for a production PCB and a lab-reviewed physical boundary. Review debug exposure, sensitive buses and key/plaintext lifetime before selecting shields, potting or an active mesh. | Use an independent hardware security lab to define test conditions and evidence. Seals and switches support specific claims about opening or detection. A higher resistance claim needs its own results. |

Confirm the board revision and wiring before choosing a sensor input. The stock
board includes a separate microSD socket, accessible headers, USB and boot/reset
controls. An enclosure or coating can affect antenna performance, heat and
servicing, so test the assembled product.
[Waveshare board documentation](https://www.waveshare.com/wiki/ESP32-S3-LCD-1.47)

## Firmware & Key Work Before Production

1. **Establish a trusted boot and service path.** Design Secure Boot v2, release
   flash encryption, NVS encryption, restricted debug/download access and
   production logging together. The current partition table has a single factory
   app and no OTA slots. Define the signed update, rollback, signing-key custody
   and device-recovery paths first. Review the existing startup path that erases
   NVS on certain initialization failures. It cannot silently reset protected
   enrollment or retry state. Test a separate production configuration on
   sacrificial units and record the resulting fuse state and recovery outcomes.
   First boot can permanently change eFuses.
   [Espressif security enablement workflows](https://docs.espressif.com/projects/esp-idf/en/release-v5.5/esp32s3/security/security-features-enablement-workflows.html)
2. **Bind the data-key wrap to the device.** Review a per-unit hardware-backed
   key design, persistent shared attempt limits and a separate high-entropy
   recovery path. Encrypting ESP32 flash and NVS does not change what an old
   microSD snapshot exposes. Rewrapping the same data key leaves older snapshots
   of its wrapper useful against ciphertext encrypted with that key. Define
   when migration requires a new data key and re-encryption, and how old media
   and backups are handled. See the [key design proposal](KEY_DESIGN.md).
3. **Test the complete access policy.** Confirm reset and power loss preserve
   retry state. Verify disabled service paths cannot unlock the vault and that a
   rejected image leaves the device in a recoverable state. Address the shared
   factory Wi-Fi credential and define how the production AP is provisioned or
   disabled. Review BLE enrollment, wired USB exports, temporary files, logs,
   crash dumps and plaintext in memory. An unlocked USB host can retain copies
   of data the vault already sent. See [hardware validation](HARDWARE_VALIDATION.md).

## Formal Evaluation & Market Access

| Track | Scope | First decision |
| --- | --- | --- |
| FIPS 140-3 | CMVP validates an identified cryptographic module, its boundary, versions, operational environment and approved services. AES-GCM use or algorithm validation alone cannot establish module validation. | If a buyer requires it, ask an NVLAP-accredited Cryptographic and Security Testing Lab to scope a boundary and target level. Confirm whether a validated component can cover the required services in the actual environment, or whether a new module submission is needed. [CMVP standards](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/fips-140-3-standards) · [Certificate database](https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program/Validated-Modules) |
| Common Criteria | Evaluates a defined target against a Security Target. The USB Portable Storage Devices collaborative Protection Profile is a candidate reference. | Confirm the buyer's scheme and profile requirements. Ask the evaluation lab whether the intended USB, wireless unlock and removable-media architecture fits the applicable profile. [USB portable storage community](https://www.commoncriteriaportal.org/communities/usb.cfm) |
| Radio & EMC | U.S. equipment authorization and EU radio equipment conformity address the marketed radio product under separate regulatory regimes. | For commercial distribution, have a compliance lab identify obligations for the exact board, antenna, enclosure, firmware, labeling and markets. Have it verify any existing grant and installation conditions before relying on them. [FCC equipment authorization overview](https://docs.fcc.gov/public/attachments/FCC-22-68A1.pdf) · [EU Radio Equipment Directive](https://single-market-economy.ec.europa.eu/sectors/electrical-and-electronic-engineering-industries-eei/radio-equipment-directive-red_en) |

Before paying for formal evaluation, specify the buyer's requirement and freeze
the intended hardware revision, BOM, enclosure, firmware hash, toolchain and
provisioning policy. Build an evidence pack with the block diagram and boundary,
interfaces, roles and services, key lifecycle, software dependencies, test
results, production records and maintenance plan. If a validation is granted,
use the exact certificate, versions, approved operating conditions and security
policy in product claims.
[CMVP Management Manual](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/cmvp-fips-140-3-management-manual)
