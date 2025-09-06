
﻿

"1 — High-level architecture

Components:

Core Wipe Engine (CWE) — single codebase (Rust or Go) that implements wipe algorithms, certificate creation, hash operations, logging, plugin/adapter interface for low-level device operations.

Platform Adapters — small OS-specific modules that call into firmware/driver ioctls or vendor tools:

Linux adapter (hdparm, nvme-cli, sg3_utils, ioctl wrappers)

Windows adapter (WinAPI, DeviceIoControl, vendor utilities, PowerShell wrapper)

Android adapter (adb/fastboot flows, Storage Manager APIs, native helper)

UI layers:

Desktop GUI (Electron/GTK/Qt wrapper) for Windows & Linux — “One-Click Wipe” flows

Android app (Kotlin) for phone/tablet user flow

CLI for pro/ITAD use and for bootable ISO automation

Certificate Generator — produces signed JSON and PDF (rendered from the signed JSON), QR code, optional blockchain anchor payload.

Verification Server / Portal — stateless REST API to verify signatures, show audit log, optionally anchor certificate hashes to a public ledger.

Offline Bootable ISO/USB — Debian/Alpine live image packaging CWE + adapters + verification tool.

CI/CD & build infra — reproducible builds, GPG/Ed25519 key signing, artifact storage.

Dataflow (short):

User chooses device → UI calls CWE with adapter → CWE performs pre-wipe scan (device metadata, SMART/NVMe info) → CWE executes appropriate sanitization sequence → CWE runs post-wipe verification (scan blank sectors, confirm Secure Erase returned OK or key erased) → CWE collects evidence → Cert generator signs JSON → outputs PDF+JSON+QR+optional blockchain anchor → UI shows success and stores local audit log.

2 — Technology choices & rationale

Language: Rust or Go for CWE.

Pros: cross-compile, static binaries, good FFI for ioctl/DeviceIoControl.

Use Rust when you need precise memory safety with low-level ioctl calls; Go when you want faster dev and easier cross compilation for CLI & server.

Low-level access: Use ioctl calls (Linux) and DeviceIoControl (Windows). For SSD/NVMe, use nvme-cli patterns or raw NVMe ioctl equivalents.

Cryptography: Ed25519 or ECDSA-P-256 for signatures. Use libsodium/ed25519_dalek (Rust) or go-libp2p/ed25519 for Go.

PDF rendering: render a deterministic PDF from JSON via a template (wkhtmltopdf or a PDF library) and embed the signed JSON as an attachment and QR code.

Verification portal: small web service in Go/Rust or Node with HTTPS and an API for signature verification and certificate retrieval. It must accept either uploaded signed JSON or certificate hash for verification.

3 — Per-media sanitization techniques & mapping to NIST SP 800-88

NIST SP 800-88 defines levels: Clear (logical), Purge (physical or cryptographic), Destroy. Map to practical methods:

NIST Level	HDD method	SSD/NVMe method	HPA/DCO	Mobile (Android)
Clear	overwrite (single pass) with dd/shred	ATA TRIM + Secure Erase if firmware supports	remove HPA via hdparm then overwrite	Factory reset + secure delete app
Purge	crypto-erase (rekey) or block erase with NVMe sanitize	NVMe Sanitize (crypto or block); ATA Secure Erase	hdparm --security-erase	Full disk encryption key destroy (if encrypted)
Destroy	degauss or physical destruction (out of scope for software)	physical destruction	physical destruction	physical destruction

Implementation details:

HDD: Use multi-pass only if required by policy. dd if=/dev/zero or shred for Clear. For Purge, short reformat + verify.

SSD/NVMe: Do not rely on overwrite. Use:

ATA Secure Erase (hdparm --user-master u --security-erase "PASSWORD" /dev/sdX) — put drive into the needed state and issue secure erase.

NVMe Sanitize (nvme sanitize /dev/nvmeX --action 1/2/...) via nvme-cli or ioctl.

If drive supports crypto-erase (hardware full-disk encryption), issue key destruction (faster & recommended).

After issuing sanitize, use vendor SMART/NVMe status to confirm.

HPA/DCO: Use hdparm --yes-i-know-what-i-am-doing --dco-restore / hdparm --set-sector to remove HPA, then issue Secure Erase.

Android:

If device has File-based Encryption (FBE) or Full Disk Encryption (FDE), prefer crypto-erase (destroy key) via vdc cryptfs changepw or vdc cryptfs wipe or adb shell calls. Newer Androids support factory reset + destroy keys.

For bootloader/unlocked phones, fastboot can issue fastboot format or use fastboot oem secure depending on vendor.

For external storage (SD cards) use secure format/formatting with randomization.

Windows:

If BitLocker is enabled — invoke key removal via manage-bde -off and then perform secure erase (or better: crypto-erase by destroying keys).

Use Disk IOCTL IOCTL_DISK to perform low-level operations; for NVMe use vendor NVMe utilities (or Windows' storport APIs).

Provide PowerShell wrappers and an MSI installer that includes the engine.

4 — Pre- and post-wipe verification

Pre-wipe: collect device metadata:

Device model, serial number (SMART: smartctl -i, NVMe identify), capacity, firmware version, partition table hash (hash of MBR/GPT), unique hardware IDs (avoid PII if not required).

Take readable screenshot of device status or output text file.

Post-wipe:

For HDD: scan first N and last N MB for non-zero patterns; compute hash of those sectors should be zero/expected.

For SSD/NVMe: query Secure Erase / Sanitize completion status; read NVMe log pages / SMART attributes indicating sanitize status.

For Android: query storage manager to verify absence of user data directories, verify encryption keys absent (if crypto-erase).

Produce evidence objects: pre.json, post.json, raw logs, and hashes of them.

5 — Certificate (JSON + PDF) — schema & signing

Design a deterministic signed artifact so verification is simple.

Example certificate JSON structure:

{
  "version": "1.0",
  "certificate_id": "uuid-v4",
  "device": {
    "manufacturer": "Dell",
    "model": "XPS13",
    "serial": "ABC1234",
    "storage": [
      {
        "path": "/dev/nvme0n1",
        "type": "NVMe",
        "firmware": "1.2.3",
        "identifier_hash": "sha256:..."
      }
    ]
  },
  "wipe": {
    "method": "nvme_sanitize_crypto",
    "nist_level": "Purge",
    "parameters": {
      "sanitization_action": "crypto_erase",
      "timestamp_start": "2025-09-06T10:12:34Z",
      "timestamp_end": "2025-09-06T10:12:40Z"
    }
  },
  "evidence": {
    "pre_wipe_hash": "sha256:...",
    "post_wipe_hash": "sha256:..."
  },
  "signer": {
    "signing_key_id": "org-key-001",
    "signature_algorithm": "Ed25519"
  },
  "signature": "BASE64_SIGNED_BYTES"
}


Signing flow:

CWE builds canonical JSON (sorted keys, deterministic serialization).

Compute signature over canonical bytes with Ed25519 using the organization’s private signing key stored in an HSM or an offline key manager.

Attach signature bytes to the JSON as signature and produce a human-readable PDF with embedded signed JSON file as an attachment.

Include a QR code on the PDF that encodes either the certificate_id or the signed JSON URL or anchor hash.

PDF: deterministic template: include certificate_id, device summary, wipe method, timestamps, and a human explanation of what was run. Also embed the signed JSON as an attachment inside the PDF file for machine verification.

6 — Verification (third-party)

Options:

Online verification portal: upload signed JSON or scan QR to fetch certificate_id → server verifies:

Validate signature using signer public key (Ed25519).

Check certificate timestamp & signer key validity (cert chain).

Optionally check anchor (if blockchain used) to confirm immutability.

Offline verification: a static CLI tool that:

Accepts signed JSON → verifies signature using pinned public key(s).

Validates evidence hashes (if raw logs present).

Returns a verification report.

To enable third-party verification, publish signer public keys and key metadata (key id, algorithm, validity window) on an HTTPS endpoint and/or via public key transparency logs. For more trust, have a multi-party signing model where multiple entities sign — e.g., local center + ITAD operator.

7 — Blockchain anchoring (optional)

To increase tamper-proof trust, anchor the certificate hash (sha256 of signed JSON) into a public ledger transaction (e.g., using OP_RETURN or small anchor on a low-fee chain). Steps:

Compute h = sha256(signed_json)

Create a minimal transaction that includes h in an OP_RETURN equivalent.

Store txn_id in certificate.

Verification: check transaction exists on the chain and includes the same h.

Note: anchoring costs money and requires handling of keys for the anchoring wallet. Make this optional.

8 — Key management & signer trust model

Signer private key handling MUST be highly secure:

Use an HSM (YubiHSM, AWS CloudHSM) for signing in production; for offline bootable workflows, use an offline signing appliance or an air-gapped HSM operated by ITAD.

Implement split signing for high trust: threshold signatures or multi-signatures from multiple parties.

Implement key rotation & revocation: publish a Certificate Authority list of active signer keys with timestamps.

For local/individual users, optionally allow the app to self-sign using a local ephemeral key but mark as untrusted in verification portal.

9 — Packaging & distribution

Desktop (Windows / Linux):

Core engine compiled for each OS.

UI wrapper (Electron or native).

Installer artifacts:

Windows MSI/EXE with code signing certificate.

Linux DEB/RPM + Snap/AppImage.

For offline environments: create a minimal bootable ISO image (see below).

Bootable ISO/USB:

Build a live Linux image (Debian Live or Alpine):

Include the CWE binary, adapters, verification tools, and GUI (lightweight).

Systemd service to run the UI on boot or auto-run the CLI.

Include offline documentation, local signer public keys, and the ability to sign certificates with a local HSM (if ITAD has one).

Use live-build (Debian) or mkisofs to create deterministic images.

Provide an image signing mechanism so users can verify the ISO signature prior to use (GPG detached signature).

Android:

Provide an APK signed with your Android key for install.

For locked devices: instruct user to factory reset in UI; for unlocked devices with developer mode available, use adb/fastboot flows.

Consider distributing through Play Store and as sideloadable APK for offline installs.

10 — Implementation steps (practical roadmap)

Phase 0 — Research & PoC:

Build small PoC CLI in Rust/Go that:

Reads SMART/NVMe identify info.

Invokes hdparm and nvme-cli wrappers on Linux.

Demonstrates ATA Secure Erase on a test device (in lab only).

Produces a signed JSON with Ed25519 signature (use libsodium).

Create minimal verification CLI that validates signatures.

Phase 1 — Core engine & adapters:

Implement CWE: wipe algorithms, canonical JSON generator, evidence collector, support for plugin adapters.

Linux adapter: implement HPA/DCO removal, ATA secure erase, NVMe sanitize, post-verify logs.

Windows adapter: DeviceIoControl wrappers for low-level ops. Use SetupDiGetDeviceRegistryProperty to get serial numbers; use IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES for NVMe if available or vendor tools.

Android adapter: implement adb shell flows; implement logic for crypto key wiping if device supports.

Phase 2 — UI & packaging:

Desktop UI with simple one-click flows and advanced mode.

Android app with simple UX and an option to generate a local certificate (if offline).

Build live ISO image with CLI + GUI.

Phase 3 — Certificate & verification infrastructure:

Implement deterministic JSON schema; sign with organization key.

Build verification portal + REST API + audit log.

Add optional blockchain anchoring service.

Phase 4 — Security hardening + compliance:

Implement HSM signing, key rotation policy.

Build reproducible signing & build pipeline.

Create testbench: many storage types, vendor devices, phones.

Phase 5 — Certification & compliance:

Document mapping to NIST SP 800-88 with evidence of methods used for each media.

Prepare test reports and external audit for NIST compliance.

11 — How to pack everything (build pipelines & reproducible ISO)

Use a CI pipeline (GitHub Actions / GitLab) that cross-compiles binaries for each platform.

For ISO:

Create a deterministic rootfs using Debian live-build and include the static binaries.

Build the ISO reproducibly and sign with GPG. Provide SHA256 sums and GPG signature.

For installers:

Windows: use WiX to produce MSI, sign the installer with an EV code signing cert.

Linux: create DEB/RPM and AppImage signatures.

12 — Security & privacy considerations

Avoid storing personal PII in certificates unless explicitly consented. Use hashed identifiers (sha256(serial+salt)) if needed.

Ensure certificates include only the minimum identifying metadata required.

Secure transmission: TLS 1.3 to verification servers.

Audit logging: keep tamper-evident logs; logs should be hashed and optionally anchored to blockchain.

Consent flow: show what metadata is collected and ask user to opt-in for public anchoring.

13 — Test cases & verification tests

Unit tests for JSON canonicalization and signature verification.

Integration tests on:

HDD (various vendors)

SATA SSD (firmware supporting ATA Secure Erase)

NVMe SSD (verify sanitize)

Devices with HPA/DCO

Android devices (FBE & FDE variants)

Windows devices with BitLocker

Create a reproducible verification dataset and test harness that simulates pre/post conditions and verifies certificate acceptance.

14 — Mapping to NIST SP 800-88 (how to show compliance)

For each wipe operation, produce a compliance evidence file that maps:

nist_level → method used (Clear/Purge/Destroy)

controls_exercised → e.g., NVMe sanitize - crypto erase, ATA secure erase

evidence → signed logs, vendor sanitize status codes, SMART/NVMe logs, hashes

Bundle evidence with certificate and create an audit summary PDF that lists the NIST mapping and the rationale why the method satisfies NIST requirements for that media.

15 — Third-party verification and ITAD workflows

Provide an API for ITADs to upload their wipes and batch anchor them, returning a batch receipt.

Provide a scalable verification portal with:

Bulk upload APIs

Webhooks for anchor confirmations

Role-based access (auditor, itad-operator, user)

Provide integration plugins for existing IT Asset Management systems (CSV, JSON exports, API connectors).

16 — Example: canonical sign and verify (pseudo steps)

canonical_json = canonicalize(certificate_object) (sort keys, stable whitespace)

sig = ed25519_sign(private_key, canonical_json)

certificate.signature = base64(sig)

Save certificate.json and render certificate.pdf (embed JSON and QR).

Verification: verify = ed25519_verify(public_key, canonical_json, signature)

17 — UX & one-click flows

Desktop/Android simple flow:

Select device (auto-detect)

Choose wipe level (Recommended default: Purge)

Accept consent & backup warnings

Click Erase & Certify

Live progress bar with step logs & estimated steps

On completion: display certificate, QR code, option to email or save

Provide an Advanced Mode for ITAD with logs export and batch operations.

18 — Example JSON certificate stub (concrete)

(you can reuse this as the schema)

{
  "version":"1.0",
  "id":"uuid-v4",
  "device":{ "type":"NVMe", "serial":"sha256:..."},
  "wipe":{"method":"nvme_sanitize_crypto","nist":"Purge","start":"...","end":"..."},
  "evidence":{"pre":"sha256:...","post":"sha256:..."},
  "signer":{"id":"org-1","alg":"Ed25519"},
  "signature":"BASE64"
}

19 — Risks, constraints & mitigations

SSD overwrite fallacy: Overwriting doesn’t guarantee sanitize — use firmware methods + vendor documentation.

Vendor quirks: Some vendors (e.g., some NVMe SSDs) implement sanitize differently — include vendor database in engine and test extensively.

Android fragmentation: Not all devices allow crypto-erase via adb/fastboot — provide fallback that informs user and recommends factory reset + encryption key destroy.

Legal/PPI: collecting serial numbers may be sensitive—use hashes and explicit consent.

20 — Milestones & deliverables

M0: Proof of concept CLI (Linux) demonstrating ATA Secure Erase + signed JSON.

M1: Core engine + Linux adapter + verification CLI.

M2: Live ISO + Desktop UI + Android adapter PoC.

M3: Verification server + public key management + optional blockchain anchoring.

M4: Production packaging (MSI/APK/DEB), HSM integration, external audit & NIST mapping documentation."

message.txt17 KB

