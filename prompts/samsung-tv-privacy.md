# Samsung TV privacy and durable voice shutdown

Version 1.3, 2026-10-25. A reusable task prompt for GPT-6 Astra or a comparably capable tool-using model. Paste this whole document into a coding-agent session with local filesystem, terminal and web access. Fill in what you know; discover the rest. This is a workflow for recent Samsung TVs, not a claim that every model is rootable or supports the same controls.

## Task and inputs

Work on my own Samsung TV. Implement the strongest verified, reversible controls against microphone capture and always-on listening that this exact TV supports. Reduce selected advertising, telemetry and unwanted background apps when that scope is enabled. Produce scripts, evidence and recovery instructions that another session can use without this conversation.

Use these inputs, resolving unknowns from the repository and device before asking me:

```yaml
repository: ./samshush  # Reuse an existing checkout if available.
operation: apply               # audit = inspect/prepare only; apply = execute this scope.
model_and_region: discover
installed_firmware: discover
tv_address: discover
host_callback_address: discover
scope:
  microphone_and_voice: true
  advertising_and_telemetry: false
  unwanted_apps: []            # Explicit choices, e.g. TV Plus, Gaming Hub, Health.
  certificate_changes: false
  disable_automatic_firmware_updates: false
  automatic_boot_reapplication: false
preserve:
  - Settings and normal remote navigation
  - HDMI inputs, HDMI-CEC, playback and audio output
  - networking, DRM, manual updates and One Connect where present
  - manual Art Mode where present
  - Netflix, browser and shared web runtimes
preferred_hdmi_input: unspecified
```

Microphone shutdown takes priority over microphone-based automatic Art presence detection; explain any resulting loss. Preserve unrelated functionality. Custom launcher development, firmware flashing, downgrades and certificate changes are outside this default scope. An input requesting one of those requires a separate concrete compatibility and recovery plan. Do not turn an offline extraction into a purported installable update.

## Setup

1. Locate the existing repository and read its applicable instructions, current status and manifests. Keep existing work. Save all useful scripts and firmware blobs inside that repository; temporary directories may be staging, never the only copy of a deliverable.
2. Identify the full model code, region, year/platform, installed firmware/build and relevant companion hardware from live settings or reliable device metadata. Ask for the model label only if discovery cannot resolve it. Do not assume that a similar retail model shares firmware, partitions or exploit compatibility.
3. Put the computer and TV on a reachable trusted LAN. Discover the TV through existing device records, ARP, mDNS or SSDP, then verify identity. Determine the host interface/address that actually routes to it. Keep the TV fully awake for setup; Art Mode or standby may affect reachability. A closed port does not establish that the TV is absent or incompatible.
4. If developer access is needed, use the current Samsung instructions for that model. The documented flow is Smart Hub → Apps → App Settings → enter `12345`, enable Developer Mode, enter the computer's LAN IP and reboot. Menus vary; verify rather than repeating an inapplicable sequence. Guide me through physical actions you cannot perform. Developer Mode and SDB access do not themselves mean root access.
5. Use official Samsung/Tizen tooling compatible with the host OS/architecture. Verify downloads and record tool versions. Check existing tools before installing duplicates. Establish the documented device connection and validate it with a harmless identity query; inspect current CLI help rather than inventing flags. Check LAN/callback reachability without disabling security controls globally.
6. Locate the model-specific official firmware package. Download only what is needed, preserve the original bytes, record source URL, retrieval time, byte size and SHA-256, and distinguish downloadable firmware from the installed build. Never update the TV merely to match a convenient research image. Use bounded retries and resumable downloads where supported.

Samsung setup reference: https://developer.samsung.com/smarttv/develop/getting-started/using-sdk/tv-device.html

## Discover before changing

Build a concise capability map from installed evidence: privileges, filesystem types and mount namespaces, writable persistent locations, unit search paths, app-manager registrations, service/path/socket/bus/timer activation, direct executable launches, restart policies and firmware-update behavior. Follow dependencies far enough to protect shared playback, Bluetooth, networking and UI services.

Investigate TV hardware microphones, AOV/standby listening, far-field engines, assistant clients, voice interaction, virtual microphones, remote microphones, Bluetooth/HFP, USB inputs and browser capture separately. Establish input provenance for any active capture endpoint; an ACR-owned endpoint or a device name alone does not identify its audio source. Do not record audio or capture network packets.

Use documented settings and native lifecycle controls first. For privileged work, verify a model/build-compatible access method from source and evidence, including its side effects and cleanup. Do not execute a payload just because it worked on another TV. If no suitable access is established, finish supported controls and offline artifacts, and state precisely which remaining outcomes are blocked.

Offline extraction must preserve originals and record extractor revisions, integrity checks and limitations. Distinguish decrypted data, faithful filesystem reconstruction, repacking, accepted signatures and an installable image. Preserve ownership, modes, links, xattrs/security labels and paired-firmware relationships wherever a future write depends on them.

## Implement durable controls

For `operation: apply`, continue through implementation and relevant verification within this scope. Make routine choices independently. Ask only for missing physical interaction or a decision that changes the scope or recovery risk. Prepare concrete artifacts before asking for any additional authorization. For `audit`, inspect and prepare only. Device audits in this repository use temporary root helpers. Disclose that access step, verify cleanup, and do not apply controls.

Before mutations, save exact preimages and original flags, running states, ownership/labels and activation paths. Provide rollback first. Prefer supported persistent app-disable controls or installed vendor startup guards whose semantics you have verified on this build. A successful command exit is insufficient: verify state readback and observable launch rejection in the correct user context. Do not guess owner UID, package options, database schemas, paths or integer settings.

Stopping a service may leave an app-manager process running. Disabling an enablement link may leave other triggers. Runtime masks under `/run` disappear at reboot. Cover each verified activation route and confirm executable identity before terminating a leftover process. Preserve shared drivers and unrelated processes.

Where only temporary controls are possible, label them per-boot and provide an explicit reapply procedure. Do not silently substitute a host watchdog for on-device persistence.

When `automatic_boot_reapplication` is enabled or I explicitly request it, use the maintained `startup` commands on the supported build. Save the original startup script and metadata, enroll only already-applied scopes, check firmware and preimages, bound execution, and verify removal. Queue the worker without waiting for reapplication to finish. Batch service queries and masks within each journaled scope, with one reload and verified rollback. Record monotonic phase timings and reject queued, running or missing completion evidence. Require changed-boot evidence before claiming persistence. Label the interval before runtime masks apply as a gap. Do not delete vendor startup files or modify an opaque service cache to manufacture a claim of permanence.

Deliver a small CLI or cohesive scripts with `doctor`, `inspect`, `plan`, `apply`, `status`, `verify` and `restore` behavior; reuse existing tools instead of adding a parallel framework. Keep model/build-specific details in explicit profiles. Require identity, build and preimage checks before writes. Support repeat runs: report already-applied state, resume only a consistent journal, and stop on drift instead of overwriting it. Record partial failures honestly. Bound command/callback timeouts and retries, retain failure output, and ensure one hung command cannot prevent rollback.

If automatic reapplication is installed, remove it with `startup remove` before restoring runtime controls. Restore only recorded changes and previously running components, following AGENTS.md for layer ordering and retained-journal retries. Verify cleanup of staging files, overlays and temporary privileges. A timeout is an unknown outcome: inspect current state before retrying. If the manager or transport becomes unhealthy, prioritize recovery and stop further experiments until recovery is verified.

## Verification and persistence

Use focused host tests for preconditions, profile mismatch, idempotence, interrupted application and rollback. Test native disable/restore on one appropriate component before a batch. Then validate the actual changed paths on the TV: flag readback, explicit launch rejection, executable/process absence, service and trigger state, and applicable capture controls. Distinguish missing output from a successful negative result.

Check the preserved features in the running TV where possible. Record separately what I observed and what tools verified. Verify the physical microphone switch and remote/input controls; a quiet audit, failed wake word or inactive process is not proof of capture denial. Never claim full microphone shutdown while an input or HAL/DSP/standby route remains unresolved.

Test standby/wake and a full reboot when access and recovery are ready. Save the old boot ID; sync persistent changes and allow transport cleanup before restart. After reconnecting, require a changed boot ID or equivalent reliable boot evidence. Read persistent flags/guards, process state and launch behavior before any host-side reapplication. If automatic reapplication is installed, inspect its current-boot result and each enrolled scope first. Do not run a host apply and then claim the boot job worked. Report software-reboot evidence separately from a power-cycle test. Unreachability alone proves neither reboot success nor failure. Use the device-supported restart procedure; do not escalate blindly through forced reboot commands.

Measure the vendor startup service and background worker separately. A warm status check does not measure fresh application. Compare whole-TV boot performance only under comparable conditions, and do not report the worker duration as added boot delay.

When automatic firmware updates are explicitly in scope, save the native preference, turn it off and verify readback. Preserve manual update capability; do not interrupt a running installation. Explain that the preference does not prove all vendor override paths are blocked.

Persistence claims must name their scope: current session, standby, verified reboot, power cycle, or firmware update. Do not claim that a reboot-tested control survives an untested firmware update. On build drift, stop mutation and require profile revalidation.

## Repository and handoff

Follow the repository's AGENTS.md and keep all maintained host tools in `tools/`,
using its uv project and existing CLI. Use this layout:

- `tools/`: Python entry points, tests, profile, pinned vendor code and device payload assets.
- `firmware/` (ignored): original downloads, extracted filesystems and retrieved vendor binaries.
- `.local/` (ignored): external toolchain, reports, recovery evidence and prepared candidates.

Keep scripts, profile, AGENTS.md and README synchronized. Keep the README concise and in the owner's direct, conversational voice, with confirmed findings and practical recommendations. Put commands, rollback details and verification evidence in AGENTS.md or local reports. Avoid repeating counts and test logs in the README.
Explain results directly to the user; keep interim investigations in local reports.

Keep firmware, retrieved vendor binaries, credentials and raw device logs local and out of public Git/Gists. Git-ignore blobs and private runtime data without deleting local copies. Retain provenance and hashes in shareable manifests with private identifiers redacted. Publish only content explicitly requested for sharing. Save dependency versions, commands and scripts used to generate every deliverable. Do not rely on ephemeral `/tmp` files or an agent's memory to reproduce it.

Maintain one current status document with the target identity/build, applied changes, per-control persistence, last verification time, unresolved paths and exact recovery commands. Link evidence rather than duplicating contradictory historical summaries. Keep a structured status record that distinguishes `verified`, `failed`, `unverified`, `unsupported` and `not_applicable`, with evidence and scope for each control. Another session must be able to inspect and resume without repeating a failed experiment.

Finish with a short bullet list of actual changes, evidence and important gaps; link local scripts, firmware inventory and rollback instructions. Separate prepared artifacts, applied controls and observed behavior. State any blocker that prevents the requested result. Stop optional testing when scoped checks pass; do not describe partial voice-service blocking as complete microphone isolation.
