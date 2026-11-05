# Agent Guidelines for Nephrite

Nephrite is a fork of QEMU that accepts contributions made with AI tools,
which QEMU declines (see `README.rst`). QEMU's policy in
`docs/devel/code-provenance.rst` governs contributions to QEMU, not to
Nephrite.

## Contributions

- Follow QEMU's coding style (`docs/devel/style.rst`) and run
  `scripts/checkpatch.pl` on every commit.
- Make one logical change per commit. Subjects use QEMU's prefixes, such
  as `target/i386:` or `hw/i386/amd_iommu:`, and bodies explain why,
  citing hardware documentation by document number and revision (for
  example, Intel's SDM 325462-093 or AMD's APM 24593 rev. 3.45).
- Name the AI tool in an `Assisted-by:` trailer, such as
  `Assisted-by: Claude:claude-opus-5-5`. The human who submits the change
  adds their `Signed-off-by:`, as in QEMU
  (`docs/devel/submitting-a-patch.rst`).
- Every commit must build on its own.
- List user-visible changes, bug fixes, and deviations from the hardware
  in `DIFFERENCES.rst`.

## Security

Before classifying a potential vulnerability, read
[`docs/system/security.rst`](docs/system/security.rst) to determine whether it
falls within the security boundary that Nephrite shares with QEMU.

Not every crash, assertion failure, or buffer overrun is a security
vulnerability. Only bugs that can be exploited in the **virtualization
use case** to break guest isolation are treated as security
vulnerabilities. Relevant configurations generally involve:

- **Hardware Accelerators**: e.g. KVM and Xen. TCG is explicitly excluded.
- **Virtualization focused boards**: e.g. virt, q35, pseries etc
- **Common devices for Virtualization**: e.g. VirtIO and platform devices

If unsure, the linked `security.rst` document provides authoritative guidance.
