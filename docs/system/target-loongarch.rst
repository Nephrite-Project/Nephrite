.. _LoongArch-System-emulator:

LoongArch System emulator
-------------------------

Nephrite can emulate loongArch 64 bit systems via the
``nephrite-system-loongarch64`` binary. Only one machine type ``virt`` is
supported.

When using KVM as accelerator, Nephrite can emulate la464 cpu model. And when
using the default cpu model with TCG as accelerator, Nephrite will emulate a
subset of la464 cpu features that should be enough to run distributions
built for the la464.

Board-specific documentation
============================

.. toctree::
   loongarch/virt
