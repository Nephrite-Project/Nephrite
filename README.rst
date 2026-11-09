===============
Nephrite README
===============

Nephrite is a fork of `QEMU <https://www.qemu.org>`_, the generic and open
source machine emulator and virtualizer. It is not affiliated with or
endorsed by the QEMU project.


Why a fork
==========

Nephrite exists because QEMU does not accept contributions made with AI
tools. QEMU's `code provenance policy
<https://www.qemu.org/docs/master/devel/code-provenance.html>`_ says:

    Current QEMU project policy is to DECLINE any contributions which are
    believed to include or derive from AI generated content. This includes
    ChatGPT, Claude, Copilot, Llama and similar tools.

Nephrite's changes were written with such tools, so they cannot go to QEMU.
Nephrite publishes them for anyone who can use them instead, and it accepts
contributions made with AI tools.

Its changes so far are mostly in x86 emulation (TCG): Intel VMX with EPT
and the APIC virtualization features, AMD SVM's remaining features, a PMU,
CET, segment limit checks, and many corrections to how the emulated
processor behaves, along with fixes to devices, the IOMMUs, and the
firmware. `DIFFERENCES.rst <DIFFERENCES.rst>`_ lists every difference from
QEMU: new features, bug fixes, behaviour changes, and the known deviations
from the hardware.


Nephrite next to QEMU
=====================

Nephrite installs next to QEMU without overwriting any of its files. Its
programs are ``nephrite-system-x86_64``, ``nephrite-img``,
``nephrite-nbd``, and so on, with QEMU's options, and it keeps its data,
modules, configuration, documentation, man pages, translations, icons, and
plugin header under names of its own: ``share/nephrite``,
``/etc/nephrite``, and the like. The interfaces that carry the program's
name carry Nephrite's: environment variables such as ``NEPHRITE_LD_PREFIX``,
D-Bus names under ``org.nephrite``, the guest agent's
``org.nephrite.guest_agent.0`` channel, and the ``nephrite`` member of the
version that QMP reports.

Guests see the same machines as under QEMU, with Nephrite in place of QEMU
in the names that they display, such as those of disks, USB devices, and
processors. What guests and drivers identify devices and firmware
interfaces by stays QEMU's: PCI and USB IDs, ACPI and SMBIOS IDs, and the
fw_cfg signature.


Versions
========

Nephrite's version numbers are its own, starting at 0.1.0, and its
programs name the version of QEMU that they are based on too:

.. code-block:: shell

  $ nephrite-system-x86_64 --version
  Nephrite emulator version 0.1.0, based on QEMU 11.1.50

Its release tags are ``v0.1.0`` and on. QEMU has tags of the same names
for its old releases, so leave QEMU's tags out of a clone of Nephrite:
fetch QEMU with ``git fetch --no-tags``, or set ``git config
remote.<name>.tagOpt --no-tags``.


Building
========

Nephrite builds as QEMU does:

.. code-block:: shell

  mkdir build
  cd build
  ../configure
  make
  make install

``configure --help`` lists the options; ``make install`` installs under
``/usr/local`` unless ``configure --prefix`` says otherwise.
``docs/devel/build-system.rst`` documents the build system.


Documentation
=============

The ``docs/`` folder holds Nephrite's documentation, which comes from
QEMU's; ``configure --enable-docs`` builds it with `Sphinx
<https://www.sphinx-doc.org/en/master/>`_. The versions that it names, such
as those of machine types and of deprecated and removed features, are
QEMU's.


Bugs and contributions
======================

Report bugs and send changes through the issues and pull requests of
`<https://github.com/Nephrite-Project/Nephrite>`_.


License
=======

Like QEMU, Nephrite as a whole is released under the GNU General Public
License, version 2; the LICENSE file has the details. QEMU is a trademark of
Fabrice Bellard.
