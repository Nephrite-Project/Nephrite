======================================
Nephrite persistent reservation helper
======================================

Synopsis
--------

**nephrite-pr-helper** [*OPTION*]

Description
-----------

Implements the persistent reservation helper for Nephrite.

SCSI persistent reservations allow restricting access to block devices
to specific initiators in a shared storage setup.  When implementing
clustering of virtual machines, it is a common requirement for virtual
machines to send persistent reservation SCSI commands.  However,
the operating system restricts sending these commands to unprivileged
programs because incorrect usage can disrupt regular operation of the
storage fabric. Nephrite's SCSI passthrough devices ``scsi-block``
and ``scsi-generic`` support passing guest persistent reservation
requests to a privileged external helper program. :program:`nephrite-pr-helper`
is that external helper; it creates a listener socket which will
accept incoming connections for communication with Nephrite.

If you want to run VMs in a setup like this, this helper should be
started as a system service, and you should read the Nephrite manual
section on "persistent reservation managers" to find out how to
configure Nephrite to connect to the socket created by
:program:`nephrite-pr-helper`.

After connecting to the socket, :program:`nephrite-pr-helper` can
optionally drop root privileges, except for those capabilities that
are needed for its operation.

:program:`nephrite-pr-helper` can also use the systemd socket activation
protocol.  In this case, the systemd socket unit should specify a
Unix stream socket, like this::

    [Socket]
    ListenStream=/var/run/nephrite-pr-helper.sock

Options
-------

.. program:: nephrite-pr-helper

.. option:: -d, --daemon

  run in the background (and create a PID file)

.. option:: -q, --quiet

  decrease verbosity

.. option:: -v, --verbose

  increase verbosity

.. option:: -f, --pidfile=PATH

  PID file when running as a daemon. By default the PID file
  is created in the system runtime state directory, for example
  :file:`/var/run/nephrite-pr-helper.pid`.

.. option:: -k, --socket=PATH

  path to the socket. By default the socket is created in
  the system runtime state directory, for example
  :file:`/var/run/nephrite-pr-helper.sock`.

.. option:: -T, --trace [[enable=]PATTERN][,events=FILE][,file=FILE]

  .. include:: ../qemu-option-trace.rst.inc

.. option:: -u, --user=USER

  user to drop privileges to

.. option:: -g, --group=GROUP

  group to drop privileges to

.. option:: -h, --help

  Display a help message and exit.

.. option:: -V, --version

  Display version information and exit.
