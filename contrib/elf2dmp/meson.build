if curl.found()
  executable('nephrite-elf2dmp', files('main.c', 'addrspace.c', 'download.c', 'pdb.c', 'qemu_elf.c'), genh,
             dependencies: [glib, curl],
             install: true)
endif
