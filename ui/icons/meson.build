foreach s: [16, 24, 32, 48, 64, 128, 256, 512]
  s = '@0@x@0@'.format(s.to_string())
  install_data('nephrite_@0@.png'.format(s),
               rename: 'nephrite.png',
               install_dir: qemu_icondir / 'hicolor' / s / 'apps')
endforeach

install_data('nephrite_32x32.bmp',
             rename: 'nephrite.bmp',
             install_dir: qemu_icondir / 'hicolor' / '32x32' / 'apps')

install_data('nephrite.svg',
             install_dir: qemu_icondir / 'hicolor' / 'scalable' / 'apps')
