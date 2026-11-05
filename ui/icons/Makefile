# Regenerates Nephrite's bitmaps from nephrite.svg with librsvg's
# rsvg-convert and ImageMagick: the PNGs and the BMP that the UIs and the
# icon theme take, and the Windows icon, the installer's bitmap, and the
# macOS icon resource in pc-bios.

SIZES = 16 24 32 48 64 128 256 512

regenerate:
	for s in $(SIZES); do \
	    rsvg-convert -w $$s -h $$s nephrite.svg -o nephrite_$${s}x$${s}.png; \
	done
	magick nephrite_32x32.png BMP:nephrite_32x32.bmp
	magick nephrite_16x16.png nephrite_24x24.png nephrite_32x32.png \
	    nephrite_48x48.png nephrite_64x64.png nephrite_256x256.png \
	    ../../pc-bios/nephrite-nsis.ico
	rsvg-convert nephrite-nsis.svg | magick - -background white -flatten \
	    -type TrueColor BMP3:../../pc-bios/nephrite-nsis.bmp
	python3 rez-icns.py ../../pc-bios/nephrite.rsrc
