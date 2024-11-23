set -eux

BUILDDIR=build
rm -rf $BUILDDIR
mkdir $BUILDDIR

nasm -f elf64 crtstub.S -o $BUILDDIR/crtstub.o
clang -o $BUILDDIR/main.o -fpic -g -nostdlib -ffunction-sections -c main.c
ld -o tringle -T link.ld --gc-sections $BUILDDIR/crtstub.o $BUILDDIR/main.o
