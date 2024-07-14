#!/usr/bin/bash

MKFS=./mkfs/mkfs
DATA=data.bin
let size = 1024
for i in $(seq 1 100 4096); do
  dd if=/dev/zero bs=1024 count=$i of=$DATA 2>/dev/null
  ls -lh data.bin
  $MKFS test.img $DATA >/dev/null || exit 1
done
