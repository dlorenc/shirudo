#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Harness self-check input: provoke a KASAN slab-out-of-bounds report on a
# variant built with --patch testing/shield-k/0100-shield-kasan-probe.patch.
# (LKDTM cannot be used: shirudo's lockdown refuses debugfs writes.) The
# table must show KASAN/BUG > 0 for this row and the VM must be recycled.
echo 1 > /proc/sys/kernel/shield_kasan_probe
echo "rc=$?"
