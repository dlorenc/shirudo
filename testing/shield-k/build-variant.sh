#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# build-variant.sh -- build and stage a variant of the shirudo CI test
# kernel for shield-k (shirudo-spike). The variant boots with
# `shield-k ... --kernel <name>`.
#
#   build-variant.sh <name> [--kasan] [--revert <sha>]... [--patch <file>]...
#                    [--fragment <file>]... [--from <git-url>]
#
#   --kasan           merge testing/kernel/kernel-kasan.conf (KASAN + KCOV)
#   --revert <sha>    revert this upstream commit (e.g. the fix of a CVE) on
#                     top of the pinned bpf-next commit and the carried
#                     patches; fetched from --from (default: torvalds/linux,
#                     then stable, then bpf-next) with its parent
#   --patch <file>    another patch to git-am (e.g. a hand-made partial revert)
#   --fragment <file> another config fragment (e.g. CONFIG_<DRIVER>=y the
#                     vulnerable code needs)
#
# Sources live in $KBUILD (default ~/kbuild): one bpf-next object store in
# $KBUILD/kasan/src, shared by every variant through a git worktree.
# Output: artifacts/<name>-kernel-debs/ in this checkout. Takes about 2.5
# minutes on 64 vCPUs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KBUILD="${KBUILD:-$HOME/kbuild}"
die() { echo "build-variant: $*" >&2; exit 2; }
log() { echo "build-variant: $(date -u +%H:%M:%S) $*" >&2; }

NAME="${1:-}"; shift || true
[[ "$NAME" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || die "usage: build-variant.sh <name> [--kasan] [--revert <sha>]... [--patch <file>]... [--fragment <file>]..."
[ "$NAME" != bpf-next ] || die "bpf-next is the pinned CI kernel; pick another name"
REVERTS=() PATCHES=() FRAGS=()
FROM=""
while [ $# -gt 0 ]; do
	case "$1" in
	--kasan) FRAGS+=("$ROOT/testing/kernel/kernel-kasan.conf"); shift ;;
	--revert) REVERTS+=("$2"); shift 2 ;;
	--patch) PATCHES+=("$(realpath -- "$2")"); shift 2 ;;
	--fragment) FRAGS+=("$(realpath -- "$2")"); shift 2 ;;
	--from) FROM="$2"; shift 2 ;;
	*) die "unknown argument $1" ;;
	esac
done

read -r SHA <"$ROOT/testing/kernel/bpf-next.commit"
STORE="$KBUILD/kasan/src"
OUT="$KBUILD/$NAME"
mkdir -p "$OUT"
if [ ! -d "$STORE/.git" ]; then
	git init -q "$STORE"
fi
git -C "$STORE" cat-file -e "$SHA^{commit}" 2>/dev/null ||
	git -C "$STORE" fetch --no-tags --shallow-since=2026-09-06 \
		https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git "$SHA"
if [ "$OUT/src" != "$STORE" ] && [ ! -e "$OUT/src/.git" ]; then
	git -C "$STORE" worktree add -q -f --detach "$OUT/src" "$SHA"
fi

# Reverts become patches made against the pinned commit plus the carried
# patches, so build-kernel.sh applies them last with git am --3way.
if [ "${#REVERTS[@]}" -gt 0 ]; then
	work="$OUT/revert-work"
	rm -rf "$work"; git -C "$STORE" worktree prune
	git -C "$STORE" worktree add -q -f --detach "$work" "$SHA"
	for p in "$ROOT"/testing/kernel/patches/*.patch; do
		GIT_COMMITTER_NAME=shirudo GIT_COMMITTER_EMAIL=shirudo@build-kernel \
			git -C "$work" -c core.hooksPath=/dev/null am --quiet --3way "$p"
	done
	mkdir -p "$OUT/patches"
	rm -f "$OUT"/patches/*.patch
	n=0
	for r in "${REVERTS[@]}"; do
		if ! git -C "$STORE" cat-file -e "$r^{commit}" 2>/dev/null ||
			! git -C "$STORE" cat-file -e "$r^^{commit}" 2>/dev/null; then
			for url in $FROM https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git \
				https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \
				https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git; do
				log "fetching $r (and parent) from $url"
				git -C "$STORE" fetch -q --no-tags --depth=2 "$url" "$r" 2>/dev/null && break
			done
		fi
		git -C "$STORE" cat-file -e "$r^{commit}" || die "cannot fetch $r"
		log "reverting $(git -C "$STORE" log -1 --format='%h %s' "$r")"
		GIT_COMMITTER_NAME=shirudo GIT_COMMITTER_EMAIL=shirudo@build-kernel \
			GIT_AUTHOR_NAME=shield-k GIT_AUTHOR_EMAIL=shield-k@build-variant \
			git -C "$work" revert --no-edit "$r" >/dev/null ||
			{ git -C "$work" status --short >&2; git -C "$work" revert --abort || true;
			  die "revert of $r does not apply to $SHA; make a patch by hand and pass --patch"; }
		n=$((n + 1))
		git -C "$work" format-patch -q -1 --start-number "$n" -o "$OUT/patches" HEAD
	done
	PATCHES+=("$OUT"/patches/*.patch)
	git -C "$STORE" worktree remove -f "$work"
fi

# The variant's name goes into the kernel release.
printf 'CONFIG_LOCALVERSION="-shirudo-ci-%s"\n' "$NAME" >"$OUT/localversion.conf"
FRAGS+=("$OUT/localversion.conf")

mkdir -p "$KBUILD/gnu-coreutils-bin"
ln -sf /usr/bin/gnuinstall "$KBUILD/gnu-coreutils-bin/install"
args=(--llvm 20 --arch x86-64 --out "$OUT")
for f in "${FRAGS[@]}"; do args+=(--fragment "$f"); done
for p in ${PATCHES[@]+"${PATCHES[@]}"}; do args+=(--patch "$p"); done
t0=$(date +%s)
log "build-kernel.sh ${args[*]}"
PATH="$KBUILD/gnu-coreutils-bin:$PATH" "$ROOT/testing/kernel/build-kernel.sh" "${args[@]}" >"$OUT/build.log" 2>&1 ||
	{ tail -30 "$OUT/build.log" >&2; die "kernel build failed; see $OUT/build.log"; }
pkg=$(ls -d "$OUT"/pkgs/x86-64/*/ | tail -1)
KERNEL_ARTIFACT_DEST="artifacts/$NAME-kernel-debs" "$ROOT/testing/vm/kernel-artifact.sh" stage "$pkg"
log "staged $ROOT/artifacts/$NAME-kernel-debs in $(( $(date +%s) - t0 ))s; boot with: shield-k ... --kernel $NAME"
