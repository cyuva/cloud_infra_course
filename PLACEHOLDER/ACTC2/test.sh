#!/usr/bin/env bash
set -euo pipefail

# Strict phase tests for simple_container.
# Goal: Each phase test should PASS iff that phase is implemented, and FAIL otherwise.
#
# Usage:
#   ./strict_phase_tests.sh [ROOTFS] [SIMPLE_CONTAINER_BIN]
#
# Defaults:
#   ROOTFS=~/actc2/rootfs
#   SIMPLE_CONTAINER_BIN=./simple_container
#
# Notes:
# - Tests assume /bin/sh exists inside rootfs.
# - Phase 2 test uses a random marker file in host /tmp; without pivot_root, container will SEE it.
# - Phase 5 test uses a tiny helper that performs the mount(2) syscall (no dependency on /bin/mount).
# - Phase 6 test checks /proc/self/status "Seccomp:" == 2 (filter mode), which is definitive.

ROOTFS="${1:-$HOME/actc2/rootfs}"
SC_BIN="${2:-./simple_container}"

PASS=0
FAIL=0

green(){ printf "\033[32m%s\033[0m\n" "$*"; }
red(){ printf "\033[31m%s\033[0m\n" "$*"; }
blue(){ printf "\033[36m%s\033[0m\n" "$*"; }

ok(){ green "✅ $1"; PASS=$((PASS+1)); }
bad(){ red "❌ $1"; FAIL=$((FAIL+1)); }

die() { red "FATAL: $*"; exit 2; }

need() {
  [[ -e "$1" ]] || die "missing: $1"
}

run_make() {
  blue "[BUILD] make clean && make"
  make clean >/dev/null
  make >/dev/null
  ok "build ok"
  echo
}

in_container() {
  # usage: in_container "<shell command>"
  sudo "$SC_BIN" "$ROOTFS" /bin/sh -c "$1"
}

# Prepare host-side helpers copied into rootfs:
# - /root/mount_test : calls mount("tmpfs", "/mnt", "tmpfs", ...) and returns 0 on success, 100+errno on failure.
prepare_helpers() {
  local c=/tmp/mount_test.c
  local b=/tmp/mount_test

  cat >"$c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/mount.h>
#include <string.h>

int main(void) {
    int r = mount("tmpfs", "/mnt", "tmpfs", 0, "");
    if (r == 0) {
        puts("MOUNT_OK");
        return 0;
    }
    printf("MOUNT_FAIL errno=%d (%s)\n", errno, strerror(errno));
    return 100 + errno;
}
C
  gcc -Wall -Wextra -O2 -static -o "$b" "$c" >/dev/null 2>&1 || die "failed to compile mount_test"

  # Force-create /root inside rootfs, then copy
  sudo mkdir -p "$ROOTFS/root" || die "mkdir rootfs/root"
  sudo install -m 0755 "$b" "$ROOTFS/root/mount_test" || die "install mount_test"
}

phase_1() {
  blue "[PHASE 1] UTS namespace + sethostname"
  local host_before inside host_after
  host_before="$(hostname)"
  inside="$(in_container 'hostname' 2>/dev/null || true)"
  host_after="$(hostname)"
  if [[ "$inside" == "mycontainer" && "$host_after" == "$host_before" ]]; then
    ok "Phase 1 (inside hostname=mycontainer, host unchanged)"
  else
    bad "Phase 1 (inside='$inside', host_before='$host_before', host_after='$host_after')"
  fi
  echo
}

phase_2() {
  blue "[PHASE 2] pivot_root jail (must NOT see host /tmp marker, and pwd must be /)"
  local marker="/tmp/sc_marker_$$.$RANDOM.$(date +%s)"
  echo "HOST_MARKER" | sudo tee "$marker" >/dev/null

  # Inside container:
  # - If pivot_root is NOT implemented: marker will be visible.
  # - If pivot_root IS implemented: marker should NOT be visible (random name, rootfs shouldn't have it).
  # Also pwd should be / after pivot_root+chdir.
  local out seen pwd
  out="$(in_container "test -e '$marker' && echo SEEN || echo NOTSEEN; pwd" 2>/dev/null || true)"
  seen="$(echo "$out" | head -n1 | tr -d '\r')"
  pwd="$(echo "$out" | tail -n1 | tr -d '\r')"

  sudo rm -f "$marker" >/dev/null 2>&1 || true

  if [[ "$seen" == "NOTSEEN" && "$pwd" == "/" ]]; then
    ok "Phase 2 (marker not visible, pwd=/)"
  else
    bad "Phase 2 (expected NOTSEEN and /, got seen='$seen' pwd='$pwd')"
  fi
  echo
}

phase_3() {
  blue "[PHASE 3] PID namespace + fresh /proc (PID must be 1)"
  # Definitive check: $$ must be 1 in a new PID namespace (child becomes init).
  # Also ensure /proc is mounted (mount output contains ' on /proc ') and /proc/1 exists.
  local out pid proc_mounted proc1
  out="$(in_container 'echo $$; mount | grep -E " on /proc " >/dev/null 2>&1; echo PROC_MOUNTED=$?; test -e /proc/1/comm; echo PROC1=$?' 2>/dev/null || true)"
  pid="$(echo "$out" | sed -n '1p' | tr -d '\r')"
  proc_mounted="$(echo "$out" | grep -oE 'PROC_MOUNTED=[0-9]+' | cut -d= -f2 | tr -d '\r')"
  proc1="$(echo "$out" | grep -oE 'PROC1=[0-9]+' | cut -d= -f2 | tr -d '\r')"

  if [[ "$pid" == "1" && "${proc_mounted:-1}" == "0" && "${proc1:-1}" == "0" ]]; then
    ok "Phase 3 (PID=1, /proc mounted, /proc/1 exists)"
  else
    bad "Phase 3 (expected PID=1 PROC_MOUNTED=0 PROC1=0, got PID='$pid' PROC_MOUNTED='${proc_mounted:-?}' PROC1='${proc1:-?}')"
  fi
  echo
}

phase_4() {
  blue "[PHASE 4] cgroup v2 memory.max + cgroup.procs (must exist during run)"
  # Run a long-ish sleep so we can observe /sys/fs/cgroup/simple_container while container runs.
  # This MUST exist if phase 4 implemented (parent creates it, adds PID, waits).
  sudo "$SC_BIN" "$ROOTFS" /bin/sh -c 'sleep 6' &
  local runner_pid="$!"
  # Give it a moment to start and create cgroup
  sleep 1

  local cg="/sys/fs/cgroup/simple_container"
  if [[ ! -d "$cg" ]]; then
    # kill the background run to avoid hanging
    sudo kill "$runner_pid" >/dev/null 2>&1 || true
    wait "$runner_pid" >/dev/null 2>&1 || true
    bad "Phase 4 (cgroup dir '$cg' not found while container running)"
    echo
    return
  fi

  local memmax procs
  memmax="$(sudo cat "$cg/memory.max" 2>/dev/null || true)"
  procs="$(sudo cat "$cg/cgroup.procs" 2>/dev/null || true)"

  # Let container finish cleanly
  wait "$runner_pid" >/dev/null 2>&1 || true

  # memory.max should be set to ~100MB; accept exact 100000000 and common close values.
  if [[ "$memmax" =~ ^[0-9]+$ ]] && [[ -n "$procs" ]]; then
    case "$memmax" in
      100000000|99999744|104857600) ok "Phase 4 (memory.max=$memmax, cgroup.procs non-empty)" ;;
      *) bad "Phase 4 (unexpected memory.max=$memmax; expected ~100MB)" ;;
    esac
  else
    bad "Phase 4 (could not read memory.max/procs)"
  fi
  echo
}

phase_5() {
  blue "[PHASE 5] capabilities drop (must NOT have CAP_SYS_ADMIN -> mount syscall must FAIL)"
  # This is a strict discriminator:
  # - Without dropping caps, as real root, mount(tmpfs) should succeed inside a private mount namespace.
  # - With the whitelist (no CAP_SYS_ADMIN), mount(2) should fail with EPERM (errno=1).
  #
  # We use /root/mount_test (copied into rootfs) to avoid requiring /bin/mount.
  local out rc
  out="$(sudo "$SC_BIN" "$ROOTFS" /bin/sh -c 'mkdir -p /mnt; /root/mount_test; echo RC=$?' 2>&1 || true)"
  rc="$(echo "$out" | grep -oE 'RC=[0-9]+' | cut -d= -f2 | tr -d '\r')"

  # mount_test returns 100+errno on failure; EPERM -> 101.
  if [[ "${rc:-999}" == "101" ]]; then
    ok "Phase 5 (mount blocked with EPERM as expected)"
  else
    bad "Phase 5 (expected mount_test RC=101 (EPERM). Output was: $(echo "$out" | tr '\n' ' '))"
  fi
  echo
}

phase_6() {
  blue "[PHASE 6] seccomp filter loaded (Seccomp: 2)"
  # Definitive check: /proc/self/status "Seccomp:" should be 2 when a filter is active.
  # (0 = disabled, 1 = strict, 2 = filter)
  local sec
  sec="$(in_container "awk '/^Seccomp:/{print \$2}' /proc/self/status" 2>/dev/null || true | tr -d '\r')"
  if [[ "$sec" == "2" ]]; then
    ok "Phase 6 (Seccomp filter active: Seccomp=2)"
  else
    bad "Phase 6 (expected Seccomp=2, got '$sec')"
  fi
  echo
}

main() {
  blue "=== STRICT simple_container phase tests ==="
  echo "ROOTFS=$ROOTFS"
  echo "SC_BIN=$SC_BIN"
  echo "Workdir=$(pwd)"
  echo

  need "$ROOTFS"
  need "$SC_BIN"

  run_make
  prepare_helpers

  phase_1
  phase_2
  phase_3
  phase_4
  phase_5
  phase_6

  blue "=== Summary ==="
  echo "PASS: $PASS"
  echo "FAIL: $FAIL"
  if [[ "$FAIL" -ne 0 ]]; then
    exit 1
  fi
}

main "$@"

