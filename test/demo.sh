#!/usr/bin/env bash
#
# demo.sh — 90-second scripted walkthrough of the Nightfall DLP enforcer.
#
# This script runs the safe, non-privileged setup itself (build the objects,
# create a lab secret file) and PRINTS the two steps that require sudo + a live
# kernel — loading the eBPF programs and triggering a blocked connect — for you
# to run in a second terminal during the demo. It never calls sudo or loads BPF.
#
# Run from the repo root:  ./test/demo.sh
set -euo pipefail

# Resolve the repo root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

LAB=/tmp/dlp-lab/secrets
SECRET="$LAB/hr.csv"

hr() { printf '\n=== %s ===\n' "$1"; }

hr "Step 0  build (no sudo)"
echo "\$ make bpf loader"
make bpf loader
echo "Built bpf/dlp.bpf.o and build/loader."

hr "Step 1  plant a fake secret (no sudo)"
echo "\$ mkdir -p $LAB"
mkdir -p "$LAB"
# Test data is synthetic, well-known-fake values — never real secrets.
# The SSN alone would be level 1 (ALERT only); the Luhn-valid card number
# 4242424242424242 pushes the file to level 2 (PAN), so the connect is BLOCKED.
cat > "$SECRET" <<'CSV'
name,ssn,card,notes
Jane Doe,SSN 123-45-6789,4242424242424242,demo record — synthetic fake data only
CSV
echo "Wrote $SECRET:"
sed 's/^/    /' "$SECRET"
echo "The classifier scores this file level 2 (Luhn-valid PAN), which is at"
echo "BLOCK_LEVEL(2): a tainted process is denied outbound connections."

hr "Step 2  load + register  (YOU run this, needs sudo + live kernel)"
cat <<'STEP'
    # In terminal A — load the LSM programs and start the agent.
    # The loader classifies everything under /tmp/dlp-lab/secrets and
    # registers regulated files by {major,minor,inode}, then streams audits.
    sudo ./build/loader

    # Expected:
    #   Registered /tmp/dlp-lab/secrets/hr.csv (level 2)
    #   Attached dlp_open to kernel
    #   Attached dlp_task_alloc to kernel
    #   Attached dlp_connect to kernel
    #   Attached dlp_sendmsg to kernel
    #   Nightfall DLP Active. Enforcing kernel boundary...
STEP

hr "Step 3  trigger enforcement  (YOU run this, in terminal B)"
cat <<'STEP'
    # A single shell reads the secret (taints itself), then tries to exfil.
    # The taint follows the process; the connect is denied in-kernel.
    sudo sh -c 'cat /tmp/dlp-lab/secrets/hr.csv >/dev/null; curl -m 3 https://1.1.1.1'

    # Expected in terminal B:
    #   curl: (7) ... Operation not permitted        <- kernel vetoed connect()
    # Expected in terminal A (the loader's audit stream):
    #   [DLP] BLOCK pid <N> exfil /tmp/dlp-lab/secrets/hr.csv (level 2)
    #   (a level-1 SSN-only file would ALERT-and-allow instead of BLOCK)
STEP

hr "done"
echo "Non-privileged setup complete. Run Steps 2 and 3 above to see live enforcement."
