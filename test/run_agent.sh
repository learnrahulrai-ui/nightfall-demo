#!/usr/bin/env bash
# run_agent.sh — start the FULL Nightfall DLP agent in one terminal:
#   kernel network enforcement (LSM, root)  +  file sensor (inotify)  +  clipboard sensor (X11).
# One agent, three exfil channels watched. Ctrl-C stops and unloads everything.
# Run the trigger commands from a SECOND terminal (see test/triggers.txt or NOTES/ALL_DEMOS.md).
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "[agent] building..."; make demos >/dev/null 2>&1 || { echo "build failed"; exit 1; }
mkdir -p /tmp/dlp-lab/secrets /tmp/dlp-test /tmp/dlp-protected
printf 'name,ssn,card\nJane,SSN 123-45-6789,4242424242424242\n' > /tmp/dlp-lab/secrets/hr.csv
export DISPLAY="${DISPLAY:-:1}"

F=""; C=""
cleanup() {
  echo; echo "[agent] stopping + unloading..."
  [ -n "$F" ] && kill "$F" 2>/dev/null
  [ -n "$C" ] && kill "$C" 2>/dev/null
  sudo pkill -x loader 2>/dev/null
  for id in $(sudo bpftool link show 2>/dev/null | awk '/lsm/{print $1}' | tr -d ':'); do
    sudo bpftool link detach id "$id" 2>/dev/null
  done
  sudo rm -rf /sys/fs/bpf/dlp 2>/dev/null
  echo "[agent] clean."
}
trap cleanup EXIT INT TERM

echo "[agent] file sensor  -> inotify on /tmp/dlp-test"
./build/filewatch & F=$!
echo "[agent] clipboard sensor -> X11 XFixes"
./build/clipboard_watch & C=$!
echo "[agent] kernel network enforcement -> LSM (sudo)"
sudo rm -rf /sys/fs/bpf/dlp
echo "[agent] ===== ACTIVE — watching file, clipboard, network. Ctrl-C to stop. ====="
sudo ./build/loader          # foreground; prints [DLP] BLOCK; Ctrl-C ends the whole agent
