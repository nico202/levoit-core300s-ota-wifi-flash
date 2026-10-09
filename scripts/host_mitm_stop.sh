#!/usr/bin/env bash
# host_mitm_stop.sh - undo host_mitm.sh (run as root).
set -uo pipefail
IFACE=${IFACE:-wlan0}
GATEWAY=${GATEWAY:-}
DEVICE=${DEVICE:?set DEVICE}
SERVER=${SERVER:-}
PORT=${PORT:-18080}

[ -n "$SERVER" ] && iptables -t nat -D PREROUTING -s "$DEVICE" -p tcp --dport 80 -j DNAT --to-destination "$SERVER:$PORT" 2>/dev/null
iptables -t nat -D POSTROUTING -s "$DEVICE" -j MASQUERADE 2>/dev/null
iptables -D FORWARD -s "$DEVICE" -j ACCEPT 2>/dev/null
iptables -D FORWARD -d "$DEVICE" -j ACCEPT 2>/dev/null
for ip in $(getent hosts fw.vesync.com | awk '{print $1}' | sort -u); do
  iptables -D FORWARD -s "$DEVICE" -p tcp -d "$ip" --dport 443 -j REJECT 2>/dev/null
done
# heal the device's ARP cache: re-announce the real gateway MAC
if [ -n "$GATEWAY" ]; then
  python3 - "$IFACE" "$DEVICE" "$GATEWAY" <<'PY' 2>/dev/null || true
import sys
from scapy.all import ARP, Ether, sendp, getmacbyip
iface, dev, gw = sys.argv[1:4]
gwm = getmacbyip(gw)
if gwm:
    for _ in range(3):
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=gwm, psrc=gw, hwdst="ff:ff:ff:ff:ff:ff", pdst=dev), iface=iface, verbose=False)
PY
fi
echo "[*] MITM stopped"
