#!/bin/sh
# Lock traffic capture â€” run ON THE ROUTER while the user wakes the lock.
# Captures everything to/from 192.168.3.92 (b0:f8:93:91:79:b6) for later
# analysis: what does the lock connect to when it wakes? Does it hold a
# persistent connection the cloud can push an openLock down?
#
# Usage on router:  sh /tmp/lockcap.sh 300      (5 min window)
#                   sh /tmp/lockcap.sh 600 &    (10 min, background)
#
# Stops automatically after SECS. Output: /tmp/lockcap.pcap + .txt

SECS=${1:-900}
PCAP=/tmp/lockcap.pcap
TXT=/tmp/lockcap.txt

rm -f "$PCAP" "$TXT"

echo "=== capturing $SECS s of lock traffic (192.168.3.92 / b0:f8:93:91:79:b6) ==="
date

# Full packet capture, no DNS resolution, full snaplen (-s 0), buffer in RAM
tcpdump -i br-lan -s 0 -U -n -w "$PCAP" \
  '(ether host b0:f8:93:91:79:b6) or (host 192.168.3.92)' &
TCPDUMP_PID=$!

# Concurrent human-readable stream (connection-level view)
tcpdump -i br-lan -l -n -tttt \
  '(ether host b0:f8:93:91:79:b6) or (host 192.168.3.92)' > "$TXT" 2>&1 &
TXT_PID=$!

sleep "$SECS"

kill $TCPDUMP_PID $TXT_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null
wait $TXT_PID 2>/dev/null

echo "=== capture done ==="
ls -la "$PCAP" "$TXT"
echo
echo "--- connection summary (unique endpoints) ---"
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(\.[0-9]+)?' "$TXT" \
  | sort | uniq -c | sort -rn | head -30
