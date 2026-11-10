"""Temporary diagnostic: what does a Windows raw ICMPv6 socket receive over loopback?"""
import socket, struct, time, select, subprocess, sys
sys.path.insert(0, "tests")
from fakeserver6 import HOME_RA

def listen(bind, label, sender_pkts):
    r = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    try:
        r.bind(bind)
    except OSError as e:
        print(f"[{label}] bind {bind} failed: {e}"); r.close(); return
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
    for name, pkt in sender_pkts:
        try:
            s.sendto(pkt, ("::1", 0))
            print(f"[{label}] sent {name}")
        except OSError as e:
            print(f"[{label}] send {name} failed: {e}")
    seen, end = [], time.monotonic() + 2
    while time.monotonic() < end:
        rd, _, _ = select.select([r], [], [], 0.3)
        if rd:
            data, addr = r.recvfrom(65535)
            seen.append((data[0], len(data), addr[0]))
    print(f"[{label}] received (type, len, src): {seen}")
    r.close(); s.close()

echo = struct.pack("!BBHHH", 128, 0, 0, 0x1234, 1) + b"hello"
for bind in (("::1", 0, 0, 0), ("::", 0, 0, 0)):
    listen(bind, f"bind={bind[0]}", [("echo-request", echo), ("router-advert", HOME_RA)])
print(subprocess.run(["netsh", "interface", "ipv6", "show", "interfaces"], capture_output=True, text=True).stdout)
print(subprocess.run(["powershell", "-NoProfile", "-Command",
  "Get-NetIPInterface -AddressFamily IPv6 | Select-Object ifIndex,InterfaceAlias,ManagedAddressConfiguration,OtherStatefulConfiguration,RouterDiscovery | Format-Table -AutoSize | Out-String -Width 200"],
  capture_output=True, text=True).stdout)
