import psutil
import socket

print('=== Network Interface Analysis ===')
interfaces = psutil.net_if_addrs()
stats = psutil.net_if_stats()

# Get the primary interface being used
try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(('8.8.8.8', 80))
        primary_ip = s.getsockname()[0]
    print(f'Primary IP being used: {primary_ip}')
except:
    primary_ip = None

print('\n=== All Network Interfaces ===')
for i, (name, addrs) in enumerate(interfaces.items(), 1):
    is_up = stats.get(name, {}).isup if name in stats else False
    print(f'Interface {i}: {name}')
    print(f'  Status: {"UP" if is_up else "DOWN"}')

    for addr in addrs:
        if addr.family.name == 'AF_INET':
            is_primary = addr.address == primary_ip if primary_ip else False
            print(f'  IP: {addr.address} {"<-- PRIMARY" if is_primary else ""}')
            print(f'  Netmask: {addr.netmask}')
    print()
