# -*- coding: utf-8 -*-
"""
Created on Sat May  3 12:04:36 2025

@author: Elkin
"""
## pip install scapy
# scanner.py

import scapy
from scapy.all import ARP, Ether, srp
from datetime import datetime
import socket
import ipaddress

def get_local_ip():
    """Obtiene la IP local del equipo."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"[ERROR] No se pudo obtener IP local: {e}")
        return None

def generate_ip_range(ip):
    """Genera el rango de red /24 a partir de la IP."""
    network = ipaddress.IPv4Network(ip + '/24', strict=False)
    return str(network)

def scan_network(ip_range):
    """Escanea dispositivos conectados a la red usando ARP."""
    print(f"[INFO] Escaneando red {ip_range}...\n")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    return devices

def display_devices(devices):
    if not devices:
        print("No se encontraron dispositivos.")
    else:
        print("Dispositivos conectados:\n")
        for device in devices:
            print(f"IP: {device['ip']}\tMAC: {device['mac']}\tDetectado: {device['time']}")

if __name__ == "__main__":
    local_ip = get_local_ip()
    if local_ip:
        ip_range = generate_ip_range(local_ip)
        devices = scan_network(ip_range)
        display_devices(devices)