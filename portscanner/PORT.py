## this code will scan for open ports on a given IP address. Will then attempt to banner grab
# and tell the user if there are any known vulnerabilities


# https://www.youtube.com/watch?v=nYPV1rCVdvs
# used this as inspiration for the code


# used to run threads in parallel
from concurrent.futures import ThreadPoolExecutor
import socket
import time
import threading

from scapy.all import IP, TCP, UDP, sr1


# target_ip = "192.168.1.1"
# port = 80

max_workers = 1

scapy_lock = threading.Lock()


def generate_port_chunks(port_range):
    port_ranges = port_range.split("-")
    port_chunk = []

    # splits the range into chunks
    chunksize = int((int(port_ranges[1]) - int(port_ranges[0])) / max_workers)

    # makes a nested list of port chunks for each worker

    for i in range(max_workers):
        start = int(port_ranges[0]) + (chunksize * i)
        end = start + chunksize

        # Ensure the last chunk does not exceed the upper limit
        if end > int(port_ranges[1]):
            end = int(port_ranges[1])

        port_chunk.append([start, end])

    return port_chunk


def scan(ip_address, port_chunk):
    print(
        (
            f"[~] Scanning ip address {ip_address} from port {port_chunk[0]} to port {port_chunk[1]}"
        )
    )
    for port in range(int(port_chunk[0]), int(port_chunk[1])):
        try:
            # This was the connection is more stealthy by not completing the handshake. hopefully

            # the flag sets tcp flags to SYN, which is a request to open a connection
            packet = IP(dst=ip_address) / TCP(dport=port, flags="S")
            with scapy_lock:
                resp = sr1(packet, timeout=1, verbose=0)

            # the response
            response = sr1(packet, timeout=1, verbose=0)

            # different responses
            if response is None:
                print(f"Port {port} is filtered (no response)")
                # checks if the response has a TCP layer
            elif response.haslayer(TCP):
                # The port is open
                if response.getlayer(TCP).flags == 0x12:
                    print(f"Port {port} is open (SYN-ACK)")
                #     # the port is closed
                # elif response.getlayer(TCP).flags == 0x14:
                #     print(f"Port {port} is closed (RST)")
        except:
            print("nothinghere")


def main():
    ip_address = socket.gethostbyname(socket.gethostname())
    port_range = "0-1000"

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        port_chunks = generate_port_chunks(port_range)

        # Iterate over the port chunks
        ip_addresses = [ip_address] * len(
            port_chunks
        )  # Repeat the IP address for each chunk
        executor.map(
            scan, ip_addresses, port_chunks
        )  # Map the scan function to the IPs and chunks

    end_time = time.time()
    print(f" Scanned {port_range[1]} ports in {end_time - start_time} seconds.")


main()


# Next step is to try banner grabbing and checking for vulnerabilities


## old code

#             print(f"Port {port} is closed (RST)")
#     # makes a socket
#     # Takes two args, addrsss family and socket type TCP right now. Udp would be SOCK_DGRAM
#     scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     # trying to esatablish a connection, if nowthing happens for 2 seconds its closed
#     scan_socket.settimeout(2)
#     scan_socket.connect((ip_address, port))

#     udp_socket.settimeout(2)
#     udp_socket.connect((ip_address, port))
#     print(f"[!] Port {port} is open")


# try:
#     scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     scan_socket.settimeout(2)
#     scan_socket.connect((ip_address, port))
#     print(f"[!] TCP Port {port} is open")
# except socket.error as e:
#     print(f"[!] Error occurred while scanning TCP port {port}: {e}")

# try:
#     udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     udp_socket.settimeout(2)
#     udp_socket.connect((ip_address, port))
#     print(f"[!] UDP Port {port} is open")
# except socket.error as e:
#     print(f"[!] Error occurred while scanning UDP port {port}: {e}")
