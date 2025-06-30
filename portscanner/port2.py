from concurrent.futures import ThreadPoolExecutor
import socket
import time
import threading

# for grabbing public ip address
import requests
from scapy.all import IP, TCP, UDP, sr1


def scan(ip_address, start_port, end_port, verbose=False, only_open=False):
    print(f"[~] Scanning {ip_address} from port {start_port} to port {end_port}")
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            # the flag sets tcp flags to SYN, which is a request to open a connection
            packet = IP(dst=ip_address) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=1, verbose=0)
            if response is None:
                # did not receive a response, port is filtered
                print(f"Port {port} is filtered (no response)")
                # if the response has a TCP layer
            elif response.haslayer(TCP):
                # reads the tcp layer
                flags = response.getlayer(TCP).flags
                # the poke has been awknowledged and the port is open
                if flags == 0x12:
                    open_ports.append(port)
                    if verbose or only_open:
                        print(f"Port {port} is open (SYN-ACK)")
                        # the port is closed
                elif flags == 0x14:
                    if verbose and not only_open:
                        print(f"Port {port} is closed (RST)")
        except Exception as e:
            if verbose:
                print(f"Error on port {port}: {e}")

    if not verbose and not only_open:
        print(f"Open ports: {open_ports}")
        return open_ports


def banner_grab(ip_address, ports):
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(20)  # 3-second timeout per connection
            s.connect((ip_address, port))  # Correct tuple format

            # Try to receive data immediately
            banner = s.recv(1024).decode(errors="ignore").strip()
            print(f"[+] Banner for {ip_address}:{port} -> {banner}")

        # except socket.timeout:
        #     print(f"[!] Timeout on {ip_address}:{port}")
        # except socket.error as e:
        #     print(f"[!] Error on {ip_address}:{port} -> {e}")
        # finally:
        except Exception as e:
            print(f"{e}")
            s.close()


# TODO:  Look at a way to find the different ports and see if there is anythin i need to do to banner grab


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Simple TCP SYN port scanner")
    parser.add_argument("--start", type=int, default=0, help="Start port (default: 0)")
    parser.add_argument("--end", type=int, default=999, help="End port (default: 999)")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show all port statuses"
    )
    parser.add_argument(
        "-o", "--only-open", action="store_true", help="Show only open ports"
    )
    args = parser.parse_args()
    # gets public ip address
    ip_addr = requests.get("https://api.ipify.org").text
    start_time = time.time()
    # does the scan
    port_list = scan(
        ip_addr, args.start, args.end, verbose=args.verbose, only_open=args.only_open
    )
    end_time = time.time()
    print(f"Scan completed in {end_time - start_time:.2f} seconds.")

    banner_grab(ip_addr, port_list)


if __name__ == "__main__":
    main()
