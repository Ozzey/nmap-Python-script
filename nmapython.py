import nmap

scanner = nmap.PortScanner()

print("Welcome Anon")
print("<---------------------------------------------->")

ip_addr= input("Enter the targeted IP Address:")
print("The Targeted IP is", ip_addr)
type(ip_addr)

resp = input("""\nPlease ENTER the scan you want to run
                 1.SYN ACK scan
                 2.UDP scan
                 3.COMPREHENSIVE scan\n""")
print("You have selected option:", resp)

if resp == '1':
    print("Nmap Version:", scanner.nmap_version())
    print("\nScanning...")
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status:",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())

elif resp == '2':
    print("Nmap Version:", scanner.nmap_version())
    print("\nScanning...")
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status:",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['udp'].keys())

elif resp == '3':
        print("Nmap Version:", scanner.nmap_version())
        print("\nScanning...")
        scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
        print(scanner.scaninfo())
        print("IP Status:",scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports:", scanner[ip_addr]['tcp'].keys())
else:
    print("Please Enter a Valid Option")
