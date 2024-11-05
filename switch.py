 #!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

cam_table = {}
vlan_table = {}

own_bridge_id = 0
root_bridge_id = 0
root_path_cost = 0
root_port = 0

interfaces_states = {}

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def create_bdpu(own_bridge_id, root_bridge_id, root_path_cost):
    dest_addr = bytes([int(x, 16) for x in "01:80:c2:00:00:00".split(':')])
    src_addr = get_switch_mac()
    llc_length = struct.pack('!H', 52)
    llc_header = struct.pack('!B', 0x42) + struct.pack('!B', 0x42) + struct.pack('!B', 0x03)
    bdpu_header = struct.pack('!L', 0)
    bpdu_config = struct.pack('!B', 0) + struct.pack('!Q', own_bridge_id) + struct.pack('!L', root_path_cost) + \
                    struct.pack('!Q', root_bridge_id) + struct.pack('!H', 0) + \
                    struct.pack('!H', 0) + struct.pack('!H', 0) + \
                    struct.pack('!H', 0) + struct.pack('!H', 0)
    
    bpdu_frame = dest_addr + src_addr + llc_length + llc_header + bdpu_header + bpdu_config
    return bpdu_frame

def send_bdpu_every_sec(interfaces):
    global own_bridge_id, root_bridge_id, root_path_cost

    # trimite bpdu la fiecare secunda
    while True:
        # ma asigur ca sunt root bridge
        if root_bridge_id == own_bridge_id:
            for i in interfaces:
                # trimit bpdu pe toate interfetele trunk
                if vlan_table[get_interface_name(i)] == "T":
                    bpdu_frame = create_bdpu(own_bridge_id=own_bridge_id, root_bridge_id=own_bridge_id, root_path_cost=0)
                    send_to_link(i, len(bpdu_frame), bpdu_frame)
        time.sleep(1)

def send_to_all_interfaces(interfaces, interface, length, data, vlan_id, in_vlan):
    for i in interfaces:
        if i != interface:
            # se obtine vlan-ul pe care trebuie trimis cadru
            out_vlan = vlan_table[get_interface_name(i)]

            # daca cadrul vine pe un port trunk si trebuie trimis pe un port trunk
            if in_vlan == "T" and out_vlan == "T" and interfaces_states[i] != "BLOCKED":
                send_to_link(i, length, data)
            # daca cadrul vine pe un port trunk si trebuie trimis pe un access port
            elif in_vlan == "T" and out_vlan != "T" and vlan_id == int(out_vlan):
                untagged_frame = data[0:12] + data[16:]
                send_to_link(i, length - 4, untagged_frame)

            # daca cadrul NU vine pe un port trunk (vine de pe un access port) si trebuie trimis pe un port trunk
            elif in_vlan != "T" and out_vlan == "T" and interfaces_states[i] != "BLOCKED":
                tagged_frame = data[0:12] + create_vlan_tag(int(in_vlan)) + data[12:]
                send_to_link(i, length + 4, tagged_frame)
            # daca cadrul NU vine pe un port trunk (vine de pe un access port) si trebuie trimis pe un access port
            elif in_vlan != "T" and out_vlan != "T" and int(in_vlan) == int(out_vlan):
                    send_to_link(i, length, data)

def deal_with_bpdu(interface, interfaces, data):
    global own_bridge_id, root_bridge_id, root_path_cost, root_port

    recv_root_bridge_id = int.from_bytes(data[22:30], byteorder='big')
    recv_root_path_cost = int.from_bytes(data[30:34], byteorder='big')
    recv_own_bridge_id = int.from_bytes(data[34:42], byteorder='big')

    # daca am primit un bpdu de la un switch cu un root bridge mai mic
    if recv_root_bridge_id < root_bridge_id:
        # retin undeva daca am fost root bridge pana acum
        was_root = own_bridge_id == root_bridge_id

        root_bridge_id = recv_root_bridge_id

        # adaugam 10 la cost pentru ca toate link urile sunt de 100Mbps
        root_path_cost = recv_root_path_cost + 10
        root_port = interface

        # daca am fost root bridge pana acum, setam toate interfetele trunk ca BLOCKED
        if was_root:
            # parcurgem toate interfetele trunk si le punem pe blocked
            for i in interfaces:
                if i != root_port and vlan_table[get_interface_name(i)] == "T":
                    interfaces_states[i] = "BLOCKED"
        
        if interfaces_states[root_port] == "BLOCKED":
            interfaces_states[root_port] = "LISTENING"
        
        # dam update si forwardam bpdu ul primit catre toate interfetele trunk
        for i in interfaces:
            if i != root_port and vlan_table[get_interface_name(i)] == "T":
                # forwardam bpdu ul primit actualizand root bridge id si root path cost cu ale noastre
                modified_bpdu = data[0:30] + struct.pack('!L', root_path_cost) + struct.pack('!Q', own_bridge_id) + data[42:]
                send_to_link(i, len(modified_bpdu), modified_bpdu)
    # daca am primit un bpdu de la un switch cu un root bridge egal cu al nostru
    elif recv_root_bridge_id == root_bridge_id:
        # actualizam root path cost daca este mai mic
        if interface == root_port and recv_root_path_cost + 10 < root_path_cost:
            root_path_cost = recv_root_path_cost + 10
        elif interface != root_port:
            if recv_root_path_cost > root_path_cost:
                if interfaces_states[interface] != "DESIGNATED":
                    interfaces_states[interface] = "DESIGNATED"
    elif recv_own_bridge_id == own_bridge_id:
        interfaces_states[interface] = "BLOCKED"
    else:
        pass

    if own_bridge_id == root_bridge_id:
        for i in interfaces:
            if vlan_table[get_interface_name(i)] == "T":
                interfaces_states[i] = "DESIGNATED"

def main():
    global own_bridge_id, root_bridge_id, root_path_cost, root_port

    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # read the switch configuration file
    cfg_file = f"configs/switch{switch_id}.cfg"
    with open(cfg_file, "r") as f:
        switch_priority = int(f.readline().strip())
        for line in f:
            interface, vlan_id = line.strip().split()
            vlan_table[interface] = vlan_id

    # INITIALIZARE
    # punem pe toate interfetele trunk starea BLOCKED
    for i in interfaces:
        if vlan_table[get_interface_name(i)] == "T":
            interfaces_states[i] = "BLOCKED"

    # setam variabilele pentru root bridge
    own_bridge_id = switch_priority
    root_bridge_id = own_bridge_id
    root_path_cost = 0

    # daca suntem root bridge, setam toate interfetele ca DESIGNATED
    if own_bridge_id == root_bridge_id:
        for i in interfaces:
            interfaces_states[i] = "DESIGNATED"

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(interfaces,))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        print(f"Received frame with VLAN ID {vlan_id}")

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # verificam daca am primit un cadru bpdu
        if dest_mac == "01:80:c2:00:00:00":
            deal_with_bpdu(interface, interfaces, data)
            # nu facem nimic cu cadrul bpdu --drop
            continue

        cam_table[src_mac] = interface
        # retinem vlan-ul pe care a venit cadru
        in_vlan = vlan_table[get_interface_name(interface)]

        # verificam daca mac ul destinatie este unicast
        if dest_mac != "ff:ff:ff:ff:ff:ff":
            # verficam daca avem mac ul destinatie in tabela cam
            if dest_mac in cam_table:
                # se obtine vlan ul pe care trebuie trimis cadru
                out_vlan = vlan_table[get_interface_name(cam_table[dest_mac])]

                # daca cadrul vine pe un port trunk si trebuie trimis pe un port trunk
                if in_vlan == "T" and out_vlan == "T" and interfaces_states[cam_table[dest_mac]] != "BLOCKED":
                    send_to_link(cam_table[dest_mac], length, data)
                # daca cadrul vine pe un port trunk si trebuie trimis pe un access port
                elif in_vlan == "T" and out_vlan != "T" and vlan_id == int(out_vlan):
                    untagged_frame = data[0:12] + data[16:]
                    send_to_link(cam_table[dest_mac], length - 4, untagged_frame)
                
                # daca cadrul NU vine pe un port trunk (vine de pe access port) si trebuie trimis pe un port trunk
                if in_vlan != "T" and out_vlan == "T" and interfaces_states[cam_table[dest_mac]] != "BLOCKED":
                    # se adauga 802.1Q tag
                    tagged_frame = data[0:12] + create_vlan_tag(int(in_vlan)) + data[12:]
                    send_to_link(cam_table[dest_mac], length + 4, tagged_frame)
                # daca cadrul NU vine pe un port trunk (vine de pe access port) si trebuie trimis pe un access port
                elif in_vlan != "T" and out_vlan != "T" and int(in_vlan) == int(out_vlan):
                    send_to_link(cam_table[dest_mac], length, data)
            # daca nu avem mac ul in tabela cam, trimitem cadru pe toate porturile
            else:
                send_to_all_interfaces(interfaces, interface, length, data, vlan_id, in_vlan)
        # daca mac-ul destinatie este broadcast, trimitem pe toate porturile
        else:
            send_to_all_interfaces(interfaces, interface, length, data, vlan_id, in_vlan)
                    
if __name__ == "__main__":
    main()
