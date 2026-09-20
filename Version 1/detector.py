import argparse
from datetime import datetime  #for the log file fragments.log

from scapy.all import IP, sniff 


class OverlapDetectorV1:
    """
    limited version 1 detector:
    - Identifies fragmented IPv4 packets.
    - Remembers only the most recently received fragment for each (source, destination, protocol, IP ID) key.
    - Compares the current fragment only with that previous fragment.
    - Logs every fragment to a file.
    - Displays only overlap alerts in the terminal.

    Limitation:
    If two overlapping fragments are separated by another fragment 
    (so fragments arrive out of order), V1 will fail to detect the overlap.
    """

    def __init__(self, log_path="fragments.log"):
        #Each key stores the most recently seen fragment (only previous compared to current).
        self.fragment_table = {}
        self.fragments_processed = 0
        self.log_path = log_path

        #Line buffering writes each log entry without waiting for the file to be completely filled or closed.
        #gpt's execution
        self.log_file = open(
            self.log_path,
            mode="a",
            encoding="utf-8",
            buffering=1,
        )

        self.log_file.write(
            "\n"
            "================ NEW CAPTURE SESSION ================\n"
            f"Started: {datetime.now().isoformat(timespec='seconds')}\n"
            "=====================================================\n"
        )

    @staticmethod
    def fragment_key(ip_packet):
        """
        Identifiers for fragments that are expected to belong to the same original IPv4 packet.
        It makes up the key in the dictionary
        """
        return (
            ip_packet.src,
            ip_packet.dst,
            int(ip_packet.proto),  #FYI: protocol 17=UDP, prot 6=TCP, prot 1=ICMP
            int(ip_packet.id),  #unique identifier for each packet, so common among fragments of the same packet
        )

    def log_fragment(
        self,
        ip_packet,
        more_fragments,
        fragment_offset,
        start_byte,
        end_byte,
    ):
        """Write the details of every received fragment to the log file."""

        timestamp = datetime.now().isoformat(timespec="milliseconds")
        payload_length = end_byte - start_byte

        self.log_file.write(
            f"{timestamp} "
            f"Source={ip_packet.src} "
            f"Destination={ip_packet.dst} "
            f"Protocol={int(ip_packet.proto)} "
            f"IP_ID={int(ip_packet.id)} "
            f"MF={more_fragments} "
            f"Offset={fragment_offset} "
            f"Payload_length={payload_length} "
            f"Range=[{start_byte}, {end_byte})\n"
        )

    def process_packet(self, packet):
        if IP not in packet: 
            return

        more_fragments = int(packet[IP].flags.MF)
        fragment_offset = int(packet[IP].frag)

        #A packet is ordinary and unfragmented only when: MF = 0 AND fragment offset = 0. ignore these
        if more_fragments == 0 and fragment_offset == 0:
            return

        self.fragments_processed = self.fragments_processed + 1 #add that fragment to the count of processed fragments
        
        """
        Process one captured packet and check whether its IPv4 fragment
        overlaps the previously stored fragment.

        The fragment payload length is calculated using the IPv4 header's
        Total Length and Internet Header Length (IHL) fields:
        payload length = IP total length - (IHL * 4)
        IHL is multiplied by 4 because it is measured in 32-bit words,
        while the required result is in bytes.

        The detector does not use len(bytes(ip_packet.payload)) because
        captured Ethernet frames can have padding added to satisfy
        Ethernet's minimum frame size. Scapy may include those padding
        bytes in the dissected payload, making a short fragment appear
        longer than its real IPv4 payload and potentially producing a
        FALSE overlap alert.

        Using the lengths declared in the IPv4 header excludes Ethernet
        padding and produces the correct fragment byte range.
        """

        start_byte = fragment_offset * 8

        ip_header_length = int(packet[IP].ihl) * 4
        payload_length = int(packet[IP].len) - ip_header_length

        end_byte = start_byte + payload_length

        key = self.fragment_key(packet[IP])

        current_fragment = {
            "start": start_byte,
            "end": end_byte,
            "offset": fragment_offset,
            "mf": more_fragments,
            "length": payload_length,
        }

        #Every fragment is recorded in the log file.
        self.log_fragment(
            ip_packet=packet[IP],
            more_fragments=more_fragments,
            fragment_offset=fragment_offset,
            start_byte=start_byte,
            end_byte=end_byte,
        )
        #CORE LOGIC!!!
        #V1 compares the current fragment only with the immediately
        #previous fragment stored under the same packet key.
        previous_fragment = self.fragment_table.get(key)

        if previous_fragment is not None:  #if a fragment exists in the dictionary, so if fragemnt is not the first
            previous_start = previous_fragment["start"]
            previous_end = previous_fragment["end"]

            overlap_start = max(start_byte, previous_start)  
            overlap_end = min(end_byte, previous_end)

            if overlap_start < overlap_end:
                overlap_size = overlap_end - overlap_start

                print("\n[ALERT] Overlapping IPv4 fragments detected")
                print("Source:", packet[IP].src)
                print("Destination:", packet[IP].dst)
                print("Protocol:", int(packet[IP].proto))
                print("IP ID:", int(packet[IP].id))

                print("\nPrevious fragment:")
                print("  Offset:", previous_fragment["offset"])
                print("  MF:", previous_fragment["mf"])
                print(f"  Byte range: [{previous_start}, {previous_end})")

                print("\nCurrent fragment:")
                print("  Offset:", fragment_offset)
                print("  MF:", more_fragments)
                print(f"  Byte range: [{start_byte}, {end_byte})")

                print(f"\nOverlapping range: [{overlap_start}, {overlap_end})")
                print("Overlap size:", overlap_size, "bytes\n")

        #V1 weakness:
        #The current fragment replaces the previously stored fragment.
        #Older fragments are forgotten.
        self.fragment_table[key] = current_fragment

    def print_summary(self):
        print("\nV1 LOGS SUMMARY: ")
        print(f"Fragments processed: {self.fragments_processed}")
        print(f"Fragment log: {self.log_path}")
        print("--------------------------------------")

    def close(self):
        """Close the fragment log safely."""
        if not self.log_file.closed:
            self.log_file.close()


#GPT helped a lot with main, in calling functions, logging, choosing input, 
#and raising keyboard interrupts for session interruption 
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Detect adjacent overlapping IPv4 fragments from either "
            "live traffic or a PCAP file."
        )
    )

    #Create a mutually exclusive group.
    #The user must select exactly one input source: either --interface or --pcap, but not both.
    input_group = parser.add_mutually_exclusive_group(required=True)

    input_group.add_argument(
        "-i",
        "--interface",
        help="Network interface to monitor for live traffic.",
    )

    input_group.add_argument(
        "-r",
        "--pcap",
        help="PCAP file to analyze offline.",
    )



    #Read the arguments provided by the user in the terminal.
    #The results are stored inside the args object.
    parser_arguments = parser.parse_args()

    #Always write fragment information to fragments.log.
    detector = OverlapDetectorV1(
        log_path="fragments.log"
    )

    try:
        #If the user provided --pcap, analyze stored packets from the specified PCAP file.
        if parser_arguments.pcap:
            print(
                f"Reading IPv4 fragments from PCAP: "
                f"{parser_arguments.pcap}"
            )

            #Read the packets from the PCAP file.
            sniff(
                #Specify the PCAP file that Scapy should read.
                offline=parser_arguments.pcap,

                #For every packet read, call: detector.process_packet(packet)
                prn=detector.process_packet,

                #Do not make Scapy keep another copy of every packet in memory after it has been processed.
                store=False,
            )

            #This is reached when every packet in the PCAP has been processed.
            print("\nFinished reading the PCAP file.")

        #Because --pcap and --interface are mutually exclusive, reaching else means that the user selected 
        #live capture.
        else:
            print(
                f"Listening for IPv4 traffic on: "
                f"{parser_arguments.interface}"
            )
            print("Press Ctrl+C to stop.\n")

            #Capture live traffic from the selected interface.
            sniff(
                #The network interface to monitor, such as: eth0, enp0s3, or lo.
                iface=parser_arguments.interface,

                #Ask the packet-capture system to send only IPv4 packets to the program.
                filter="ip",

                #Call process_packet() for each captured packet.
                prn=detector.process_packet,

                #Do not keep captured packets in Scapy's memory.
                store=False,
            )

    #Ctrl+C raises a KeyboardInterrupt.
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    #The finally block always runs after finishing a PCAP, after Ctrl+C, or after most errors.
    finally:
        #Print the total number of fragments processed.
        detector.print_summary()

        #Close the fragment log file to ensure that all informatio is written and the file resource is released.
        detector.close()

if __name__ == "__main__":
    main()
