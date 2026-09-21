import argparse
from datetime import datetime  #for the log file fragments.log

from scapy.all import IP, sniff 


class OverlapDetectorV2:
    """
    Stateful version 2 detector:
    -Identifies fragmented IPv4 packets.
    -Stores all fragments for each (source, destination, protocol, IP ID) key.
    -Detects consecutive and non-consecutive overlaps, even out of order.
    -Compares the actual overlapping payload bytes.
    -Ignores exact fragment retransmissions.
    -Deletes a datagram's entry after all of its bytes have arrived.
    -Logs every fragment to a file.
    -Displays only overlap alerts in the terminal.

    The final boundary is not stored separately. Whenever completion is
    checked, it is derived from the end position of the stored MF=0 fragment.

    (because 
        attacker v2 will exploit this by sending many small incomplete fragmnts each belonging to a packet to 
        create overhead in processing and comparison)
    """

    def __init__(self, log_path="fragments.log"):
        #Each key maps directly to a list of fragments belonging to one incomplete IPv4 datagram.
        self.fragment_table = {}
        self.fragments_processed = 0
        self.overlaps_detected = 0
        self.retransmissions_ignored = 0
        self.datagrams_reassembled = 0
        self.log_path = log_path

        #Line buffering writes each log entry without waiting for the file to be completely filled or closed.
        #GPT implemented the logging logistics and syntax
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
            int(ip_packet.proto),  #FYI: protocol 17=UDP, proto 6=TCP, proto 1=ICMP
            int(ip_packet.id),  #unique identifier for each packet, so common among fragments of the same packet
        )
    '''
    So how does the fragment table look like? it stores as key the original packet source, destination, ID, 
    protocol, and as value the list of all fragments' details. To visualize:
    fragment_table = {
        (source, destination, protocol, IP_ID): [
            {"offset1"=...,"start1"=...,"end1"=...,"mf1"=...,"length1"=...,"payload1"...},
            {"offset2"=...,"start2"=...,"end2"=...,"mf2"=...,"length2"=...,"payload2"...},
        ]
    }
    '''

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

    @staticmethod
    def exact_retransmission(stored_fragment, current_fragment):
        same_start = (
            stored_fragment["start"]
            == current_fragment["start"])

        same_end = (
            stored_fragment["end"]
            == current_fragment["end"])

        same_mf = (
            stored_fragment["mf"]
            == current_fragment["mf"])

        same_payload = (
            stored_fragment["payload"]
            == current_fragment["payload"])

        return same_start and same_end and same_mf and same_payload

    @staticmethod
    def datagram_is_complete(stored_fragments):
        """
        This is so that the dictionary does not store every fragment of every processed packet forever 
        A datagram is complete only when: 
        1.Its final fragment (MF=0) has been received. 
        2.The stored byte ranges continuously cover byte 0 through the end of that final fragment, with no missing gap. 
        last_fragment_end_byte is calculated here

        When this function returns True, the completed datagram can be
        removed from the fragment dictionary.

        Incomplete datagrams will remain stored in this version.
        """

        final_fragment_ends = []

        #Look for a fragment that claims to be the final fragment.
        for fragment in stored_fragments:
            if fragment["mf"] == 0:
                final_fragment_ends.append(fragment["end"])

        #We cannot know the complete datagram size until MF=0 is received.
        if len(final_fragment_ends) == 0:
            return False

        #There should normally be only one MF=0 fragment.
        #If there are many (the attacker might exploit this), use the largest claimed ending position.
        last_fragment_end_byte = max(final_fragment_ends)

        #Sort the fragments according to where they belong in the datagram.
        def get_start_byte(fragment):
            return fragment["start"]   #returns the start byte of each stored fragment
        sorted_fragments = sorted(
            stored_fragments,
            key=get_start_byte, 
        )   #sorts stored frags according to start byte

        #This records how many bytes are continuously available from byte 0.
        covered_until = 0

        for fragment in sorted_fragments:
            fragment_start = fragment["start"]
            fragment_end = fragment["end"]

            #If the next fragment starts after covered_until, some bytes
            #between the fragments are still missing.
            if fragment_start > covered_until:
                return False

            #Extend the continuously covered range when this fragment
            #reaches farther than the previous fragments.
            if fragment_end > covered_until:
                covered_until = fragment_end

            #All bytes up to the final fragment's end are now available.
            if covered_until >= last_fragment_end_byte:
                return True

        return False

    def process_packet(self, packet):
        if IP not in packet: 
            return

        more_fragments = int(packet[IP].flags.MF)
        fragment_offset = int(packet[IP].frag)

        #A packet is ordinary and unfragmented only when: MF = 0 AND fragment offset = 0. ignore these
        if more_fragments==0 and fragment_offset==0:
            return

        self.fragments_processed = self.fragments_processed + 1 #add that fragment to the count of processed fragments
        
        """
        We had this false positives issue while testing, so we asked ChatGPT and it turned out that the 
        Ethernet padding is the issue, so some references and chat gave us a way to solve it detailed below:

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

        #Take only the payload bytes declared by the IPv4 header. Slicing the
        #serialized IPv4 packet this way also excludes Ethernet padding.
        ip_packet_bytes = bytes(packet[IP])  #this line makes the detector aware of byte content of the payload 
        # and not only the number of bytes, to be used in exact retransmission detection
        fragment_payload = ip_packet_bytes[ip_header_length : ip_header_length + payload_length]

        current_fragment = {
            "start": start_byte,
            "end": end_byte,
            "offset": fragment_offset,
            "mf": more_fragments,
            "length": payload_length,
            "payload": fragment_payload,
        }

        #Every fragment is recorded in the log file.
        self.log_fragment(
            ip_packet=packet[IP],
            more_fragments=more_fragments,
            fragment_offset=fragment_offset,
            start_byte=start_byte,
            end_byte=end_byte,
        )
        #Create an empty fragment list for a newly observed datagram key.
        if key not in self.fragment_table:
            self.fragment_table[key] = []

        stored_fragments = self.fragment_table[key]

        #First check whether this is the exact retransmission of a fragment
        #already stored for the same datagram. It is not stored or alerted.
        for stored_fragment in stored_fragments:
            if self.exact_retransmission(
                stored_fragment,
                current_fragment,
            ):
                self.retransmissions_ignored += 1
                return

        #CORE V2 LOGIC!!!
        #Compare the current fragment with every stored fragment. So even out of order overlaps are caught
        for stored_fragment in stored_fragments:
            stored_start = stored_fragment["start"]
            stored_end = stored_fragment["end"]

            overlap_start = max(start_byte, stored_start)
            overlap_end = min(end_byte, stored_end)
            #lets say stored fragment=[0;64) and current fragment=[32;90)
            #overlap start= max(32;0)= 32
            #overlap end= min(64;90)= 64 
            #so overlap= [32;64)
            if overlap_start < overlap_end:
                self.overlaps_detected = self.overlaps_detected+1
                overlap_size = overlap_end - overlap_start

                print("\n[ALERT] Overlapping IPv4 fragments detected")
                print("Source:", packet[IP].src)
                print("Destination:", packet[IP].dst)
                print("Protocol:", int(packet[IP].proto))
                print("IP ID:", int(packet[IP].id))
                print(f"Stored range: [{stored_start}, {stored_end})")
                print(f"Current range: [{start_byte}, {end_byte})")
                print(f"Overlapping range: [{overlap_start}, {overlap_end})")
                print("Overlap size:", overlap_size, "bytes")

        #Keep the fragment so later out-of-order fragments can be compared
        #against it.
        stored_fragments.append(current_fragment)

        #The dictionary is in volatile RAM. Explicitly remove this entry only
        #after its ranges cover byte 0 through the boundary claimed by MF=0.
        if self.datagram_is_complete(stored_fragments):
            self.datagrams_reassembled += 1
            del self.fragment_table[key]

    def print_summary(self):
        print("\nV2 LOGS SUMMARY: ")
        print(f"Fragments processed: {self.fragments_processed}")
        print(f"Overlaps detected: {self.overlaps_detected}")
        print(f"Exact retransmissions ignored: {self.retransmissions_ignored}")
        print(f"Completed datagrams discarded: {self.datagrams_reassembled}")
        print(f"Incomplete datagrams still stored: {len(self.fragment_table)}")
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
            "Detect stateful and out-of-order IPv4 fragment overlaps from either "
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
    detector = OverlapDetectorV2(
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

    #Ctrl C raises a KeyboardInterrupt.
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
