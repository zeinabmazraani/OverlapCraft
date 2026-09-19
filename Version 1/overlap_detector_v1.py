import argparse 
from collections import defaultdict 
#it was gpt's idea to use defaultdict instead of normal dictionary to dynamially create an entry everytime a new key is seen (so new packet with new src, dst, prot, ID)

from scapy.all import IP, sniff
#I thought about the logic and pseudocode, GPT helped with syntax and a few implementation fixes

class OverlapDetectorV1:
    """
    V1 detector:
    - Groups IPv4 fragments belonging to the same original packet.
    - Calculates each fragment's byte range.
    - Alerts when two fragment ranges overlap.
    """

    def __init__(self):
        self.fragment_table = defaultdict(list)
        self.fragments_processed = 0
        self.overlaps_detected = 0

    @staticmethod
    def fragment_key(ip_packet):
        """
        These fields identify fragments belonging to the same
        original IPv4 packet. It makes up the key in the dictionary
        """
        return (
            ip_packet.src,
            ip_packet.dst,
            int(ip_packet.proto), #FYI: protocol 17=UDP, prot 6=TCP, prot 1=ICMP
            int(ip_packet.id),
        )

    def process_packet(self, packet):
        if IP not in packet:
            return

        ip_packet = packet[IP]

        more_fragments = int(ip_packet.flags.MF)
        fragment_offset = int(ip_packet.frag)

        # Ignore ordinary and unfragmented IPv4 packets
        if more_fragments == 0 and fragment_offset == 0:
            return

        self.fragments_processed = self.fragments_processed + 1

        # IPv4 fragment offsets are measured in blocks of 8 bytes
        start_byte = fragment_offset * 8
        fragment_data = bytes(ip_packet.payload)  #convertng packet data into raw bytes (to be used better in V2)
        end_byte = start_byte + len(fragment_data) #len returns the nb of payload bytes

        key = self.fragment_key(ip_packet) #dict key, and dict value is src, dst, and so on

        print(
            f"[FRAGMENT] Source={ip_packet.src} "
            f"Destination={ip_packet.dst} "
            f"ID={ip_packet.id} "
            f"Range=[{start_byte}, {end_byte})"
        )

        # CORE LOGIC!!!!!
        # Compare the new fragment with every fragment already stored in the dictionary as key value pairs for this same IPv4 packet.
        for previous_fragment in self.fragment_table[key]:
            previous_start = previous_fragment["start"]
            previous_end = previous_fragment["end"]

            overlap_start = max(start_byte, previous_start) 
            overlap_end = min(end_byte, previous_end)

            if overlap_start < overlap_end:
                overlap_size = overlap_end - overlap_start
                self.overlaps_detected = self.overlaps_detected + 1

                print("\n[ALERT] OVERLAPPING IPv4 FRAGMENTS")
                print(f"  Source: {ip_packet.src}")
                print(f"  Destination: {ip_packet.dst}")
                print(f"  Protocol: {ip_packet.proto}")
                print(f"  IP ID: {ip_packet.id}")
                print(
                    f"  Previous:     "
                    f"[{previous_start}, {previous_end})"
                )
                print(f"  New: [{start_byte}, {end_byte})")
                print(
                    f"  Overlap:      "
                    f"[{overlap_start}, {overlap_end})"
                )
                print(f"  Overlap size: {overlap_size} bytes\n")

        self.fragment_table[key].append(
            {
                "start": start_byte,
                "end": end_byte,
                "data": fragment_data,
            }
        )

    def print_summary(self):
        print("\n========== V1 DETECTION SUMMARY ==========")
        print(f"Fragments processed: {self.fragments_processed}")

        print("==========================================")


def main():
    parser = argparse.ArgumentParser(
        description="Detect overlapping IPv4 fragments from live network traffic."
    )
    parser.add_argument(
        "interface",
        help="Network interface that should be monitored.",
    )
    args = parser.parse_args()

    detector = OverlapDetectorV1()

    print(f"Listening for IPv4 traffic on interface: {args.interface}")
    print("Press Ctrl+C to stop the detector.\n")

    try:
        sniff(
            iface=args.interface,
            filter="ip",
            prn=detector.process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        detector.print_summary()


if __name__ == "__main__":
    main()