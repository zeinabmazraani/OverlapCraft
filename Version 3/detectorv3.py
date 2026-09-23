'''
This code's logic is fully human developed. therefore, I fully understand how detection works.
AI was used for assist in syntax and implementation.
Throughtout the code, I acknowledged GPT's contribution in comments and docstrings. 
'''

import argparse
import time
from datetime import datetime  # for the log file fragments.log

from scapy.all import IP, sniff 


class OverlapDetectorV3:
    """
    Stateful version 3 detector:
    -Identifies fragmented IPv4 packets.
    -Stores all fragments for each (source, destination, protocol, IP ID) key.
    -Detects consecutive and non-consecutive overlaps, even out of order.
    -Compares the actual overlapping payload bytes.
    -Ignores exact fragment retransmissions.
    -Deletes a datagram's entry after all of its bytes have arrived.
    -Expires incomplete datagrams after a fixed amount of time.
    -Limits the number of datagrams, fragments, and stored payload bytes.
    -Logs every fragment to a file.
    -Displays only overlap alerts in the terminal.

    The limits prevent an attacker from growing the dictionary and the
    fragment-comparison work without a bound. They are configurable because
    the best values depend on the machine and the expected network traffic.
    """

    def __init__(
        self,
        log_path="fragments.log",
        fragment_timeout=30, #to give margin for actual harmless fragments, this could be tighter as an improvement 
        max_datagrams=4096, #also configurable
        max_fragments_per_datagram=128, 
        #by choice, since the max IPv4 packet size with a standard MTU of 1.5k bytes would be 45 fragmnts
        #with a tighter MTU of 576 bytes would be 119 fragmnts, so 128 is like a safety margin
        max_buffered_bytes=16 * 1024 * 1024,
        max_log_bytes=5 * 1024 * 1024,
    ):
        # Each key maps directly to the fragments of one incomplete datagram.
        self.fragment_table = {}

        # Creation times are stored separately to keep fragment_table simple.
        # The creation time is never refreshed, so an attacker cannot keep an
        # incomplete entry forever by occasionally sending another fragment.
        self.datagram_creation_times = {}

        self.fragment_timeout = fragment_timeout
        self.max_datagrams = max_datagrams
        self.max_fragments_per_datagram = max_fragments_per_datagram
        self.max_buffered_bytes = max_buffered_bytes
        self.max_log_bytes = max_log_bytes
        self.buffered_payload_bytes = 0
        self.latest_packet_time = 0
        self.last_cleanup_time = 0

        self.fragments_processed = 0
        self.overlaps_detected = 0
        self.retransmissions_ignored = 0
        self.datagrams_reassembled = 0
        self.datagrams_expired = 0
        self.datagrams_evicted = 0
        self.datagrams_dropped_fragment_limit = 0
        self.datagrams_dropped_memory_limit = 0
        self.log_resets = 0
        self.state_exhaustion_warning_shown = False
        self.incomplete_fragment_warning_shown = False
        self.single_fragment_datagrams_expired = 0
        self.log_path = log_path

        #Performance measurements used to show whether the detector becomes slower
        #when many incomplete fragmented datagrams remain stored.
        self.fragments_currently_stored = 0
        self.total_processing_time_ms = 0.0
        self.total_cpu_time_ms = 0.0
        self.maximum_processing_time_ms = 0.0
        self.capture_start_time = time.perf_counter()

        if self.fragment_timeout <= 0:
            raise ValueError("fragment_timeout must be greater than zero")
        if self.max_datagrams <= 0:
            raise ValueError("max_datagrams must be greater than zero")
        if self.max_fragments_per_datagram <= 0:
            raise ValueError("max_fragments_per_datagram must be greater than zero")
        if self.max_buffered_bytes <= 0:
            raise ValueError("max_buffered_bytes must be greater than zero")
        if self.max_log_bytes <= 0:
            raise ValueError("max_log_bytes must be greater than zero")

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

        # Keep the log bounded too. Once it reaches the limit, begin a fresh
        # log instead of allowing attack traffic to fill the disk forever.
        if self.log_file.tell() >= self.max_log_bytes:
            self.log_file.close()
            self.log_file = open(
                self.log_path,
                mode="w",
                encoding="utf-8",
                buffering=1,
            )
            self.log_resets += 1
            self.log_file.write(
                "================ LOG SIZE LIMIT REACHED ================\n"
                "Previous fragment records were cleared.\n"
                "========================================================\n"
            )

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

    def log_fragment_performance(
        self,
        processing_started_at,
        wall_start,
        cpu_start,
        comparison_count,
    ):
        """Log when fragment processing finished and how much time and CPU it used."""

        #datetime gives readable start and finish timestamps for the log file.
        processing_finished_at = datetime.now()

        #perf_counter measures the real elapsed processing time, while
        #process_time measures only the CPU time used by this detector.
        processing_time_ms = (time.perf_counter() - wall_start) * 1000
        cpu_time_ms = (time.process_time() - cpu_start) * 1000

        #This percentage estimates how much of the fragment's elapsed processing
        #time was spent actively using the CPU.
        if processing_time_ms > 0:
            cpu_usage_percent = (cpu_time_ms / processing_time_ms) * 100
        else:
            cpu_usage_percent = 0.0

        self.total_processing_time_ms += processing_time_ms
        self.total_cpu_time_ms += cpu_time_ms

        if processing_time_ms > self.maximum_processing_time_ms:
            self.maximum_processing_time_ms = processing_time_ms

        self.log_file.write(
            f"PERFORMANCE "
            f"Started={processing_started_at.isoformat(timespec='microseconds')} "
            f"Finished={processing_finished_at.isoformat(timespec='microseconds')} "
            f"Processing_ms={processing_time_ms:.6f} "
            f"CPU_time_ms={cpu_time_ms:.6f} "
            f"CPU_usage_percent={cpu_usage_percent:.2f} "
            f"Comparisons={comparison_count} "
            f"Incomplete_datagrams={len(self.fragment_table)} "
            f"Stored_fragments={self.fragments_currently_stored}\n"
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

    def packet_capture_time(self, packet):
        """Return the packet's capture time, or the current time if unavailable."""
        try:
            captured_time = float(packet.time)
        except (AttributeError, TypeError, ValueError):
            captured_time = time.time()

        # PCAP timestamps can occasionally move backwards. Keeping this value
        # non-decreasing makes timeout behavior predictable.
        if captured_time > self.latest_packet_time:
            self.latest_packet_time = captured_time

        return self.latest_packet_time

    def remove_datagram(self, key):
        """Remove one datagram and update the amount of buffered data."""
        stored_fragments = self.fragment_table.pop(key, [])
        self.datagram_creation_times.pop(key, None)

        #Keep the stored-fragment performance counter synchronized with the table.
        self.fragments_currently_stored -= len(stored_fragments)

        if self.fragments_currently_stored < 0:
            self.fragments_currently_stored = 0

        for fragment in stored_fragments:
            self.buffered_payload_bytes -= fragment["length"]

        # This guard avoids displaying a negative value if state was already
        # empty because of malformed or unexpected input.
        if self.buffered_payload_bytes < 0:
            self.buffered_payload_bytes = 0

    def remove_expired_datagrams(self, current_time):
        """Remove incomplete datagrams that exceeded the absolute timeout."""
        # Checking once per second avoids scanning state for every packet.
        if current_time - self.last_cleanup_time < 1:
            return

        self.last_cleanup_time = current_time

        # Python dictionaries keep insertion order. Because creation times are
        # never refreshed, the first key is always the oldest one.
        while len(self.datagram_creation_times) > 0:
            oldest_key = next(iter(self.datagram_creation_times))
            creation_time = self.datagram_creation_times[oldest_key]

            if current_time - creation_time < self.fragment_timeout:
                break

            #An expired datagram that contains only one fragment may mean that
            #someone is creating many unfinished datagrams to consume resources.
            stored_fragment_count = len(self.fragment_table.get(oldest_key, []))

            if stored_fragment_count == 1:
                self.single_fragment_datagrams_expired += 1
                self.warn_about_incomplete_fragment_attack(
                    oldest_key,
                    current_time - creation_time,
                )

            self.remove_datagram(oldest_key)
            self.datagrams_expired=self.datagrams_expired + 1

    def remove_oldest_datagram(self):
        """Remove the oldest incomplete datagram from the table."""
        if len(self.datagram_creation_times) == 0:
            return

        oldest_key = next(iter(self.datagram_creation_times))

        self.remove_datagram(oldest_key)
        self.datagrams_evicted=self.datagrams_evicted+ 1

    def warn_about_state_exhaustion(self, reason):
        """Display one warning when a resource limit is reached."""
        if self.state_exhaustion_warning_shown:
            return

        self.state_exhaustion_warning_shown = True
        print("\n[WARNING] Possible fragment-state exhaustion attack")
        print("Reason:", reason)
        print("The detector is discarding incomplete fragment state.\n")

    def warn_about_incomplete_fragment_attack(self, key, datagram_age):
        """Warn once when a one-fragment incomplete datagram expires."""
        if self.incomplete_fragment_warning_shown:
            return

        self.incomplete_fragment_warning_shown = True
        source, destination, protocol, ip_id = key

        print("\n[WARNING] Possible Overlap Starvation resource-exhaustion attack")
        print("An incomplete datagram expired with only one fragment stored.")
        print("Source:", source)
        print("Destination:", destination)
        print("Protocol:", protocol)
        print("IP ID:", ip_id)
        print(f"Datagram age: {datagram_age:.2f} seconds")
        print("Repeated cases may indicate an attempt to fill the fragment table.\n")

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

        Incomplete datagrams are eventually removed by the timeout.
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

        #Record when processing starts. perf_counter is used for elapsed time,
        #and process_time is used for the CPU time consumed by this fragment.
        processing_started_at = datetime.now()
        wall_start = time.perf_counter()
        cpu_start = time.process_time()
        comparison_count = 0

        current_time = self.packet_capture_time(packet)

        # Old incomplete entries are cleared before handling the new packet.
        self.remove_expired_datagrams(current_time)

        more_fragments = int(packet[IP].flags.MF)
        fragment_offset = int(packet[IP].frag)

        #A packet is ordinary and unfragmented only when: MF = 0 AND fragment offset = 0. ignore these
        if more_fragments == 0 and fragment_offset == 0:
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

        if payload_length <= 0:
            #Record performance even when an invalid fragment returns early.
            self.log_fragment_performance(
                processing_started_at,
                wall_start,
                cpu_start,
                comparison_count,
            )
            return

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
        # Create an empty list for a newly observed datagram. If the global
        # table is full, remove the oldest incomplete entry first. This limit
        # is global, so changing or spoofing the source address cannot bypass it.
        if key not in self.fragment_table:
            if len(self.fragment_table) >= self.max_datagrams:
                self.remove_oldest_datagram()
                self.warn_about_state_exhaustion(
                    "the maximum number of incomplete datagrams was reached"
                )

            self.fragment_table[key] = []
            self.datagram_creation_times[key] = current_time

        stored_fragments = self.fragment_table[key]

        #First check whether this is the exact retransmission of a fragment
        #already stored for the same datagram. It is not stored or alerted.
        for stored_fragment in stored_fragments:
            #Count each explicit stored-fragment comparison performed by the detector.
            comparison_count += 1
            if self.exact_retransmission(
                stored_fragment,
                current_fragment,
            ):
                self.retransmissions_ignored += 1
                #Record the finish time even though a retransmission returns early.
                self.log_fragment_performance(
                    processing_started_at,
                    wall_start,
                    cpu_start,
                    comparison_count,
                )
                return

        # One datagram cannot create unlimited comparison work. The current
        # fragment is not stored when this limit has already been reached.
        if len(stored_fragments) >= self.max_fragments_per_datagram:
            self.remove_datagram(key)
            self.datagrams_dropped_fragment_limit += 1
            self.warn_about_state_exhaustion(
                "one datagram reached the fragment limit"
            )
            #Record the finish time before returning after the fragment limit.
            self.log_fragment_performance(
                processing_started_at,
                wall_start,
                cpu_start,
                comparison_count,
            )
            return

        # The byte limit bounds the total payload memory. To keep the policy
        # simple, the current datagram is discarded if its new fragment would
        # push the whole detector above the limit.
        if self.buffered_payload_bytes + payload_length > self.max_buffered_bytes:
            self.remove_datagram(key)
            self.datagrams_dropped_memory_limit += 1
            self.warn_about_state_exhaustion(
                "the total buffered-payload limit was reached"
            )
            #Record the finish time before returning after the memory limit.
            self.log_fragment_performance(
                processing_started_at,
                wall_start,
                cpu_start,
                comparison_count,
            )
            return

        #CORE V2 LOGIC!!!
        #Compare the current fragment with every stored fragment. So even out of order overlaps are caught
        for stored_fragment in stored_fragments:
            #Count each explicit stored-fragment comparison performed by the detector.
            comparison_count += 1
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
        self.buffered_payload_bytes += payload_length
        self.fragments_currently_stored += 1

        #The dictionary is in volatile RAM. Explicitly remove this entry only
        #after its ranges cover byte 0 through the boundary claimed by MF=0.
        if self.datagram_is_complete(stored_fragments):
            self.datagrams_reassembled += 1
            self.remove_datagram(key)

        #Record the finishing timestamp and performance indicators for this fragment.
        self.log_fragment_performance(
            processing_started_at,
            wall_start,
            cpu_start,
            comparison_count,
        )

    def print_summary(self):
        #Calculate overall averages and throughput for this capture session.
        capture_duration_seconds = time.perf_counter() - self.capture_start_time

        if self.fragments_processed > 0:
            average_processing_time_ms = (
                self.total_processing_time_ms / self.fragments_processed
            )
            average_cpu_time_ms = (
                self.total_cpu_time_ms / self.fragments_processed
            )
        else:
            average_processing_time_ms = 0.0
            average_cpu_time_ms = 0.0

        if capture_duration_seconds > 0:
            fragments_per_second = (
                self.fragments_processed / capture_duration_seconds
            )
        else:
            fragments_per_second = 0.0

        print("\nV2 LOGS SUMMARY: ")
        print(f"Fragments processed: {self.fragments_processed}")
        print(f"Overlaps detected: {self.overlaps_detected}")
        print(f"Exact retransmissions ignored: {self.retransmissions_ignored}")
        print(f"Completed datagrams discarded: {self.datagrams_reassembled}")
        print(f"Expired incomplete datagrams: {self.datagrams_expired}")
        print(
            "Expired datagrams containing only one fragment: "
            f"{self.single_fragment_datagrams_expired}"
        )
        print(f"Old datagrams evicted: {self.datagrams_evicted}")
        print(
            "Datagrams dropped by fragment limit: "
            f"{self.datagrams_dropped_fragment_limit}"
        )
        print(
            "Datagrams dropped by memory limit: "
            f"{self.datagrams_dropped_memory_limit}"
        )
        print(f"Incomplete datagrams still stored: {len(self.fragment_table)}")
        print(f"Fragments currently stored: {self.fragments_currently_stored}")
        print(f"Payload bytes still buffered: {self.buffered_payload_bytes}")
        print(f"Average processing time: {average_processing_time_ms:.6f} ms")
        print(f"Maximum processing time: {self.maximum_processing_time_ms:.6f} ms")
        print(f"Average CPU time: {average_cpu_time_ms:.6f} ms")
        print(f"Processing throughput: {fragments_per_second:.2f} fragments/second")
        print(f"Log resets after size limit: {self.log_resets}")
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
    #Executed by chatGPT
    input_group = parser.add_mutually_exclusive_group(required=True)

    input_group.add_argument(
        "-i",
        "--interface",
        help="Network interface to monitor for live traffic.",)

    input_group.add_argument(
        "-r",
        "--pcap",
        help="PCAP file to analyze offline.",)

    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
        help="Maximum incomplete-datagram lifetime in seconds (default: 30).",)

    parser.add_argument(
        "--max-datagrams",
        type=int,
        default=4096,
        help="Maximum incomplete datagrams stored at once (default: 4096).",)

    parser.add_argument(
        "--max-fragments",
        type=int,
        default=128,
        help="Maximum fragments stored for one datagram (default: 128).",)

    parser.add_argument(
        "--max-buffered-bytes",
        type=int,
        default=16 * 1024 * 1024,
        help="Maximum payload bytes stored across all datagrams.",)

    parser.add_argument(
        "--max-log-bytes",
        type=int,
        default=5 * 1024 * 1024,
        help="Maximum fragments.log size before it is restarted.",)

    #Read the arguments provided by the user in the terminal.
    #The results are stored inside the args object.
    parser_arguments = parser.parse_args()

    #Always write fragment information to fragments.log.
    detector = OverlapDetectorV3(
        log_path="fragments.log",
        fragment_timeout=parser_arguments.timeout,
        max_datagrams=parser_arguments.max_datagrams,
        max_fragments_per_datagram=parser_arguments.max_fragments,
        max_buffered_bytes=parser_arguments.max_buffered_bytes,
        max_log_bytes=parser_arguments.max_log_bytes,
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

    finally:
        #Print the total number of fragments processed.
        detector.print_summary()

        #Close the fragment log file to ensure that all informatio is written and the file resource is released.
        detector.close()

if __name__ == "__main__":
    main()
