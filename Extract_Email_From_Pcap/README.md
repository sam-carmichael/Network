# Extract email from pcap

To get a better sense of Network protocal, I did the project.

The goal of project is to extract the content of email from the packet capture of network.
It was completed in 2013, at that time, my IDE is Visual Studio 2008, so the dependency is WinPcap_4_1_3.exe

The protocal of email: POP3<br>
The file format of packet capture: pcap file.

The src folder includes the source code.

The test_file includees the file of test:
+ input file: Input_File/topcoder_csdn.pcap
+ output file: Output_File/121_195_178_52_110_222_29_65_228_1592.txt

How to verify the result?
Open the topcoder_csdn.pcap with [Wireshark](https://www.wireshark.org/), input "tcp.port == 110" in the DisplayFilters of textbook, select any Frame, then use "Follow -> TCP Stream" to verify the result.
