Docsis packet generator
=======================

This tool can be used to generate various DOCSIS packets.

I use it mainly to generate packets for fuzz-testing of the Wireshark DOCSIS dissector and
to test the quality of the dissector.
It can be used for training purposes also.
The packets generated are stored in a PCAP file format. It can be understood by Wireshark and tshark.

Field values are not trying to be Cablelabs compliant at all, at least at this stage.

Bug reporting
-------------

Please use the GitHub system to report feature request and bugs.