Docsis packet generator
=======================

This tool can be used to generate various DOCSIS packets.

I use it mainly to generate packets for fuzz-testing of the Wireshark DOCSIS dissector and
to test the quality of the dissector.
It can be used for training purposes also.
The packets generated are stored in a PCAP file format. It can be understood by Wireshark and tshark.

Field values are not trying to be Cablelabs compliant at all, at least at this stage.

Usage
-----

```
./gen-capture.pl [--pcap=<filename>] [--all]
```

`--pcap = <filename>`

  * Provide pcap file without being prompted by application.
  
`--all`

  * Write out all TLVs/sub TLVs.

Bug reporting
-------------

Please use the GitHub system to report feature request and bugs.