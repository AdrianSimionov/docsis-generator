#!/usr/bin/expect

set timeout 1

spawn "./gen-capture.pl"

# Choose filename
expect ":  " 
send "OK.pcap\r"

# SYNC packet
expect ":  "
send "1\r"
# Next packet
expect ")  "
send "0\r"

# Type 2 UCD
expect ":  "
send "2\r"
# TLV 1
expect ":  "
send "1\r"
# Next TLV
expect ")  "
send "0\r"
# TLV 2
expect ":  "
send "2\r"
# Next TLV
expect ")  "
send "1\r"

# Last packet
expect ")  "
send "1\r\r"

# print exit code
expect " "
send "\r"

exit