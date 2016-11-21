#!/usr/bin/expect

set timeout 1

spawn "./gen-capture.pl"

# Choose filename
sleep 0.1
expect ":  "
send "OK.pcap\r"

for {set i 0} {$i < 1} {incr i 1} {

    # SYNC
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
    send "0\r"
    # TLV 3
    expect ":  "
    send "3\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 4
    expect ":  "
    send "4\r"
    # TLV 4.1
    expect ":  "
    send "1\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.2
    expect ":  "
    send "2\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.3
    expect ":  "
    send "3\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.4
    expect ":  "
    send "4\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.5
    expect ":  "
    send "5\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.6
    expect ":  "
    send "6\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.7
    expect ":  "
    send "7\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.8
    expect ":  "
    send "8\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.9
    expect ":  "
    send "9\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.10
    expect ":  "
    send "10\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 4.11
    expect ":  "
    send "11\r"
    # Last sub-TLV
    expect ")  "
    send "1\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 5
    expect ":  "
    send "5\r"
    # TLV 5.1
    expect ":  "
    send "1\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.2
    expect ":  "
    send "2\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.3
    expect ":  "
    send "3\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.4
    expect ":  "
    send "4\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.5
    expect ":  "
    send "5\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.6
    expect ":  "
    send "6\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.7
    expect ":  "
    send "7\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.8
    expect ":  "
    send "8\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.9
    expect ":  "
    send "9\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.10
    expect ":  "
    send "10\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.11
    expect ":  "
    send "11\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.12
    expect ":  "
    send "12\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.13
    expect ":  "
    send "13\r"
    # Next sub-TLV
    expect ")  "
    send "0\r"
    # TLV 5.14
    expect ":  "
    send "14\r"
    # Last sub-TLV
    expect ")  "
    send "1\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 6
    expect ":  "
    send "6\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 7
    expect ":  "
    send "7\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 15
    expect ":  "
    send "15\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 16
    expect ":  "
    send "16\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 18
    expect ":  "
    send "18\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 19
    expect ":  "
    send "19\r"
    # Last TLV
    expect ")  "
    send "1\r"
    # Next packet
    expect ")  "
    send "0\r"

    # Version 1 MAP
    expect ":  "
    send "3a\r"
    # Next packet
    expect ")  "
    send "0\r"

    # RNG-REQ
    expect ":  "
    send "4\r"
    # Next packet
    expect ")  "
    send "0\r"

    # RNG-RSP
    expect ":  "
    send "5\r"
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
    send "0\r"
    # TLV 3
    expect ":  "
    send "3\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 4
    expect ":  "
    send "4\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 5
    expect ":  "
    send "5\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 6
    expect ":  "
    send "6\r"
    # Next TLV
    expect ")  "
    send "0\r"
    # TLV 7
    expect ":  "
    send "7\r"
    # Last TLV
    expect ")  "
    send "1\r"
    # Next packet
    expect ")  "
    send "0\r"

    # Request Frame (minislots)
    expect ":  "
    send "a\r"
    # Next packet
    expect ")  "
    send "0\r"

    # Request Frame (bytes)
    expect ":  "
    send "b\r"
    # Next packet
    expect ")  "
    send "0\r"

}

# Last SYNC packet
expect ":  "
send "1\r"
# Next packet
expect ")  "
send "1\r"

expect " "
send "\r"

exit