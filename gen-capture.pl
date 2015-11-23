#!/usr/bin/perl

use strict;
use warnings;
use Switch;

# Subroutine prototypes
sub SYNC ();

system $^O eq 'MSWin32' ? 'cls' : 'clear';

my $pcap_file = "file.pcap";
my $packet_length;
my $packet_value;
my $pcap_header;
my $packet_timestamp = "0000000000000000";
my $frame_number = 1;
my $last_frame = 0;
my $frame_type;

$pcap_header = "D4C3B2A1020004000000000000000000000004008F000000";

print "\n  Pcap filename to be saved:  ";
$pcap_file = <>;

open PCAP_FILE, '>>' . $pcap_file;
binmode(PCAP_FILE);

print PCAP_FILE pack "H*", $pcap_header;

while ($last_frame != 1) {
  system $^O eq 'MSWin32' ? 'cls' : 'clear';
  printf ("\n  Following packet types can be generated:\n\n");
  printf ("   1) SYNC     16)          31)          46)          61) Special OFDM Packet  \n");
  printf ("   2)          17)          32)          47)                                   \n");
  printf ("   3)          18)          33)          48)                                   \n");
  printf ("   4)          19)          34)          49)                                   \n");
  printf ("   5)          20)          35)          50)                                   \n");
  printf ("   6)          21)          36)          51)                                   \n");
  printf ("   7)          22)          37)          52)                                   \n");
  printf ("   8)          23)          38)          53)                                   \n");
  printf ("   9)          24)          39)          54)                                   \n");
  printf ("  10)          25)          40)          55)                                   \n");
  printf ("  11)          26)          41)          56)                                   \n");
  printf ("  12)          27)          42)          57)                                   \n");
  printf ("  13)          28)          43)          58)                                   \n");
  printf ("  14)          29)          44)          59)                                   \n");
  printf ("  15)          30)          45)          60)                                   \n");
  printf "\n  Frame " . $frame_number . " - Choose packet type which will be generated:  ";
  $frame_type = <>;
  switch ($frame_type) {
    case 1 {
      ($packet_length, $packet_value) = SYNC();
    } 
    else {
      ($packet_length, $packet_value) = SYNC();
    }
  }
  ($packet_length, $packet_value) = SYNC();
  print PCAP_FILE pack "H*", $packet_timestamp;
  print PCAP_FILE pack "V", $packet_length;
  print PCAP_FILE pack "V", $packet_length;
  print PCAP_FILE pack "H*", $packet_value;
  printf "\n  Is this last Frame in the PCAP capture file? (Choose: 1 for YES / 0 for NO)  ";
  $last_frame = <>;
  $frame_number++;
}

printf "\n  Your packets were stored in file:    " . $pcap_file . "\n\n";

close PCAP_FILE;

sub SYNC() {
  our $SYNC_length;
  our $SYNC_value;
  $SYNC_length = 0;
  $SYNC_value = "000003010100000000";
  $SYNC_value = $SYNC_value . sprintf("%02x", rand(0xFF));
  $SYNC_length = $SYNC_length + 10;
  $SYNC_value = sprintf("%04x", $SYNC_length) . $SYNC_value;
  $SYNC_length = $SYNC_length + 2;
  for (my $i = 0; $i < 3; $i++) {
    $SYNC_value = sprintf("%02x", rand(0xFF)) . $SYNC_value;
    $SYNC_length = $SYNC_length + 1;
  }
  $SYNC_value = "001DCE" . $SYNC_value;
  $SYNC_length = $SYNC_length + 3;
  for (my $i = 0; $i < 3; $i++) {
    $SYNC_value = sprintf("%02x", rand(0xFF)) . $SYNC_value;
    $SYNC_length = $SYNC_length + 1;
  }
  $SYNC_value = "001DCE" . $SYNC_value;
  $SYNC_length = $SYNC_length + 3;
  $SYNC_value = "0000" . $SYNC_value;
  $SYNC_value = sprintf("%04x", $SYNC_length) . $SYNC_value;
  $SYNC_length = $SYNC_length + 4;
  $SYNC_value = "C000" . $SYNC_value;
  $SYNC_length = $SYNC_length + 2;
  return ($SYNC_length, $SYNC_value);
}