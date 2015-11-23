#!/usr/bin/perl

use strict;
use warnings;
use Switch;

# Subroutine prototypes
sub SYNC ();
sub request_minislots();
sub request_bytes();

# system $^O eq 'MSWin32' ? 'cls' : 'clear';

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

open PCAP_FILE, '>' . $pcap_file;
binmode(PCAP_FILE);

print PCAP_FILE pack "H*", $pcap_header;

while ($last_frame != 1) {
#  system $^O eq 'MSWin32' ? 'cls' : 'clear';
  print "\n  Following packet types can be generated:\n\n";
  print "   1) SYNC     16)          31)          46)          61) Special OFDM Packet        \n";
  print "   2)          17)          32)          47)                                         \n";
  print "   3)          18)          33)          48)           a) Request Frame (minislots)  \n";
  print "   4)          19)          34)          49)           b) Request Frame (bytes)      \n";
  print "   5)          20)          35)          50)                                         \n";
  print "   6)          21)          36)          51)                                         \n";
  print "   7)          22)          37)          52)                                         \n";
  print "   8)          23)          38)          53)                                         \n";
  print "   9)          24)          39)          54)                                         \n";
  print "  10)          25)          40)          55)                                         \n";
  print "  11)          26)          41)          56)                                         \n";
  print "  12)          27)          42)          57)                                         \n";
  print "  13)          28)          43)          58)                                         \n";
  print "  14)          29)          44)          59)                                         \n";
  print "  15)          30)          45)          60)                                         \n";
  print "\n  Frame " . $frame_number . " - Choose packet type which will be generated:  ";
  $frame_type = <>;
  chomp $frame_type;
  switch ($frame_type) {
    case 1 {
      ($packet_value, $packet_length) = SYNC();
    } 
    case "a" {
      ($packet_value, $packet_length) = request_minislots();
    }
    case "b" {
      ($packet_value, $packet_length) = request_bytes();
    }
    else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
    }
  }
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
  our $packet_value;
  our $packet_length = 0;
  # Add SYNC Message
  $packet_value = "000000" . sprintf("%02x", rand(0xFF));
  $packet_length = $packet_length + 4;
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "01", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 0, 0);
  return ($packet_value, $packet_length);
}

sub request_minislots() {
  our $packet_value = "";
  our $packet_length = 0;
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, sprintf("%02x", rand(0xFF)), 192, 4, 0);
  return ($packet_value, $packet_length);
}

sub request_bytes() {
  our $packet_value = "";
  our $packet_length = 0;
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, sprintf("%02x", rand(0xFF)), 192, 8, 0);
  return ($packet_value, $packet_length);
}

# value, length, dsap, ssap, version, type, reserved/multipart
sub add_mac_management () {
  our @input = @_;
  our $packet_value;
  our $packet_length;
  our $i;
  # Add Reserved/Multipart field
  $packet_value = $input[6] . $input[0];
  $packet_length = $input[1] + 1;
  # Add Type field
  $packet_value = $input[5] . $packet_value;
  $packet_length = $packet_length + 1;
  # Add Version field
  $packet_value = $input[4] . $packet_value;
  $packet_length = $packet_length + 1;
  # Add Control field
  $packet_value = "03" . $packet_value;
  $packet_length = $packet_length + 1;
  # Add SSAP field
  $packet_value = $input[3] . $packet_value;
  $packet_length = $packet_length + 1;
  # Add DSAP field
  $packet_value = $input[2] . $packet_value;
  $packet_length = $packet_length + 1;
  # Add Length field
  $packet_value = sprintf("%04x", $packet_length) . $packet_value;
  $packet_length = $packet_length + 2;
  # Add Source MAC Address
  for ($i = 0; $i < 3; $i++) {
    $packet_value = sprintf("%02x", rand(0xFF)) . $packet_value;
    $packet_length = $packet_length + 1;
  }
  $packet_value = "00015C" . $packet_value;
  $packet_length = $packet_length + 3;
  # Add Destination MAC Address
  for ($i = 0; $i < 3; $i++) {
    $packet_value = sprintf("%02x", rand(0xFF)) . $packet_value;
    $packet_length = $packet_length + 1;
  }
  $packet_value = "00015C" . $packet_value;
  $packet_length = $packet_length + 3;
  return ($packet_value, $packet_length);
}

# value, length, hcs, ehdr, macparm, fc_type (64/128/192), fc_parm (2..62), ehdr_on (0/1)
sub add_docsis () {
  our @input = @_;
  our $packet_value;
  our $packet_length;
  switch ($input[6]) {
    case 0 {
      # Add HCS field
      $packet_value = $input[2] . $input[0];
      $packet_length = $input[1] + 2;
      # TODO Add ehdr field
      # Add Length field
      $packet_value = sprintf("%04x", $packet_length) . $packet_value;
      $packet_length = $packet_length + 2;
      # Add MAC_PARM field
      $packet_value = $input[4] . $packet_value;
      use bytes;
      $packet_length = $packet_length + (length (pack "H*", $input[4]));
      no bytes;
      # Add Frame Control (FC) field
      $packet_value = sprintf("%02x", $input[5] + $input[6] + $input[7]) . $packet_value;
      $packet_length = $packet_length + 1;
      last;
    }
    case 4 {
      # Add HCS field
      $packet_value = $input[2] . $input[0];
      $packet_length = $input[1] + 2;
      # Add SID
      $packet_value = sprintf("%04x", rand(0x3FFF)) . $packet_value;
      $packet_length = $packet_length + 2;
      # Add Minislots field
      $packet_value = sprintf("%02x", rand(0xFF)) . $packet_value;
      $packet_length = $packet_length + 1;
      # Add Frame Control (FC) field
      $packet_value = sprintf("%02x", $input[5] + $input[6] + $input[7]) . $packet_value;
      $packet_length = $packet_length + 1;
      last;
    }
    case 8 {
      # Add HCS field
      $packet_value = $input[2] . $input[0];
      $packet_length = $input[1] + 2;
      # Add SID
      $packet_value = sprintf("%04x", rand(0x3FFF)) . $packet_value;
      $packet_length = $packet_length + 2;
      # Add Bytes field
      $packet_value = sprintf("%04x", rand(0xFF)) . $packet_value;
      $packet_length = $packet_length + 2;
      # Add Frame Control (FC) field
      $packet_value = sprintf("%02x", $input[5] + $input[6] + $input[7]) . $packet_value;
      $packet_length = $packet_length + 1;
      last;
    }
  }
  return ($packet_value, $packet_length);
}