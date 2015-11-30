#!/usr/bin/perl

use strict;
use warnings;
use Switch;

# Subroutine prototypes
sub SYNC ();
sub type2UCD();
sub RNG_REQ();
sub type29UCD();
sub B_INIT_RNG_REQ();
sub type35UCD();
sub request_minislots();
sub request_bytes();
sub random_bits;

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
  print "   1) SYNC         16)               31)                  46)               61)                             \n";
  print "   2) Type 2 UCD   17)               32)                  47)                                               \n";
  print "   3)              18)               33)                  48)                a) Request Frame (minislots)   \n";
  print "   4) RNG-REQ      19)               34) B-INIT-RNG-REQ   49)                b) Request Frame (bytes)       \n";
  print "   5)              20)               35) Type 35 UCD      50)                                               \n";
  print "   6)              21)               36)                  51)                                               \n";
  print "   7)              22)               37)                  52)                                               \n";
  print "   8)              23)               38)                  53)                                               \n";
  print "   9)              24)               39)                  54)                                               \n";
  print "  10)              25)               40)                  55)                                               \n";
  print "  11)              26)               41)                  56)                                               \n";
  print "  12)              27)               42)                  57)                                               \n";
  print "  13)              28)               43)                  58)                                               \n";
  print "  14)              29) Type 29 UCD   44)                  59)                                               \n";
  print "  15)              30)               45)                  60)                                               \n";
  print "\n  Frame " . $frame_number . " - Choose packet type which will be generated:  ";

  $frame_type = <>;
  chomp $frame_type;
  switch ($frame_type) {
    case 1 {
      ($packet_value, $packet_length) = SYNC();
    }
    case 2 {
      ($packet_value, $packet_length) = type2UCD();
    }
    case 4 {
      ($packet_value, $packet_length) = RNG_REQ();
    }
    case 29 {
      ($packet_value, $packet_length) = type29UCD();
    }
    case 34 {
      ($packet_value, $packet_length) = B_INIT_RNG_REQ();
    }
    case 35 {
      ($packet_value, $packet_length) = type35UCD();
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

sub type2UCD() {
  our $packet_value;
  our $packet_length;
  our $last_tlv = 0;
  our $last_sub_tlv = 0;
  our $choosen_tlv;
  our $choosen_sub_tlv;
  our $tlv_number = 1;
  our $sub_tlv_number = 1;
  our $sub_tlv_value;
  our $sub_tlv_length;
  our $i;
  our $j;
  # Add Upstream Channel ID field
  $packet_value = sprintf("%02x", rand(0xFF));
  $packet_length = 1;
  # Add Config Change Count field
  $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
  $packet_length = $packet_length + 1;
  # Add Minislot Size field
  $packet_value = $packet_value . sprintf("%02x", 2 ** rand(0x8));
  $packet_length = $packet_length + 1;
  # Add Downstream Channel ID field
  $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
  $packet_length = $packet_length + 1;
  # Add TLV data
  while ($last_tlv != 1) {
    print "\n  Following TLVs can be added:\n\n";
    print "   1) Modulation Rate\n";
    print "   2) Frequency\n";
    print "   3) Preamble Pattern\n";
    print "   4) Burst Descriptor (DOCSIS 1.x)\n";
    print "      ...\n";
    print "   5) Burst Descriptor (DOCSIS 2.0/3.0)\n";
    print "      ...\n";
    print "   6) Extended Preamble Pattern\n";
    print "   7) S-CDMA Mode Enable\n";
    print "  15) Maintain Power Spectral Density\n";
    print "  16) Ranging Required\n";
    print "  18) Ranging Hold-Off Priority Field\n";
    print "  19) Channel Class ID\n";
    print "\n  TLV " . $tlv_number . " - Choose TLV which should be added:  ";
    $choosen_tlv = <>;
    chomp $choosen_tlv;
    switch ($choosen_tlv) {
      case 1 {
        $packet_value = $packet_value . "01" . "01" . sprintf("%02x", 2 ** rand(0x5));
        $packet_length = $packet_length + 3;
      }
      case 2 {
        $packet_value = $packet_value . "02" . "04" . sprintf("%08x", (int(rand(80)) + 5) * 1000000);
        $packet_length = $packet_length + 6;
      }
      case 3 {
        $i = int(rand(127)) + 1;
        $packet_value = $packet_value . "03" . sprintf("%02x", $i);
        for (my $j = 0; $j < $i; $j++) {
          $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
        }
        $packet_length = $packet_length + $i + 2;
      }
      case 4 {
        # Create BURST4 sub-TLVs
        $sub_tlv_value = "";
        $sub_tlv_length = 0;
        $last_sub_tlv = 0;
        while ($last_sub_tlv != 1) {
          print "\n  Following sub-TLVs can be added:\n\n";
          print "   1) Modulation Type\n";
          print "   2) Differential Encoding\n";
          print "   3) Preamble Length\n";
          print "   4) Preamble Value Offset\n";
          print "   5) FEC Error Correction (T)\n";
          print "   6) FEC Codeword Information Bytes (k)\n";
          print "   7) Scrambler Seed\n";
          print "   8) Maximum Burst Size\n";
          print "   9) Guard Time Size\n";
          print "  10) Last Codeword Length\n";
          print "  11) Scrambler on/off\n";
          print "\n  sub-TLV " . $sub_tlv_number++ . " - Choose sub-TLV which should be added:  ";
          $choosen_sub_tlv = <>;
          chomp $choosen_sub_tlv;
          switch ($choosen_sub_tlv) {
            case 1 {
              $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", rand(7) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 2 {
              $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 3 {
              $sub_tlv_value = $sub_tlv_value . "03" . "02" . sprintf("%04x", rand(1536) + 1);
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 4 {
              $sub_tlv_value = $sub_tlv_value . "04" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 5 {
              $sub_tlv_value = $sub_tlv_value . "05" . "01" . sprintf("%02x", rand(17));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 6 {
              $sub_tlv_value = $sub_tlv_value . "06" . "01" . sprintf("%02x", rand(238) + 16);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 7 {
              $sub_tlv_value = $sub_tlv_value . "07" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 8 {
              $sub_tlv_value = $sub_tlv_value . "08" . "01" . sprintf("%02x", rand(0xFF) + 16);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 9 {
              $sub_tlv_value = $sub_tlv_value . "09" . "01" . sprintf("%02x", rand(0xFF));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 10 {
              $sub_tlv_value = $sub_tlv_value . "0A" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 11 {
              $sub_tlv_value = $sub_tlv_value . "0B" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            else {
              print "\n  This is not a valid option. Calling EXIT... \n\n";
              exit;
            }
          }
          printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
          $last_sub_tlv = <>;
        }
        $packet_value = $packet_value . "04" . sprintf("%02x", $sub_tlv_length + 1) . sprintf("%02x", int(rand(15)) + 1) . $sub_tlv_value;
        $packet_length = $packet_length + 3 + $sub_tlv_length;
      }
      case 5 {
        # Create BURST5 sub-TLVs
        $sub_tlv_value = "";
        $sub_tlv_length = 0;
        $last_sub_tlv = 0;
        while ($last_sub_tlv != 1) {
          print "\n  Following sub-TLVs can be added:\n\n";
          print "   1) Modulation Type\n";
          print "   2) Differential Encoding\n";
          print "   3) Preamble Length\n";
          print "   4) Preamble Value Offset\n";
          print "   5) FEC Error Correction (T)\n";
          print "   6) FEC Codeword Information Bytes (k)\n";
          print "   7) Scrambler Seed\n";
          print "   8) Maximum Burst Size\n";
          print "   9) Guard Time Size\n";
          print "  10) Last Codeword Length\n";
          print "  11) Scrambler on/off\n";
          print "  12) R-S Interleaver Depth (Ir)\n";
          print "  13) R-S Interleaver Block Size (Br)\n";
          print "  14) Preamble Type\n";
          print "\n  sub-TLV " . $sub_tlv_number++ . " - Choose sub-TLV which should be added:  ";
          $choosen_sub_tlv = <>;
          chomp $choosen_sub_tlv;
          switch ($choosen_sub_tlv) {
            case 1 {
              $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", rand(7) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 2 {
              $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 3 {
              $sub_tlv_value = $sub_tlv_value . "03" . "02" . sprintf("%04x", rand(1536) + 1);
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 4 {
              $sub_tlv_value = $sub_tlv_value . "04" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 5 {
              $sub_tlv_value = $sub_tlv_value . "05" . "01" . sprintf("%02x", rand(17));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 6 {
              $sub_tlv_value = $sub_tlv_value . "06" . "01" . sprintf("%02x", rand(238) + 16);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 7 {
              $sub_tlv_value = $sub_tlv_value . "07" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 8 {
              $sub_tlv_value = $sub_tlv_value . "08" . "01" . sprintf("%02x", rand(0xFF) + 16);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 9 {
              $sub_tlv_value = $sub_tlv_value . "09" . "01" . sprintf("%02x", rand(0xFF));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 10 {
              $sub_tlv_value = $sub_tlv_value . "0A" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 11 {
              $sub_tlv_value = $sub_tlv_value . "0B" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 12 {
              $sub_tlv_value = $sub_tlv_value . "0C" . "01" . sprintf("%02x", rand(0xFF));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 13 {
              $sub_tlv_value = $sub_tlv_value . "0D" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 14 {
              $sub_tlv_value = $sub_tlv_value . "0E" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            else {
              print "\n  This is not a valid option. Calling EXIT... \n\n";
              exit;
            }
          }
          printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
          $last_sub_tlv = <>;
        }
        $packet_value = $packet_value . "05" . sprintf("%02x", $sub_tlv_length + 1) . sprintf("%02x", int(rand(15)) + 1) . $sub_tlv_value;
        $packet_length = $packet_length + 3 + $sub_tlv_length;
      }
      case 6 {
        $i = int(rand(63)) + 1;
        $packet_value = $packet_value . "06" . sprintf("%02x", $i);
        for (my $j = 0; $j < $i; $j++) {
          $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
        }
        $packet_length = $packet_length + $i + 2;
      }
      case 7 {
        $packet_value = $packet_value . "07" . "01" . sprintf("%02x", int(rand(2)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 15 {
        $packet_value = $packet_value . "0F" . "01" . sprintf("%02x", int(rand(2)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 16 {
        $packet_value = $packet_value . "10" . "01" . sprintf("%02x", int(rand(3)));
        $packet_length = $packet_length + 3;
      }
      case 18 {
        $packet_value = $packet_value . "12" . "04" . random_bits(32, 0xFFFF000F);
        $packet_length = $packet_length + 6;
      }
      case 19 {
        $packet_value = $packet_value . "13" . "04" . random_bits(32, 0xFFFF000F);
        $packet_length = $packet_length + 6;
      }
      else {
        print "\n  This is not a valid option. Calling EXIT... \n\n";
        exit;
      }
    }
    printf "\n  Is this last TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "02", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub RNG_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add Service Identifier
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Downstream Channel ID
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Reserved Field
  $packet_value = $packet_value . "00";
  $packet_length = $packet_length + 1;
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "04", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 0, 0);
  return ($packet_value, $packet_length);
}

sub type29UCD() {
  our $packet_value;
  our $packet_length;
  our $last_tlv = 0;
  our $last_sub_tlv = 0;
  our $choosen_tlv;
  our $choosen_sub_tlv;
  our $tlv_number = 1;
  our $sub_tlv_number = 1;
  our $sub_tlv_value;
  our $sub_tlv_length;
  our $i;
  our $j;
  # Add Upstream Channel ID field
  $packet_value = sprintf("%02x", rand(0xFF));
  $packet_length = 1;
  # Add Config Change Count field
  $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
  $packet_length = $packet_length + 1;
  # Add Minislot Size field
  $packet_value = $packet_value . sprintf("%02x", 2 ** rand(0x8));
  $packet_length = $packet_length + 1;
  # Add Downstream Channel ID field
  $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
  $packet_length = $packet_length + 1;
  # Add TLV data
  while ($last_tlv != 1) {
    print "\n  Following TLVs can be added:\n\n";
    print "   1) Modulation Rate\n";
    print "   2) Frequency\n";
    print "   3) Preamble Pattern\n";
    print "   5) Burst Descriptor (DOCSIS 2.0/3.0)\n";
    print "      ...\n";
    print "   6) Extended Preamble Pattern\n";
    print "   7) S-CDMA Mode Enable\n";
    print "   8) S-CDMA Spreading Intervals per frame\n";
    print "   9) S-CDMA Codes per Minislot\n";
    print "  10) S-CDMA Number of Active Codes\n";
    print "  11) S-CDMA Code Hopping Seed\n";
    print "  12) S-CDMA US ratio numerator 'M'\n";
    print "  13) S-CDMA US ratio denominator 'N'\n";
    print "  14) S-CDMA Timestamp Snapshop\n";
    print "  15) Maintain Power Spectral Density\n";
    print "  16) Ranging Required\n";
    print "  17) S-CDMA Maximum Scheduled Codes enabled\n";
    print "  18) Ranging Hold-Off Priority Field\n";
    print "  19) Channel Class ID\n";
    print "\n  TLV " . $tlv_number . " - Choose TLV which should be added:  ";
    $choosen_tlv = <>;
    chomp $choosen_tlv;
    switch ($choosen_tlv) {
      case 1 {
        $packet_value = $packet_value . "01" . "01" . sprintf("%02x", 2 ** rand(0x5));
        $packet_length = $packet_length + 3;
      }
      case 2 {
        $packet_value = $packet_value . "02" . "04" . sprintf("%08x", (int(rand(80)) + 5) * 1000000);
        $packet_length = $packet_length + 6;
      }
      case 3 {
        $i = int(rand(127)) + 1;
        $packet_value = $packet_value . "03" . sprintf("%02x", $i);
        for (my $j = 0; $j < $i; $j++) {
          $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
        }
        $packet_length = $packet_length + $i + 2;
      }
      case 5 {
        # Create BURST5 sub-TLVs
        $sub_tlv_value = "";
        $sub_tlv_length = 0;
        $last_sub_tlv = 0;
        while ($last_sub_tlv != 1) {
          print "\n  Following sub-TLVs can be added:\n\n";
          print "   1) Modulation Type\n";
          print "   2) Differential Encoding\n";
          print "   3) Preamble Length\n";
          print "   4) Preamble Value Offset\n";
          print "   5) FEC Error Correction (T)\n";
          print "   6) FEC Codeword Information Bytes (k)\n";
          print "   7) Scrambler Seed\n";
          print "   8) Maximum Burst Size\n";
          print "   9) Guard Time Size\n";
          print "  10) Last Codeword Length\n";
          print "  11) Scrambler on/off\n";
          print "  12) R-S Interleaver Depth (Ir)\n";
          print "  13) R-S Interleaver Block Size (Br)\n";
          print "  14) Preamble Type\n";
          print "  15) S-CDMA Spreader on/off\n";
          print "  16) S-CDMA Codes per Subframe\n";
          print "  17) S-CDMA Framer Interleaving Step Size\n";
          print "  18) TCM Encoding\n";
          print "\n  sub-TLV " . $sub_tlv_number++ . " - Choose sub-TLV which should be added:  ";
          $choosen_sub_tlv = <>;
          chomp $choosen_sub_tlv;
          switch ($choosen_sub_tlv) {
            case 1 {
              $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", rand(7) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 2 {
              $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 3 {
              $sub_tlv_value = $sub_tlv_value . "03" . "02" . sprintf("%04x", rand(1536) + 1);
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 4 {
              $sub_tlv_value = $sub_tlv_value . "04" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 5 {
              $sub_tlv_value = $sub_tlv_value . "05" . "01" . sprintf("%02x", rand(17));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 6 {
              $sub_tlv_value = $sub_tlv_value . "06" . "01" . sprintf("%02x", rand(238) + 16);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 7 {
              $sub_tlv_value = $sub_tlv_value . "07" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 8 {
              $sub_tlv_value = $sub_tlv_value . "08" . "01" . sprintf("%02x", rand(0xFF) + 16);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 9 {
              $sub_tlv_value = $sub_tlv_value . "09" . "01" . sprintf("%02x", rand(0xFF));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 10 {
              $sub_tlv_value = $sub_tlv_value . "0A" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 11 {
              $sub_tlv_value = $sub_tlv_value . "0B" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 12 {
              $sub_tlv_value = $sub_tlv_value . "0C" . "01" . sprintf("%02x", rand(0xFF));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 13 {
              $sub_tlv_value = $sub_tlv_value . "0D" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 14 {
              $sub_tlv_value = $sub_tlv_value . "0E" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 15 {
              $sub_tlv_value = $sub_tlv_value . "0F" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 16 {
              $sub_tlv_value = $sub_tlv_value . "10" . "01" . sprintf("%02x", rand(128) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 17 {
              $sub_tlv_value = $sub_tlv_value . "11" . "01" . sprintf("%02x", rand(31) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 18 {
              $sub_tlv_value = $sub_tlv_value . "12" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            else {
              print "\n  This is not a valid option. Calling EXIT... \n\n";
              exit;
            }
          }
          printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
          $last_sub_tlv = <>;
        }
        $packet_value = $packet_value . "05" . sprintf("%02x", $sub_tlv_length + 1) . sprintf("%02x", int(rand(15)) + 1) . $sub_tlv_value;
        $packet_length = $packet_length + 3 + $sub_tlv_length;
      }
      case 6 {
        $i = int(rand(63)) + 1;
        $packet_value = $packet_value . "06" . sprintf("%02x", $i);
        for (my $j = 0; $j < $i; $j++) {
          $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
        }
        $packet_length = $packet_length + $i + 2;
      }
      case 7 {
        $packet_value = $packet_value . "07" . "01" . sprintf("%02x", int(rand(2)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 8 {
        $packet_value = $packet_value . "08" . "01" . sprintf("%02x", int(rand(32)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 9 {
        $packet_value = $packet_value . "09" . "01" . sprintf("%02x", int(rand(31)) + 2);
        $packet_length = $packet_length + 3;
      }
      case 10 {
        $packet_value = $packet_value . "0A" . "01" . sprintf("%02x", int(rand(65)) + 64);
        $packet_length = $packet_length + 3;
      }
      case 11 {
        $packet_value = $packet_value . "0B" . "02" . random_bits(16, 0xFFFE);
        $packet_length = $packet_length + 4;
      }
      case 12 {
        $packet_value = $packet_value . "0C" . "02" . random_bits(16, 0xFFFF);
        $packet_length = $packet_length + 4;
      }
      case 13 {
        $packet_value = $packet_value . "0D" . "02" . random_bits(16, 0xFFFF);
        $packet_length = $packet_length + 4;
      }
      case 14 {
        $packet_value = $packet_value . "0E" . "09" . random_bits(32, 0xFFFFFFFF) . random_bits(24, 0xFFFFFF) . random_bits(16, 0xFFFF);
        $packet_length = $packet_length + 11;
      }
      case 15 {
        $packet_value = $packet_value . "0F" . "01" . sprintf("%02x", int(rand(2)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 16 {
        $packet_value = $packet_value . "10" . "01" . sprintf("%02x", int(rand(3)));
        $packet_length = $packet_length + 3;
      }
      case 17 {
        $packet_value = $packet_value . "11" . "01" . sprintf("%02x", int(rand(2)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 18 {
        $packet_value = $packet_value . "12" . "04" . random_bits(32, 0xFFFF000F);
        $packet_length = $packet_length + 6;
      }
      case 19 {
        $packet_value = $packet_value . "13" . "04" . random_bits(32, 0xFFFF000F);
        $packet_length = $packet_length + 6;
      }
      else {
        print "\n  This is not a valid option. Calling EXIT... \n\n";
        exit;
      }
    }
    printf "\n  Is this last TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "1D", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub B_INIT_RNG_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add Capabilities Flag
  $packet_value = random_bits(8, 0xC0);
  $packet_length = $packet_length + 1;
  # Add MAC Domain Downstream Service Group
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Downstream Channel ID
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Upstream Channel ID
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "22", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 0, 0);
  return ($packet_value, $packet_length);
}

sub type35UCD() {
  our $packet_value;
  our $packet_length;
  our $last_tlv = 0;
  our $last_sub_tlv = 0;
  our $choosen_tlv;
  our $choosen_sub_tlv;
  our $tlv_number = 1;
  our $sub_tlv_number = 1;
  our $sub_tlv_value;
  our $sub_tlv_length;
  our $i;
  our $j;
  # Add Upstream Channel ID field
  $packet_value = sprintf("%02x", rand(0xFF));
  $packet_length = 1;
  # Add Config Change Count field
  $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
  $packet_length = $packet_length + 1;
  # Add Minislot Size field
  $packet_value = $packet_value . sprintf("%02x", 2 ** rand(0x8));
  $packet_length = $packet_length + 1;
  # Add Downstream Channel ID field
  $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
  $packet_length = $packet_length + 1;
  # Add TLV data
  while ($last_tlv != 1) {
    print "\n  Following TLVs can be added:\n\n";
    print "   1) Modulation Rate\n";
    print "   2) Frequency\n";
    print "   3) Preamble Pattern\n";
    print "   5) Burst Descriptor (DOCSIS 2.0/3.0)\n";
    print "      ...\n";
    print "   6) Extended Preamble Pattern\n";
    print "   7) S-CDMA Mode Enable\n";
    print "   8) S-CDMA Spreading Intervals per frame\n";
    print "   9) S-CDMA Codes per Minislot\n";
    print "  10) S-CDMA Number of Active Codes\n";
    print "  11) S-CDMA Code Hopping Seed\n";
    print "  12) S-CDMA US ratio numerator 'M'\n";
    print "  13) S-CDMA US ratio denominator 'N'\n";
    print "  14) S-CDMA Timestamp Snapshop\n";
    print "  15) Maintain Power Spectral Density\n";
    print "  16) Ranging Required\n";
    print "  17) S-CDMA Maximum Scheduled Codes enabled\n";
    print "  18) Ranging Hold-Off Priority Field\n";
    print "  19) Channel Class ID\n";
    print "  20) S-CDMA Selection Mode for Active Codes and Code Hopping\n";
    print "  21) S-CDMA Selection String for Active Codes\n";
    print "  22) Higher UCD for the same UCID present bitmap\n";
    print "\n  TLV " . $tlv_number . " - Choose TLV which should be added:  ";
    $choosen_tlv = <>;
    chomp $choosen_tlv;
    switch ($choosen_tlv) {
      case 1 {
        $packet_value = $packet_value . "01" . "01" . sprintf("%02x", 2 ** rand(0x5));
        $packet_length = $packet_length + 3;
      }
      case 2 {
        $packet_value = $packet_value . "02" . "04" . sprintf("%08x", (int(rand(80)) + 5) * 1000000);
        $packet_length = $packet_length + 6;
      }
      case 3 {
        $i = int(rand(127)) + 1;
        $packet_value = $packet_value . "03" . sprintf("%02x", $i);
        for (my $j = 0; $j < $i; $j++) {
          $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
        }
        $packet_length = $packet_length + $i + 2;
      }
      case 5 {
        # Create BURST5 sub-TLVs
        $sub_tlv_value = "";
        $sub_tlv_length = 0;
        $last_sub_tlv = 0;
        while ($last_sub_tlv != 1) {
          print "\n  Following sub-TLVs can be added:\n\n";
          print "   1) Modulation Type\n";
          print "   2) Differential Encoding\n";
          print "   3) Preamble Length\n";
          print "   4) Preamble Value Offset\n";
          print "   5) FEC Error Correction (T)\n";
          print "   6) FEC Codeword Information Bytes (k)\n";
          print "   7) Scrambler Seed\n";
          print "   8) Maximum Burst Size\n";
          print "   9) Guard Time Size\n";
          print "  10) Last Codeword Length\n";
          print "  11) Scrambler on/off\n";
          print "  12) R-S Interleaver Depth (Ir)\n";
          print "  13) R-S Interleaver Block Size (Br)\n";
          print "  14) Preamble Type\n";
          print "  15) S-CDMA Spreader on/off\n";
          print "  16) S-CDMA Codes per Subframe\n";
          print "  17) S-CDMA Framer Interleaving Step Size\n";
          print "  18) TCM Encoding\n";
          print "\n  sub-TLV " . $sub_tlv_number++ . " - Choose sub-TLV which should be added:  ";
          $choosen_sub_tlv = <>;
          chomp $choosen_sub_tlv;
          switch ($choosen_sub_tlv) {
            case 1 {
              $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", rand(7) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 2 {
              $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 3 {
              $sub_tlv_value = $sub_tlv_value . "03" . "02" . sprintf("%04x", rand(1536) + 1);
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 4 {
              $sub_tlv_value = $sub_tlv_value . "04" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 5 {
              $sub_tlv_value = $sub_tlv_value . "05" . "01" . sprintf("%02x", rand(17));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 6 {
              $sub_tlv_value = $sub_tlv_value . "06" . "01" . sprintf("%02x", rand(238) + 16);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 7 {
              $sub_tlv_value = $sub_tlv_value . "07" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 8 {
              $sub_tlv_value = $sub_tlv_value . "08" . "01" . sprintf("%02x", rand(0xFF) + 16);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 9 {
              $sub_tlv_value = $sub_tlv_value . "09" . "01" . sprintf("%02x", rand(0xFF));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 10 {
              $sub_tlv_value = $sub_tlv_value . "0A" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 11 {
              $sub_tlv_value = $sub_tlv_value . "0B" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 12 {
              $sub_tlv_value = $sub_tlv_value . "0C" . "01" . sprintf("%02x", rand(0xFF));
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 13 {
              $sub_tlv_value = $sub_tlv_value . "0D" . "02" . sprintf("%04x", rand(0xFFFF));
              $sub_tlv_length = $sub_tlv_length + 4;
            }
            case 14 {
              $sub_tlv_value = $sub_tlv_value . "0E" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 15 {
              $sub_tlv_value = $sub_tlv_value . "0F" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 16 {
              $sub_tlv_value = $sub_tlv_value . "10" . "01" . sprintf("%02x", rand(128) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 17 {
              $sub_tlv_value = $sub_tlv_value . "11" . "01" . sprintf("%02x", rand(31) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            case 18 {
              $sub_tlv_value = $sub_tlv_value . "12" . "01" . sprintf("%02x", rand(2) + 1);
              $sub_tlv_length = $sub_tlv_length + 3;
            }
            else {
              print "\n  This is not a valid option. Calling EXIT... \n\n";
              exit;
            }
          }
          printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
          $last_sub_tlv = <>;
        }
        $packet_value = $packet_value . "05" . sprintf("%02x", $sub_tlv_length + 1) . sprintf("%02x", int(rand(15)) + 1) . $sub_tlv_value;
        $packet_length = $packet_length + 3 + $sub_tlv_length;
      }
      case 6 {
        $i = int(rand(63)) + 1;
        $packet_value = $packet_value . "06" . sprintf("%02x", $i);
        for (my $j = 0; $j < $i; $j++) {
          $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
        }
        $packet_length = $packet_length + $i + 2;
      }
      case 7 {
        $packet_value = $packet_value . "07" . "01" . sprintf("%02x", int(rand(2)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 8 {
        $packet_value = $packet_value . "08" . "01" . sprintf("%02x", int(rand(32)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 9 {
        $packet_value = $packet_value . "09" . "01" . sprintf("%02x", int(rand(31)) + 2);
        $packet_length = $packet_length + 3;
      }
      case 10 {
        $packet_value = $packet_value . "0A" . "01" . sprintf("%02x", int(rand(65)) + 64);
        $packet_length = $packet_length + 3;
      }
      case 11 {
        $packet_value = $packet_value . "0B" . "02" . random_bits(16, 0xFFFE);
        $packet_length = $packet_length + 4;
      }
      case 12 {
        $packet_value = $packet_value . "0C" . "02" . random_bits(16, 0xFFFF);
        $packet_length = $packet_length + 4;
      }
      case 13 {
        $packet_value = $packet_value . "0D" . "02" . random_bits(16, 0xFFFF);
        $packet_length = $packet_length + 4;
      }
      case 14 {
        $packet_value = $packet_value . "0E" . "09" . random_bits(32, 0xFFFFFFFF) . random_bits(24, 0xFFFFFF) . random_bits(16, 0xFFFF);
        $packet_length = $packet_length + 11;
      }
      case 15 {
        $packet_value = $packet_value . "0F" . "01" . sprintf("%02x", int(rand(2)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 16 {
        $packet_value = $packet_value . "10" . "01" . sprintf("%02x", int(rand(3)));
        $packet_length = $packet_length + 3;
      }
      case 17 {
        $packet_value = $packet_value . "07" . "01" . sprintf("%02x", int(rand(2)) + 1);
        $packet_length = $packet_length + 3;
      }
      case 18 {
        $packet_value = $packet_value . "12" . "04" . random_bits(32, 0xFFFF000F);
        $packet_length = $packet_length + 6;
      }
      case 19 {
        $packet_value = $packet_value . "13" . "04" . random_bits(32, 0xFFFF000F);
        $packet_length = $packet_length + 6;
      }
      case 20 {
        $packet_value = $packet_value . "14" . "01" . sprintf("%02x", int(rand(4)));
        $packet_length = $packet_length + 3;
      }
      case 21 {
        $packet_value = $packet_value . "15" . "10" . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF);
        $packet_length = $packet_length + 18;
      }
      case 22 {
        $packet_value = $packet_value . "16" . "01" . random_bits(8, 0x01);
        $packet_length = $packet_length + 3;
      }
      else {
        print "\n  This is not a valid option. Calling EXIT... \n\n";
        exit;
      }
    }
    printf "\n  Is this last TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "23", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
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
    case [0,2] {
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

sub random_bits {
  our $i = 0;
  our $value = "";
  our $binary = "";
  our @input = @_;
  our @bits = split //, sprintf ("%0" . $input[0] . "b", $input[1]);
  foreach (@bits) { 
    if ($_ == 1) {
      $bits[$i] = int(rand(2));
    }
    $binary = join("", $binary, $bits[$i]);
    $value = sprintf("%0" . $input[0] / 4 . "x", oct("0b" . $binary));
    $i++;
  }
  return $value;
}