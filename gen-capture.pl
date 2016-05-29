#!/usr/bin/perl

use strict;
use warnings;

# Subroutine prototypes
sub SYNC ();
sub type2UCD();
sub Version1_MAP();
sub RNG_REQ();
sub RNG_RSP();
sub REG_REQ();
sub REG_RSP();
sub UCC_REQ();
sub UCC_RSP();
sub BPKM_REQ();
sub BPKM_RSP();
sub REG_ACK();
sub DSA_REQ();
sub DSA_RSP();
sub DSA_ACK();
sub DSC_REQ();
sub DSC_RSP();
sub DSC_ACK();
sub DSD_REQ();
sub DSD_RSP();
sub DCC_REQ();
sub DCC_RSP();
sub DCC_ACK();
sub type29UCD();
sub INIT_RNG_REQ();
sub MDD();
sub B_INIT_RNG_REQ();
sub type35UCD();
sub DBC_REQ();
sub DBC_RSP();
sub DBC_ACK();
sub REG_REQ_MP();
sub REG_RSP_MP();
sub request_minislots();
sub request_bytes();
sub random_bits;

my $pcap_file = "";
my $packet_length;
my $packet_value;
my $pcap_header;
my $packet_timestamp = "0000000000000000";
my $frame_number = 1;
my $last_frame = 0;
my $frame_type;

my $clear_screen = 1;

$pcap_header = "D4C3B2A1020004000000000000000000000004008F000000";

if ($clear_screen) {
  system $^O eq 'MSWin32' ? 'cls' : 'clear';
}

print "\n  Pcap filename to be saved:  ";
$pcap_file = <>;

open PCAP_FILE, '>' . $pcap_file;
binmode(PCAP_FILE);

print PCAP_FILE pack "H*", $pcap_header;

while ($last_frame != 1) {
  if ($clear_screen) {
    system $^O eq 'MSWin32' ? 'cls' : 'clear';
  }
  print "\n  Following packet types can be generated:\n\n";
  print "   1) SYNC                    14) REG-ACK         29) Type 29 UCD        44) REG-REQ-MP              59) DTP-ACK (N/A)               \n";
  print "   2) Type 2 UCD              15) DSA-REQ         30) INIT-RNG-REQ       45) REG-RSP-MP              60) DTP-INFO (N/A)              \n";
  print "  3a) Version 1 MAP           16) DSC-RSP         31) TST-REQ (N/A)      46) EM-REQ (N/A)                                            \n";
  print "  3b) Version 5 MAP   (N/A)   17) DSA-ACK         32) DCD (N/A)          47) EM-RSP (N/A)                                            \n";
  print "  3c) Version 5 P-MAP (N/A)   18) DSC-REQ         33) MDD (N/A)          48) CM-STATUS-ACK (N/A)      a) Request Frame (minislots)   \n";
  print "   4) RNG-REQ                 19) DSC-RSP         34) B-INIT-RNG-REQ     49) OFDM Chan Descr (N/A)    b) Request Frame (bytes)       \n";
  print "   5) RNG-RSP                 20) DSC-ACK         35) Type 35 UCD        50) DPD (N/A)                c) O-INIT-RNG-REQ (N/A)        \n";
  print "   6) REG-REQ                 21) DSD-REQ         36) DBC-REQ            51) Type 51 UCD (N/A)                                       \n";
  print "   7) REG-RSP                 22) DSD-RSP         37) DBC-RSP            52) ODS-REQ (N/A)                                           \n";
  print "   8) UCC-REQ                 23) DCC-REQ         38) DBC-ACK            53) ODS-RSP (N/A)                                           \n";
  print "   9) UCC-RSP                 24) DCC-RSP         39) DPV-REQ (N/A)      54) OPT-REQ (N/A)                                           \n";
  print "  10) TRI-TCD (N/A)           25) DCC-ACK         40) DPV-RSP (N/A)      55) OPT-RSP (N/A)                                           \n";
  print "  11) TRI-TSI (N/A)           26) DCI-REQ (N/A)   41) CM-STATUS (N/A)    56) OPT-ACK (N/A)                                           \n";
  print "  12) BPKM-REQ                27) DCI-RSP (N/A)   42) CM-CTRL-REQ (N/A)  57) DTP-REQ (N/A)                                           \n";
  print "  13) BPKM-RSP                28) UP-DIS (N/A)    43) CM-CTRL-RSP (N/A)  58) DTP-RSP (N/A)                                           \n";
  print "\n  Frame " . $frame_number . " - Choose packet type which will be generated:  ";
  $frame_type = <>;
  chomp $frame_type;
  if ($frame_type eq "1") {
    ($packet_value, $packet_length) = SYNC();
  } elsif ($frame_type eq "2") {
    ($packet_value, $packet_length) = type2UCD();
  } elsif ($frame_type eq "3a") {
    ($packet_value, $packet_length) = Version1_MAP();
  } elsif ($frame_type eq "4") {
    ($packet_value, $packet_length) = RNG_REQ();
  } elsif ($frame_type eq "5") {
    ($packet_value, $packet_length) = RNG_RSP();
  } elsif ($frame_type eq "6") {
    ($packet_value, $packet_length) = REG_REQ();
  } elsif ($frame_type eq "7") {
    ($packet_value, $packet_length) = REG_RSP();
  } elsif ($frame_type eq "8") {
    ($packet_value, $packet_length) = UCC_REQ();
  } elsif ($frame_type eq "9") {
    ($packet_value, $packet_length) = UCC_RSP();
  } elsif ($frame_type eq "12") {
    ($packet_value, $packet_length) = BPKM_REQ();
  } elsif ($frame_type eq "13") {
    ($packet_value, $packet_length) = BPKM_RSP();
  } elsif ($frame_type eq "14") {
    ($packet_value, $packet_length) = REG_ACK();
  } elsif ($frame_type eq "15") {
    ($packet_value, $packet_length) = DSA_REQ();
  } elsif ($frame_type eq "16") {
    ($packet_value, $packet_length) = DSA_RSP();
  } elsif ($frame_type eq "17") {
    ($packet_value, $packet_length) = DSA_ACK();
  } elsif ($frame_type eq "18") {
    ($packet_value, $packet_length) = DSC_REQ();
  } elsif ($frame_type eq "19") {
    ($packet_value, $packet_length) = DSC_RSP();
  } elsif ($frame_type eq "20") {
    ($packet_value, $packet_length) = DSC_ACK();
  } elsif ($frame_type eq "21") {
    ($packet_value, $packet_length) = DSD_REQ();
  } elsif ($frame_type eq "22") {
    ($packet_value, $packet_length) = DSD_RSP();
  } elsif ($frame_type eq "23") {
    ($packet_value, $packet_length) = DCC_REQ();
  } elsif ($frame_type eq "24") {
    ($packet_value, $packet_length) = DCC_RSP();
  } elsif ($frame_type eq "25") {
    ($packet_value, $packet_length) = DCC_ACK();
  } elsif ($frame_type eq "29") {
    ($packet_value, $packet_length) = type29UCD();
  } elsif ($frame_type eq "30") {
    ($packet_value, $packet_length) = INIT_RNG_REQ();
  } elsif ($frame_type eq "33") {
    ($packet_value, $packet_length) = MDD();
  } elsif ($frame_type eq "34") {
    ($packet_value, $packet_length) = B_INIT_RNG_REQ();
  } elsif ($frame_type eq "35") {
    ($packet_value, $packet_length) = type35UCD();
  } elsif ($frame_type eq "36") {
    ($packet_value, $packet_length) = DBC_REQ();
  } elsif ($frame_type eq "37") {
    ($packet_value, $packet_length) = DBC_RSP();
  } elsif ($frame_type eq "38") {
    ($packet_value, $packet_length) = DBC_ACK();
  } elsif ($frame_type eq "44") {
    ($packet_value, $packet_length) = REG_REQ_MP();
  } elsif ($frame_type eq "45") {
    ($packet_value, $packet_length) = REG_RSP_MP();
  } elsif ($frame_type eq "a") {
    ($packet_value, $packet_length) = request_minislots();
  } elsif ($frame_type eq "b") {
    ($packet_value, $packet_length) = request_bytes();
  } else {
    print "\n  This is not a valid option. Calling EXIT... \n\n";
    exit;
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
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
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
    if ($choosen_tlv eq "1") {
      $packet_value = $packet_value . "01" . "01" . sprintf("%02x", 2 ** rand(0x5));
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "2") {
      $packet_value = $packet_value . "02" . "04" . sprintf("%08x", (int(rand(80)) + 5) * 1000000);
      $packet_length = $packet_length + 6;
    } elsif ($choosen_tlv eq "3") {
      $i = int(rand(127)) + 1;
      $packet_value = $packet_value . "03" . sprintf("%02x", $i);
      for (my $j = 0; $j < $i; $j++) {
        $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
      }
      $packet_length = $packet_length + $i + 2;
    } elsif ($choosen_tlv eq "4") {
      # Create BURST4 sub-TLVs
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      $sub_tlv_number = 1;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
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
        if ($choosen_sub_tlv eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", rand(7) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "3") {
          $sub_tlv_value = $sub_tlv_value . "03" . "02" . sprintf("%04x", rand(1536) + 1);
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "4") {
          $sub_tlv_value = $sub_tlv_value . "04" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "5") {
          $sub_tlv_value = $sub_tlv_value . "05" . "01" . sprintf("%02x", rand(17));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "6") {
          $sub_tlv_value = $sub_tlv_value . "06" . "01" . sprintf("%02x", rand(238) + 16);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "7") {
          $sub_tlv_value = $sub_tlv_value . "07" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "8") {
          $sub_tlv_value = $sub_tlv_value . "08" . "01" . sprintf("%02x", rand(0xFF) + 16);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "9") {
          $sub_tlv_value = $sub_tlv_value . "09" . "01" . sprintf("%02x", rand(0xFF));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "10") {
          $sub_tlv_value = $sub_tlv_value . "0A" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "11") {
          $sub_tlv_value = $sub_tlv_value . "0B" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
      }
      $packet_value = $packet_value . "04" . sprintf("%02x", $sub_tlv_length + 1) . sprintf("%02x", int(rand(15)) + 1) . $sub_tlv_value;
      $packet_length = $packet_length + 3 + $sub_tlv_length;
    } elsif ($choosen_tlv eq "5") {
      # Create BURST5 sub-TLVs
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      $sub_tlv_number = 1;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
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
        if ($choosen_sub_tlv eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", rand(7) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "3") {
          $sub_tlv_value = $sub_tlv_value . "03" . "02" . sprintf("%04x", rand(1536) + 1);
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "4") {
          $sub_tlv_value = $sub_tlv_value . "04" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "5") {
          $sub_tlv_value = $sub_tlv_value . "05" . "01" . sprintf("%02x", rand(17));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "6") {
          $sub_tlv_value = $sub_tlv_value . "06" . "01" . sprintf("%02x", rand(238) + 16);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "7") {
          $sub_tlv_value = $sub_tlv_value . "07" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "8") {
          $sub_tlv_value = $sub_tlv_value . "08" . "01" . sprintf("%02x", rand(0xFF) + 16);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "9") {
          $sub_tlv_value = $sub_tlv_value . "09" . "01" . sprintf("%02x", rand(0xFF));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "10") {
          $sub_tlv_value = $sub_tlv_value . "0A" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "11") {
          $sub_tlv_value = $sub_tlv_value . "0B" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "12") {
          $sub_tlv_value = $sub_tlv_value . "0C" . "01" . sprintf("%02x", rand(0xFF));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "13") {
          $sub_tlv_value = $sub_tlv_value . "0D" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "14") {
          $sub_tlv_value = $sub_tlv_value . "0E" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
      }
      $packet_value = $packet_value . "05" . sprintf("%02x", $sub_tlv_length + 1) . sprintf("%02x", int(rand(15)) + 1) . $sub_tlv_value;
      $packet_length = $packet_length + 3 + $sub_tlv_length;
    } elsif ($choosen_tlv eq "6") {
      $i = int(rand(63)) + 1;
      $packet_value = $packet_value . "06" . sprintf("%02x", $i);
      for (my $j = 0; $j < $i; $j++) {
        $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
      }
      $packet_length = $packet_length + $i + 2;
    } elsif ($choosen_tlv eq "7") {
      $packet_value = $packet_value . "07" . "01" . sprintf("%02x", int(rand(2)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "15") {
      $packet_value = $packet_value . "0F" . "01" . sprintf("%02x", int(rand(2)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "16") {
      $packet_value = $packet_value . "10" . "01" . sprintf("%02x", int(rand(3)));
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "18") {
      $packet_value = $packet_value . "12" . "04" . random_bits(32, 0xFFFF000F);
      $packet_length = $packet_length + 6;
    } elsif ($choosen_tlv eq "19") {
      $packet_value = $packet_value . "13" . "04" . random_bits(32, 0xFFFF000F);
      $packet_length = $packet_length + 6;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
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

sub Version1_MAP() {
  our $packet_value;
  our $packet_length = 0;
  our $elements;
  our $i;
  # Add Upstream channel ID
  $packet_value = random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add UCD Count
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Number of elements
  $elements = int(rand(240)) + 1;
  $packet_value = $packet_value . sprintf("%02x", $elements);
  $packet_length = $packet_length + 1;
  # Add Reserved
  $packet_value = $packet_value . "00";
  $packet_length = $packet_length + 1;
  # Add Alloc Start Time
  $packet_value = $packet_value . random_bits(32, 0xFFFFFFFF);
  $packet_length = $packet_length + 4;
  # Add Ack Time
  $packet_value = $packet_value . random_bits(32, 0xFFFFFFFF);
  $packet_length = $packet_length + 4;
  # Add Ranging Backoff Start
  $packet_value = $packet_value . sprintf("%02x", rand(16));
  $packet_length = $packet_length + 1;
  # Add Ranging Backoff End
  $packet_value = $packet_value . sprintf("%02x", rand(16));
  $packet_length = $packet_length + 1;
  # Data Backoff Start
  $packet_value = $packet_value . sprintf("%02x", rand(16));
  $packet_length = $packet_length + 1;
  # Data Backoff End
  $packet_value = $packet_value . sprintf("%02x", rand(16));
  $packet_length = $packet_length + 1;
  # Add elements
  for (my $i=0; $i < $elements; $i++) {
    # Add element
    $packet_value = $packet_value . random_bits(32, 0xFFFFFFFF);
    $packet_length = $packet_length + 4;
  }
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "03", "00");
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
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub RNG_RSP() {
  our $packet_value;
  our $packet_length = 0;
  our $last_tlv = 0;
  our $choosen_tlv;
  our $tlv_number = 1;
  our $i;
  our $j;
  # Add SID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Upstream Channel ID
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  while ($last_tlv != 1) {
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
    print "\n  Following TLVs can be added:\n\n";
    print "   1) Timing Adjuts, Integer Part\n";
    print "   2) Power Level Adjust\n";
    print "   3) Offset Frequency Adjust\n";
    print "   4) Transmit Equalization Adjust\n";
    print "   5) Ranging Status\n";
    print "   6) Downstream frequency override\n";
    print "   7) Upstream channel ID override\n";
    print "\n  TLV " . $tlv_number . " - Choose TLV which should be added:  ";
    $choosen_tlv = <>;
    chomp $choosen_tlv;
    if ($choosen_tlv eq "1") {
      $packet_value = $packet_value . "01" . "04" . random_bits(32, 0xFFFFFFFF);
      $packet_length = $packet_length + 6;
    } elsif ($choosen_tlv eq "2") {
      $packet_value = $packet_value . "02" . "01" . random_bits(8, 0xFF);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "3") {
      $packet_value = $packet_value . "03" . "02" . random_bits(16, 0xFFFF);
      $packet_length = $packet_length + 4;
    } elsif ($choosen_tlv eq "4") {
      # Value 32 was choosen random, could not find the maximum value in the spec.
      $i = int(rand(32)) + 1;
      $packet_value = $packet_value . "04" . sprintf("%02x", $i);
      for (my $j = 0; $j < $i; $j++) {
        $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
      }
      $packet_length = $packet_length + $i + 2;
    } elsif ($choosen_tlv eq "5") {
      $packet_value = $packet_value . "05" . "01" . sprintf("%02x", int(rand(3)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "6") {
      $packet_value = $packet_value . "06" . "04" . sprintf("%08x", (int(rand(1686)) + 108) * 1000000);
      $packet_length = $packet_length + 6;
    } elsif ($choosen_tlv eq "7") {
      $packet_value = $packet_value . "07" . "01" . random_bits(8, 0xFF);
      $packet_length = $packet_length + 3;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
    }
    printf "\n  Is this last TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "05", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub REG_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add Temporary Service Identifier
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "06", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub REG_RSP() {
  our $packet_value;
  our $packet_length = 0;
  # Add Service Identifier
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Response Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "07", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub UCC_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add Upstream Channel ID
  $packet_value = random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "08", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub UCC_RSP() {
  our $packet_value;
  our $packet_length = 0;
  # Add Upstream Channel ID
  $packet_value = random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "09", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub BPKM_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add Code Field
  $packet_value = sprintf("%02x", (int(rand(16))));
  $packet_length = $packet_length + 1;
  # Add Identifier Field
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Attributes
  ($packet_value, $packet_length) = add_bpkm_attributes($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "0C", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub BPKM_RSP() {
  our $packet_value;
  our $packet_length = 0;
  # Add Code Field
  $packet_value = sprintf("%02x", (int(rand(16))));
  $packet_length = $packet_length + 1;
  # Add Identifier Field
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Attributes
  ($packet_value, $packet_length) = add_bpkm_attributes($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "0D", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub REG_ACK() {
  our $packet_value;
  our $packet_length = 0;
  # Add Service Identifier
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Confirmation Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "0E", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DSA_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "0F", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DSA_RSP() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Confirmation Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "10", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DSA_ACK() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Confirmation Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "11", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DSC_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "12", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DSC_RSP() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Confirmation Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "13", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DSC_ACK() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Confirmation Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "14", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DSD_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Reserved field
  $packet_value = $packet_value . "0000";
  $packet_length = $packet_length + 2;
  # Add Service Flow ID
  $packet_value = $packet_value . random_bits(32, 0xFFFFFFFF);
  $packet_length = $packet_length + 4;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "15", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DSD_RSP() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Confirmation Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Reserved field
  $packet_value = $packet_value . "00";
  $packet_length = $packet_length + 1;
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "16", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DCC_REQ () {
  our $packet_value;
  our $packet_length = 0;
  our $tlv_number = 1;
  our $tlv_type;
  our $sub_tlv_number = 1;
  our $sub_tlv_type;
  our $sub_tlv_length = 0;
  our $sub_tlv_value = "";
  our $last_tlv = 0;
  our $last_sub_tlv = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add TLV Encoded information
  while ($last_tlv != 1) {
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
    print "\n  Following TLVs can be added:\n\n";
    print "   1) Upstream Channel ID\n";
    print "   2) Downstream Parameters\n";
    print "      ...\n";
    print "   3) Initialization Technique\n";
    print "   4) UCD Substitution\n";
    print "   6) Security Association Identifier (SAID) Substitution\n";
    print "   7) Service Flow Substitutions\n";
    print "     ...\n";
    print "   8) CMTS MAC Address\n";
    print "  27) HMAC-Digest\n";
    print "  31) Key Sequence Number\n";
    print "\n  TLV " . $tlv_number . " - Choose which TLV will be generated:  ";
    $tlv_type = <>;
    chomp $tlv_type;
    if ($tlv_type eq "1") {
      $packet_value = $packet_value . "01" . "01" . random_bits(8, 0xFF);
      $packet_length = $packet_length + 3;
    } elsif ($tlv_type eq "2") {
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
        print "\n  Class of Service sub-TLVs which can be added:\n\n";
        print "  1) Downstream Frequency\n";
        print "  2) Downstream Modulation Type\n";
        print "  3) Downstream Symbol Rate\n";
        print "  4) Downstream Interleaver Depth\n";
        print "  5) Downstream Channel Identifier\n";
        print "  6) SYNC Substitution\n";
        print "  7) OFDM Block Frequency\n";
        print "\n  sub-TLV " . $sub_tlv_number . " - Choose which TLV will be generated:  ";
        $sub_tlv_type = <>;
        chomp $sub_tlv_type;
        if ($sub_tlv_type eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "04" . sprintf("%08x", (int(rand(1686)) + 108) * 1000000);
          $sub_tlv_length = $sub_tlv_length + 6;
        } elsif ($sub_tlv_type eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", (int(rand(3))));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($sub_tlv_type eq "3") {
          $sub_tlv_value = $sub_tlv_value . "03" . "01" . sprintf("%02x", (int(rand(3))));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($sub_tlv_type eq "4") {
          $sub_tlv_value = $sub_tlv_value . "04" . "02" . random_bits(16, 0xFFFF);
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($sub_tlv_type eq "5") {
          $sub_tlv_value = $sub_tlv_value . "05" . "01" . random_bits(8, 0xFF);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($sub_tlv_type eq "6") {
          $sub_tlv_value = $sub_tlv_value . "06" . "01" . sprintf("%02x", (int(rand(2))));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($sub_tlv_type eq "7") {
          $sub_tlv_value = $sub_tlv_value . "07" . "04" . sprintf("%08x", (int(rand(1686)) + 108) * 1000000);
          $sub_tlv_length = $sub_tlv_length + 6;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        print "\n  Is this last sub-TLV for this packet? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
        $sub_tlv_number++;
      }
      $packet_value = $packet_value . "02" . sprintf("%02x", $sub_tlv_length) . $sub_tlv_value;
      $packet_length = $packet_length + $sub_tlv_length + 2;
    } elsif ($tlv_type eq "3") {
      $packet_value = $packet_value . "03" . "01" . sprintf("%02x", (int(rand(5))));
      $packet_length = $packet_length + 3;
    } elsif ($tlv_type eq "4") {
      # TODO This has to be a full UCD packet
      $packet_value = $packet_value . "04" . "10" . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF);
      $packet_length = $packet_length + 18;
    } elsif ($tlv_type eq "6") {
      $packet_value = $packet_value . "06" . "04" . random_bits(16, 0x3FFF) . random_bits(16, 0x3FFF);
      $packet_length = $packet_length + 6;
    } elsif ($tlv_type eq "7") {
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
        print "\n  Class of Service sub-TLVs which can be added:\n\n";
        print "  1) Service Flow Identifier Substitution\n";
        print "  2) Service Identifier Substitution\n";
        print "  5) Unsolicited Grant Time Reference Substitution\n";
        print "\n  sub-TLV " . $sub_tlv_number . " - Choose which TLV will be generated:  ";
        $sub_tlv_type = <>;
        chomp $sub_tlv_type;
        if ($sub_tlv_type eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "08" . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF);
          $sub_tlv_length = $sub_tlv_length + 10;
        } elsif ($sub_tlv_type eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "04" . random_bits(16, 0x3FFF) . random_bits(16, 0x3FFF);
          $sub_tlv_length = $sub_tlv_length + 6;
        } elsif ($sub_tlv_type eq "5") {
          $sub_tlv_value = $sub_tlv_value . "05" . "04" . random_bits(32, 0xFFFFFFFF);
          $sub_tlv_length = $sub_tlv_length + 6;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        print "\n  Is this last sub-TLV for this packet? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
        $sub_tlv_number++;
      }
      $packet_value = $packet_value . "07" . sprintf("%02x", $sub_tlv_length) . $sub_tlv_value;
      $packet_length = $packet_length + $sub_tlv_length + 2;
    } elsif ($tlv_type eq "8") {
      $packet_value = $packet_value . "08" . "06" . random_bits(24, 0xFFFFFF) . random_bits(24, 0xFFFFFF);
      $packet_length = $packet_length + 8;
    } elsif ($tlv_type eq "27") {
      $packet_value = $packet_value . "1B" . "14" . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF);
      $packet_length = $packet_length + 22;
    } elsif ($tlv_type eq "31") {
      $packet_value = $packet_value . "1F" . "01" . sprintf("%02x", (int(rand(16))));
      $packet_length = $packet_length + 3;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
    }
    print "\n  Is this last TLV for this packet? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "17", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DCC_RSP () {
  our $packet_value;
  our $packet_length = 0;
  our $tlv_number = 1;
  our $tlv_type;
  our $sub_tlv_number = 1;
  our $sub_tlv_type;
  our $sub_tlv_length = 0;
  our $sub_tlv_value = "";
  our $last_tlv = 0;
  our $last_sub_tlv = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Confirmation Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add TLV Encoded information
  while ($last_tlv != 1) {
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
    print "\n  Following TLVs can be added:\n\n";
    print "   1) CM Jump Time\n";
    print "      ...\n";
    print "  27) HMAC-Digest\n";
    print "  31) Key Sequence Number\n";
    print "\n  TLV " . $tlv_number . " - Choose which TLV will be generated:  ";
    $tlv_type = <>;
    chomp $tlv_type;
    if ($tlv_type eq "1") {
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
        print "\n  CM Jump Time sub-TLVs:\n\n";
        print "  1) Length of Jump\n";
        print "  2) Start Time of Jump\n";
        print "\n  sub-TLV " . $sub_tlv_number . " - Choose which TLV will be generated:  ";
        $sub_tlv_type = <>;
        chomp $sub_tlv_type;
        if ($sub_tlv_type eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "04" . random_bits(32, 0xFFFFFFFF);
          $sub_tlv_length = $sub_tlv_length + 6;
        } elsif ($sub_tlv_type eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "08" . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF);
          $sub_tlv_length = $sub_tlv_length + 10;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        print "\n  Is this last sub-TLV for this packet? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
        $sub_tlv_number++;
      }
      $packet_value = $packet_value . "01" . sprintf("%02x", $sub_tlv_length) . $sub_tlv_value;
      $packet_length = $packet_length + $sub_tlv_length + 2;
    } elsif ($tlv_type eq "27") {
      $packet_value = $packet_value . "1B" . "14" . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF);
      $packet_length = $packet_length + 22;
    } elsif ($tlv_type eq "31") {
      $packet_value = $packet_value . "1F" . "01" . sprintf("%02x", (int(rand(16))));
      $packet_length = $packet_length + 3;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
    }
    print "\n  Is this last TLV for this packet? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "18", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DCC_ACK() {
  our $packet_value;
  our $packet_length = 0;
  our $tlv_number = 1;
  our $tlv_type;
  our $last_tlv = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add TLV Encoded information
  while ($last_tlv != 1) {
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
    print "\n  Following TLVs can be added:\n\n";
    print "  27) HMAC-Digest\n";
    print "  31) Key Sequence Number\n";
    print "\n  TLV " . $tlv_number . " - Choose which TLV will be generated:  ";
    $tlv_type = <>;
    chomp $tlv_type;
    if ($tlv_type eq "27") {
      $packet_value = $packet_value . "1B" . "14" . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF);
      $packet_length = $packet_length + 22;
    } elsif ($tlv_type eq "31") {
      $packet_value = $packet_value . "1F" . "01" . sprintf("%02x", (int(rand(16))));
      $packet_length = $packet_length + 3;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
    }
    print "\n  Is this last TLV for this packet? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "19", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
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
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
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
    if ($choosen_tlv eq "1") {
      $packet_value = $packet_value . "01" . "01" . sprintf("%02x", 2 ** rand(0x5));
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "2") {
      $packet_value = $packet_value . "02" . "04" . sprintf("%08x", (int(rand(80)) + 5) * 1000000);
      $packet_length = $packet_length + 6;
    } elsif ($choosen_tlv eq "3") {
      $i = int(rand(127)) + 1;
      $packet_value = $packet_value . "03" . sprintf("%02x", $i);
      for (my $j = 0; $j < $i; $j++) {
        $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
      }
      $packet_length = $packet_length + $i + 2;
    } elsif ($choosen_tlv eq "5") {
      # Create BURST5 sub-TLVs
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
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
        if ($choosen_sub_tlv eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", rand(7) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "3") {
          $sub_tlv_value = $sub_tlv_value . "03" . "02" . sprintf("%04x", rand(1536) + 1);
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "4") {
          $sub_tlv_value = $sub_tlv_value . "04" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "5") {
          $sub_tlv_value = $sub_tlv_value . "05" . "01" . sprintf("%02x", rand(17));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "6") {
          $sub_tlv_value = $sub_tlv_value . "06" . "01" . sprintf("%02x", rand(238) + 16);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "7") {
          $sub_tlv_value = $sub_tlv_value . "07" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "8") {
          $sub_tlv_value = $sub_tlv_value . "08" . "01" . sprintf("%02x", rand(0xFF) + 16);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "9") {
          $sub_tlv_value = $sub_tlv_value . "09" . "01" . sprintf("%02x", rand(0xFF));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "10") {
          $sub_tlv_value = $sub_tlv_value . "0A" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "11") {
          $sub_tlv_value = $sub_tlv_value . "0B" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "12") {
          $sub_tlv_value = $sub_tlv_value . "0C" . "01" . sprintf("%02x", rand(0xFF));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "13") {
          $sub_tlv_value = $sub_tlv_value . "0D" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "14") {
          $sub_tlv_value = $sub_tlv_value . "0E" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "15") {
          $sub_tlv_value = $sub_tlv_value . "0F" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "16") {
          $sub_tlv_value = $sub_tlv_value . "10" . "01" . sprintf("%02x", rand(128) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "17") {
          $sub_tlv_value = $sub_tlv_value . "11" . "01" . sprintf("%02x", rand(31) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "18") {
          $sub_tlv_value = $sub_tlv_value . "12" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
      }
      $packet_value = $packet_value . "05" . sprintf("%02x", $sub_tlv_length + 1) . sprintf("%02x", int(rand(15)) + 1) . $sub_tlv_value;
      $packet_length = $packet_length + 3 + $sub_tlv_length;
    } elsif ($choosen_tlv eq "6") {
      $i = int(rand(63)) + 1;
      $packet_value = $packet_value . "06" . sprintf("%02x", $i);
      for (my $j = 0; $j < $i; $j++) {
        $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
      }
      $packet_length = $packet_length + $i + 2;
    } elsif ($choosen_tlv eq "7") {
      $packet_value = $packet_value . "07" . "01" . sprintf("%02x", int(rand(2)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "8") {
      $packet_value = $packet_value . "08" . "01" . sprintf("%02x", int(rand(32)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "9") {
      $packet_value = $packet_value . "09" . "01" . sprintf("%02x", int(rand(31)) + 2);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "10") {
      $packet_value = $packet_value . "0A" . "01" . sprintf("%02x", int(rand(65)) + 64);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "11") {
      $packet_value = $packet_value . "0B" . "02" . random_bits(16, 0xFFFE);
      $packet_length = $packet_length + 4;
    } elsif ($choosen_tlv eq "12") {
      $packet_value = $packet_value . "0C" . "02" . random_bits(16, 0xFFFF);
      $packet_length = $packet_length + 4;
    } elsif ($choosen_tlv eq "13") {
      $packet_value = $packet_value . "0D" . "02" . random_bits(16, 0xFFFF);
      $packet_length = $packet_length + 4;
    } elsif ($choosen_tlv eq "14") {
      $packet_value = $packet_value . "0E" . "09" . random_bits(32, 0xFFFFFFFF) . random_bits(24, 0xFFFFFF) . random_bits(16, 0xFFFF);
      $packet_length = $packet_length + 11;
    } elsif ($choosen_tlv eq "15") {
      $packet_value = $packet_value . "0F" . "01" . sprintf("%02x", int(rand(2)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "16") {
      $packet_value = $packet_value . "10" . "01" . sprintf("%02x", int(rand(3)));
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "17") {
      $packet_value = $packet_value . "11" . "01" . sprintf("%02x", int(rand(2)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "18") {
      $packet_value = $packet_value . "12" . "04" . random_bits(32, 0xFFFF000F);
      $packet_length = $packet_length + 6;
    } elsif ($choosen_tlv eq "19") {
      $packet_value = $packet_value . "13" . "04" . random_bits(32, 0xFFFF000F);
      $packet_length = $packet_length + 6;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
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

sub INIT_RNG_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add SID
  $packet_value = random_bits(16, 0x3FFF);
  $packet_length = $packet_length + 2;
  # Add Downstream Channel ID
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Upstream Channel ID
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "1E", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub MDD() {
  our $packet_value = "";
  our $packet_length = 0;
  our $last_tlv = 0;
  our $last_sub_tlv = 0;
  our $choosen_tlv;
  our $choosen_sub_tlv;
  our $tlv_number = 1;
  our $sub_tlv_number = 1;
  our $sub_tlv_value;
  our $sub_tlv_length = 0;
  our $i = 0;
  our $j = 0;
  # Add Configuration Change Count
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Number of Fragments
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Fragment Sequence Number
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Current Channel ID
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add TLV data
  while ($last_tlv != 1) {
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
    print "\n  Following TLVs can be added:\n\n";
    print "   1) Downstream Channel Active List\n";
    print "      ...\n";
    print "   2) MAC Domain Downstream Service Group\n";
    print "      ...\n";
    print "   3) Downstream Ambiguity Resolution Frequency List TLV\n";
    print "   4) Receive Channel Profile Reporting Control\n";
    print "      ...\n";
    print "   5) IP Initialization Parameters\n";
    print "      ...\n";
    print "   6) Early Authentication and Encryption\n";
    print "   7) Upstream Active Channel List\n";
    print "      ...\n";
    print "   8) Upstream Ambiguity Resolution Channel List\n";
    print "\n  TLV " . $tlv_number . " - Choose TLV which should be added:  ";
    $choosen_tlv = <>;
    chomp $choosen_tlv;
    if ($choosen_tlv eq "1") {
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
        print "\n  Following sub-TLVs can be added:\n\n";
        print "   1) Channel ID\n";
        print "   2) Frequency\n";
        print "   3) Modulation Order/Annex\n";
        print "   4) Primary Capable\n";
        print "   5) CM-STATUS Event Enable Bitmask\n";
        print "   6) MAP and UCD Transport Indicator\n";
        print "   7) OFDM PLC Parameters\n";
        print "\n  sub-TLV " . $sub_tlv_number++ . " - Choose sub-TLV which should be added:  ";
        $choosen_sub_tlv = <>;
        chomp $choosen_sub_tlv;
        if ($choosen_sub_tlv eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . random_bits(8, 0xFF);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "04" . sprintf("%08x", (int(rand(1686)) + 108) * 1000000);
          $sub_tlv_length = $sub_tlv_length + 6;
        } elsif ($choosen_sub_tlv eq "3") {
          my @array = (0, 1, 2, 16, 17, 18, 32, 33, 34);
          $sub_tlv_value = $sub_tlv_value . "03" . "01" . sprintf("%02x", $array[rand @array]);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "4") {
          $sub_tlv_value = $sub_tlv_value . "04" . "01" . random_bits(8, 0x01);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "5") {
          $sub_tlv_value = $sub_tlv_value . "05" . "02" . random_bits(16, 0x0036);
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "6") {
          $sub_tlv_value = $sub_tlv_value . "06" . "01" . random_bits(8, 0x01);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "7") {
          $sub_tlv_value = $sub_tlv_value . "07" . "01" . random_bits(8, 0x7F);
          $sub_tlv_length = $sub_tlv_length + 3;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
      }
      $packet_value = $packet_value . "01" . sprintf("%02x", $sub_tlv_length) . $sub_tlv_value;
      $packet_length = $packet_length + $sub_tlv_length + 2;
    } elsif ( $choosen_tlv eq "2" ) {
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
        print "\n  Following sub-TLVs can be added:\n\n";
        print "   1) MD-DS-SG Identifier\n";
        print "   2) Downstream Channel ID list\n";
        print "\n  sub-TLV " . $sub_tlv_number++ . " - Choose sub-TLV which should be added:  ";
        $choosen_sub_tlv = <>;
        chomp $choosen_sub_tlv;
        if ($choosen_sub_tlv eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . random_bits(8, 0xFF);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "2") {
          $i = rand(0x1F);
          $sub_tlv_value = $sub_tlv_value . "02" . sprintf("%02x", $i);
          for ($j=1; $j <= $i; $j++) {
            $sub_tlv_value = $sub_tlv_value . random_bits(8, 0xFF);
          }
          $sub_tlv_length = $sub_tlv_length + 2 + $i;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
      }
      $packet_value = $packet_value . "02" . sprintf("%02x", $sub_tlv_length) . $sub_tlv_value;
      $packet_length = $packet_length + $sub_tlv_length + 2;
    } elsif ( $choosen_tlv eq "3" ) {
      $i = int(rand(8)) + 1;
      $packet_value = $packet_value . "03" . sprintf("%02x", $i * 4);
      for ($j=1; $j <= $i; $j++) {
        $packet_value = $packet_value . sprintf("%08x", (int(rand(1686)) + 108) * 1000000);
      }
      $packet_length = $packet_length + 2 + $i * 4;
    } elsif ( $choosen_tlv eq "4" ) {
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
        print "\n  Following sub-TLVs can be added:\n\n";
        print "   1) RCP SC-QAM Center Frequency Spacing\n";
        print "   2) Verbose RCP reporting\n";
        print "   3) Fragmented RCP transmission\n";
        print "\n  sub-TLV " . $sub_tlv_number++ . " - Choose sub-TLV which should be added:  ";
        $choosen_sub_tlv = <>;
        chomp $choosen_sub_tlv;
        if ($choosen_sub_tlv eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", int(rand(2)));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", int(rand(2)));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "3") {
          $sub_tlv_value = $sub_tlv_value . "03" . "01" . "01";
          $sub_tlv_length = $sub_tlv_length + 3;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
      }
      $packet_value = $packet_value . "04" . sprintf("%02x", $sub_tlv_length) . $sub_tlv_value;
      $packet_length = $packet_length + $sub_tlv_length + 2;
    } elsif ( $choosen_tlv eq "5" ) {
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
        print "\n  Following sub-TLVs can be added:\n\n";
        print "   1) IP Provisioning Mode\n";
        print "   2) Pre-Registration DSID\n";
        print "\n  sub-TLV " . $sub_tlv_number++ . " - Choose sub-TLV which should be added:  ";
        $choosen_sub_tlv = <>;
        chomp $choosen_sub_tlv;
        if ($choosen_sub_tlv eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", int(rand(4)));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "03" . random_bits(24, 0x0FFFFF);
          $sub_tlv_length = $sub_tlv_length + 5;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
      }
      $packet_value = $packet_value . "05" . sprintf("%02x", $sub_tlv_length) . $sub_tlv_value;
      $packet_length = $packet_length + $sub_tlv_length + 2;
    } elsif ( $choosen_tlv eq "6" ) {
      $packet_value = $packet_value . "06" . "01" . sprintf("%02x", int(rand(2)));
      $packet_length = $packet_length + 3;
    } elsif ( $choosen_tlv eq "7" ) {
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
        print "\n  Following sub-TLVs can be added:\n\n";
        print "   1) Upstream Channel ID for a channel being listed\n";
        print "   2) CM-STATUS Event Enable Bitmask\n";
        print "   3) Upstream Channel Priority\n";
        print "   4) Downstream Channel(s) on which MAPs and UCDs for this Upstream Channel are sent\n";
        print "\n  sub-TLV " . $sub_tlv_number++ . " - Choose sub-TLV which should be added:  ";
        $choosen_sub_tlv = <>;
        chomp $choosen_sub_tlv;
        if ($choosen_sub_tlv eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . random_bits(8, 0xFF);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "02" . random_bits(16, 0x01C0);
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "3") {
          $sub_tlv_value = $sub_tlv_value . "03" . "01" . sprintf("%02x", int(rand(8)));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "4") {
          $i = int(rand(16)) + 1;
          $sub_tlv_value = $sub_tlv_value . "04" . sprintf("%02x", $i);
          for ($j=1; $j <= $i; $j++) {
            $sub_tlv_value = $sub_tlv_value . random_bits(8, 0xFF);
          }
          $sub_tlv_length = $sub_tlv_length + 2 + $i;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
      }
      $packet_value = $packet_value . "07" . sprintf("%02x", $sub_tlv_length) . $sub_tlv_value;
      $packet_length = $packet_length + $sub_tlv_length + 2;
    } elsif ( $choosen_tlv eq "8" ) {
      $i = int(rand(16)) + 1;
      $packet_value = $packet_value . "08" . sprintf("%02x", $i);
      for ($j=1; $j <= $i; $j++) {
        $packet_value = $packet_value . random_bits(8, 0xFF);
      }
      $packet_length = $packet_length + 2 + $i;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
    }
    printf "\n  Is this last TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "21", "00");
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
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
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
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
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
    if ($choosen_tlv eq "1") {
      $packet_value = $packet_value . "01" . "01" . sprintf("%02x", 2 ** rand(0x5));
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "2") {
      $packet_value = $packet_value . "02" . "04" . sprintf("%08x", (int(rand(80)) + 5) * 1000000);
      $packet_length = $packet_length + 6;
    } elsif ($choosen_tlv eq "3") {
      $i = int(rand(127)) + 1;
      $packet_value = $packet_value . "03" . sprintf("%02x", $i);
      for (my $j = 0; $j < $i; $j++) {
        $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
      }
      $packet_length = $packet_length + $i + 2;
    } elsif ($choosen_tlv eq "5") {
      # Create BURST5 sub-TLVs
      $sub_tlv_value = "";
      $sub_tlv_length = 0;
      $last_sub_tlv = 0;
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
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
        if ($choosen_sub_tlv eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", rand(7) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "3") {
          $sub_tlv_value = $sub_tlv_value . "03" . "02" . sprintf("%04x", rand(1536) + 1);
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "4") {
          $sub_tlv_value = $sub_tlv_value . "04" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "5") {
          $sub_tlv_value = $sub_tlv_value . "05" . "01" . sprintf("%02x", rand(17));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "6") {
          $sub_tlv_value = $sub_tlv_value . "06" . "01" . sprintf("%02x", rand(238) + 16);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "7") {
          $sub_tlv_value = $sub_tlv_value . "07" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "8") {
          $sub_tlv_value = $sub_tlv_value . "08" . "01" . sprintf("%02x", rand(0xFF) + 16);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "9") {
          $sub_tlv_value = $sub_tlv_value . "09" . "01" . sprintf("%02x", rand(0xFF));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "10") {
          $sub_tlv_value = $sub_tlv_value . "0A" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "11") {
          $sub_tlv_value = $sub_tlv_value . "0B" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "12") {
          $sub_tlv_value = $sub_tlv_value . "0C" . "01" . sprintf("%02x", rand(0xFF));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "13") {
          $sub_tlv_value = $sub_tlv_value . "0D" . "02" . sprintf("%04x", rand(0xFFFF));
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($choosen_sub_tlv eq "14") {
          $sub_tlv_value = $sub_tlv_value . "0E" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "15") {
          $sub_tlv_value = $sub_tlv_value . "0F" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "16") {
          $sub_tlv_value = $sub_tlv_value . "10" . "01" . sprintf("%02x", rand(128) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "17") {
          $sub_tlv_value = $sub_tlv_value . "11" . "01" . sprintf("%02x", rand(31) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($choosen_sub_tlv eq "18") {
          $sub_tlv_value = $sub_tlv_value . "12" . "01" . sprintf("%02x", rand(2) + 1);
          $sub_tlv_length = $sub_tlv_length + 3;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        printf "\n  Is this last sub-TLV to be added? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
      }
      $packet_value = $packet_value . "05" . sprintf("%02x", $sub_tlv_length + 1) . sprintf("%02x", int(rand(15)) + 1) . $sub_tlv_value;
      $packet_length = $packet_length + 3 + $sub_tlv_length;
    } elsif ($choosen_tlv eq "6") {
      $i = int(rand(63)) + 1;
      $packet_value = $packet_value . "06" . sprintf("%02x", $i);
      for (my $j = 0; $j < $i; $j++) {
        $packet_value = $packet_value . sprintf("%02x", rand(0xFF));
      }
      $packet_length = $packet_length + $i + 2;
    } elsif ($choosen_tlv eq "7") {
      $packet_value = $packet_value . "07" . "01" . sprintf("%02x", int(rand(2)));
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "8") {
      $packet_value = $packet_value . "08" . "01" . sprintf("%02x", int(rand(32)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "9") {
      $packet_value = $packet_value . "09" . "01" . sprintf("%02x", int(rand(31)) + 2);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "10") {
      $packet_value = $packet_value . "0A" . "01" . sprintf("%02x", int(rand(65)) + 64);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "11") {
      $packet_value = $packet_value . "0B" . "02" . random_bits(16, 0xFFFE);
      $packet_length = $packet_length + 4;
    } elsif ($choosen_tlv eq "12") {
      $packet_value = $packet_value . "0C" . "02" . random_bits(16, 0xFFFF);
      $packet_length = $packet_length + 4;
    } elsif ($choosen_tlv eq "13") {
      $packet_value = $packet_value . "0D" . "02" . random_bits(16, 0xFFFF);
      $packet_length = $packet_length + 4;
    } elsif ($choosen_tlv eq "14") {
      $packet_value = $packet_value . "0E" . "09" . random_bits(32, 0xFFFFFFFF) . random_bits(24, 0xFFFFFF) . random_bits(16, 0xFFFF);
      $packet_length = $packet_length + 11;
    } elsif ($choosen_tlv eq "15") {
      $packet_value = $packet_value . "0F" . "01" . sprintf("%02x", int(rand(2)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "16") {
      $packet_value = $packet_value . "10" . "01" . sprintf("%02x", int(rand(3)));
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "17") {
      $packet_value = $packet_value . "11" . "01" . sprintf("%02x", int(rand(2)) + 1);
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "18") {
      $packet_value = $packet_value . "12" . "04" . random_bits(32, 0xFFFF000F);
      $packet_length = $packet_length + 6;
    } elsif ($choosen_tlv eq "19") {
      $packet_value = $packet_value . "13" . "04" . random_bits(32, 0xFFFF000F);
      $packet_length = $packet_length + 6;
    } elsif ($choosen_tlv eq "20") {
      $packet_value = $packet_value . "14" . "01" . sprintf("%02x", int(rand(4)));
      $packet_length = $packet_length + 3;
    } elsif ($choosen_tlv eq "21") {
      $packet_value = $packet_value . "15" . "10" . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF) . random_bits(32, 0xFFFFFFFF);
      $packet_length = $packet_length + 18;
    } elsif ($choosen_tlv eq "22") {
      $packet_value = $packet_value . "16" . "01" . random_bits(8, 0x01);
      $packet_length = $packet_length + 3;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
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

sub DBC_REQ() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Number of fragments
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Fragment Sequence Number
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "24", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DBC_RSP() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Confirmation Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "25", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub DBC_ACK() {
  our $packet_value;
  our $packet_length = 0;
  # Add Transaction ID
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "26", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub REG_REQ_MP() {
  our $packet_value;
  our $packet_length = 0;
  # Add Service Identifier
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Number of fragments
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Fragment Sequence Number
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "2C", "00");
  # Add DOCSIS header
  ($packet_value, $packet_length) = add_docsis($packet_value, $packet_length, "0000", undef, "00", 192, 2, 0);
  return ($packet_value, $packet_length);
}

sub REG_RSP_MP() {
  our $packet_value;
  our $packet_length = 0;
  # Add Service Identifier
  $packet_value = random_bits(16, 0xFFFF);
  $packet_length = $packet_length + 2;
  # Add Response Code
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Number of fragments
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Fragment Sequence Number
  $packet_value = $packet_value . random_bits(8, 0xFF);
  $packet_length = $packet_length + 1;
  # Add Annex C TLVs
  ($packet_value, $packet_length) = add_annex_c_tlvs($packet_value, $packet_length);
  # Add MAC Management header
  ($packet_value, $packet_length) = add_mac_management($packet_value, $packet_length, "00", "00", "01", "2D", "00");
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
  if ($input[6] eq "0" || $input[6] eq "2") {
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
  } elsif ($input[6] eq "4") {
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
  } elsif ($input[6] eq "8") {
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
  }
  return ($packet_value, $packet_length);
}

sub random_bits {
  my $i = 0;
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

sub add_annex_c_tlvs {
  our $packet_value;
  our $packet_length;
  our $last_tlv = 0;
  our $last_sub_tlv = 0;
  our $tlv_number = 1;
  our $tlv_type;
  our $sub_tlv_number = 1;
  our $sub_tlv_type;
  our $sub_tlv_length = 0;
  our $sub_tlv_value = "";
  $packet_value = $_[0];
  $packet_length = $_[1];
  while ($last_tlv != 1) {
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
    print "\n  Choose Annex C TLVs to be added:\n\n";
    print "   1) Downstream Frequency\n";
    print "   2) Upstream Channel ID\n";
    print "   3) Network Access\n";
    print "   4) DOCSIS 1.0 Class of Service\n";
    print "      ...\n";
    print "\n  TLV " . $tlv_number . " - Choose which TLV will be generated:  ";
    $tlv_type = <>;
    chomp $tlv_type;
    if ($tlv_type eq "1") {
      $packet_value = $packet_value . "01" . "04" . sprintf("%08x", (int(rand(1686)) + 108) * 1000000);
      $packet_length = $packet_length + 6;
    } elsif ($tlv_type eq "2") {
      $packet_value = $packet_value . "02" . "01" . random_bits(8, 0xFF);
      $packet_length = $packet_length + 3;
    } elsif ($tlv_type eq "3") {
      $packet_value = $packet_value . "03" . "01" . random_bits(8, 0x01);
      $packet_length = $packet_length + 3;
    } elsif ($tlv_type eq "4") {
      while ($last_sub_tlv != 1) {
        if ($clear_screen) {
          system $^O eq 'MSWin32' ? 'cls' : 'clear';
        }
        print "\n  Class of Service sub-TLVs which can be added:\n\n";
        print "  1) Class ID\n";
        print "  2) Maximum Downstream Rate\n";
        print "  3) Maximum Upstream Rate\n";
        print "  4) Upstream Channel Priority\n";
        print "  5) Guaranteed Minimum Upstream Chanel Data Rate\n";
        print "  6) Maximum Upstream Channel Transmit Burst\n";
        print "  7) Class-of-Service Privacy Enable\n";
        print "\n  sub-TLV " . $sub_tlv_number . " - Choose which TLV will be generated:  ";
        $sub_tlv_type = <>;
        chomp $sub_tlv_type;
        if ($sub_tlv_type eq "1") {
          $sub_tlv_value = $sub_tlv_value . "01" . "01" . sprintf("%02x", (int(rand(16)) + 1));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($sub_tlv_type eq "2") {
          $sub_tlv_value = $sub_tlv_value . "02" . "04" . random_bits(32, 0x00FF0000);
          $sub_tlv_length = $sub_tlv_length + 6;
        } elsif ($sub_tlv_type eq "3") {
          $sub_tlv_value = $sub_tlv_value . "03" . "04" . random_bits(32, 0x00FF0000);
          $sub_tlv_length = $sub_tlv_length + 6;
        } elsif ($sub_tlv_type eq "4") {
          $sub_tlv_value = $sub_tlv_value . "04" . "01" . sprintf("%02x", (int(rand(8))));
          $sub_tlv_length = $sub_tlv_length + 3;
        } elsif ($sub_tlv_type eq "5") {
          $sub_tlv_value = $sub_tlv_value . "05" . "04" . random_bits(32, 0x00FF0000);
          $sub_tlv_length = $sub_tlv_length + 6;
        } elsif ($sub_tlv_type eq "6") {
          $sub_tlv_value = $sub_tlv_value . "06" . "02" . random_bits(16, 0xFF00);
          $sub_tlv_length = $sub_tlv_length + 4;
        } elsif ($sub_tlv_type eq "7") {
          $sub_tlv_value = $sub_tlv_value . "07" . "01" . sprintf("%02x", (int(rand(2))));
          $sub_tlv_length = $sub_tlv_length + 3;
        } else {
          print "\n  This is not a valid option. Calling EXIT... \n\n";
          exit;
        }
        print "\n  Is this last sub-TLV for this packet? (Choose: 1 for YES / 0 for NO)  ";
        $last_sub_tlv = <>;
        $sub_tlv_number++;
      }
      $packet_value = $packet_value . "04" . sprintf("%02x", $sub_tlv_length) . $sub_tlv_value;
      $packet_length = $packet_length + $sub_tlv_length + 2;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
    }
    print "\n  Is this last TLV for this packet? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  return ($packet_value, $packet_length);
}

sub add_bpkm_attributes() {
  our @input = @_;
  our $packet_value;
  our $packet_length;
  our $tlv_number = 1;
  our $tlv_type;
  our $last_tlv = 0;
  our @ISO8859_1;
  our $i;
  our $j;
  our $this_attribute_length;
  our $attributes_length = 0;
  our $attributes_value = "";
  our $compound_attributes_length = 0;
  our $compound_attributes_value = "";
  our @DES_length;
  our @AuthKey;
  our @TEK;
  our $compound_length = 0;
  our $compound_value = "";
  our $vendor_defined_length;
  our @CryptoSuite;
  $packet_value = $input[0];
  $packet_length = $input[1];
  while ($last_tlv != 1) {
    if ($clear_screen) {
      system $^O eq 'MSWin32' ? 'cls' : 'clear';
    }
    print "\n  Following Attributes can be added:\n\n";
    print "    1) Serial Number\n";
    print "    2) Manufacturer ID\n";
    print "    3) MAC Address\n";
    print "    4) RSA Public Key\n";
    print "    5) CM Identification\n";
    print "    6) Display String\n";
    print "    7) Authorization Key\n";
    print "    8) Encrypted Traffic Encryption Key (TEK)\n";
    print "    9) Key Lifetime\n";
    print "   10) Key Sequence Number\n";
    print "   11) HMAC Digesh\n";
    print "   12) SAID\n";
    print "   13) TEK-Parameters\n";
    print "   15) Cipher Block Chaining (CBC) Initialization Vector\n";
    print "   16) Error Code\n";
    print "   17) CA Certificate\n";
    print "   18) CM Certificate\n";
    print "   19) Security Capabilities\n";
    print "   20) Cryptographic Suite\n";
    print "   21) Cryptographic Suite List\n";
    print "   22) BPI Version\n";
    print "   23) SA Descriptor\n";
    print "   24) SA Type\n";
    print "   25) SA Query\n";
    print "   26) SA Query Type\n";
    print "   27) IPv4 Address\n";
    print "  127) Vendor Defined\n";
    print "\n  Attribute " . $tlv_number . " - Choose which Attribute will be generated:  ";
    $tlv_type = <>;
    chomp $tlv_type;
    if ($tlv_type eq "1") {
      $this_attribute_length = int(rand(10)) + 10;
      $attributes_value = $attributes_value . "01" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 3;
      @ISO8859_1 = ("41", "42", "43", "44", "45", "46", "47", "48", "49", "4A",
                    "4B", "4C", "4D", "4E", "4F", "50", "51", "52", "53", "54",
                    "55", "56", "57", "58", "59", "5A", "61", "62", "63", "64",
                    "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E",
                    "6F", "70", "71", "72", "73", "74", "75", "76", "77", "78",
                    "79", "7A", "30", "31", "32", "33", "34", "35", "36", "37",
                    "38", "39", "2D");
      for ($i = 1; $i <= $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . $ISO8859_1[rand(@ISO8859_1)];
      }
      $attributes_length = $attributes_length + $this_attribute_length;
    } elsif ($tlv_type eq "2") {
      $attributes_value = $attributes_value . "02" . "0003";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . random_bits(8, 0xFF) . random_bits(8, 0xFF) . random_bits(8, 0xFF);
      $attributes_length = $attributes_length + 3;
    } elsif ($tlv_type eq "3") {
      $attributes_value = $attributes_value . "03" . "0006";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . random_bits(24, 0xFFFFFF) . random_bits(24, 0xFFFFFF);
      $attributes_length = $attributes_length + 6;
    } elsif ($tlv_type eq "4") {
      @DES_length = (106, 140, 270);
      $this_attribute_length = $DES_length[rand(@DES_length)];
      $attributes_value = $attributes_value . "04" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 3;
      for ($i = 0; $i < $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . random_bits(8, 0xFF);
      }
      $attributes_length = $attributes_length + $this_attribute_length;
    } elsif ($tlv_type eq "5") {
      $compound_attributes_value = "";
      $compound_attributes_length = 0;
      $compound_value = "";
      $compound_length = 0;
      $this_attribute_length = int(rand(10)) + 10;
      $compound_attributes_value = $compound_attributes_value . "01" . sprintf("%04x", $this_attribute_length);
      $compound_attributes_length = $compound_attributes_length + 3;
      @ISO8859_1 = ("41", "42", "43", "44", "45", "46", "47", "48", "49", "4A",
                    "4B", "4C", "4D", "4E", "4F", "50", "51", "52", "53", "54",
                    "55", "56", "57", "58", "59", "5A", "61", "62", "63", "64",
                    "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E",
                    "6F", "70", "71", "72", "73", "74", "75", "76", "77", "78",
                    "79", "7A", "30", "31", "32", "33", "34", "35", "36", "37",
                    "38", "39", "2D");
      for ($i = 1; $i <= $this_attribute_length; $i++) {
        $compound_attributes_value = $compound_attributes_value . $ISO8859_1[rand(@ISO8859_1)];
      }
      $compound_attributes_length = $compound_attributes_length + $this_attribute_length;
      $compound_attributes_value = $compound_attributes_value . "02" . "0003";
      $compound_attributes_length = $compound_attributes_length + 3;
      $compound_attributes_value = $compound_attributes_value . random_bits(8, 0xFF) . random_bits(8, 0xFF) . random_bits(8, 0xFF);
      $compound_attributes_length = $compound_attributes_length + 3;
      $compound_attributes_value = $compound_attributes_value . "03" . "0006";
      $compound_attributes_length = $compound_attributes_length + 3;
      $compound_attributes_value = $compound_attributes_value . random_bits(24, 0xFFFFFF) . random_bits(24, 0xFFFFFF);
      $compound_attributes_length = $compound_attributes_length + 6;
      @DES_length = (106, 140, 270);
      $this_attribute_length = $DES_length[rand(@DES_length)];
      $compound_attributes_value = $compound_attributes_value . "04" . sprintf("%04x", $this_attribute_length);
      $compound_attributes_length = $compound_attributes_length + 3;
      for ($i = 0; $i < $this_attribute_length; $i++) {
        $compound_attributes_value = $compound_attributes_value . random_bits(8, 0xFF);
      }
      $compound_attributes_length = $compound_attributes_length + $this_attribute_length;
      $compound_value = $compound_value . "02" . "0003";
      $compound_length = $compound_length +3;
      $compound_value = $compound_value . random_bits(8, 0xFF) . random_bits(8, 0xFF) . random_bits(8, 0xFF);
      $compound_length = $compound_length +3;
      for ($i = 0; $i < rand(10); $i++) {
        $vendor_defined_length = int(rand(12)) + 1;
        $compound_value = $compound_value . random_bits(8, 0xFE) . sprintf("%04x", $vendor_defined_length);
        for ($j = 0; $j < $vendor_defined_length; $j++) {
          $compound_value = $compound_value . random_bits(8, 0xFF);
        }
        $compound_length = $compound_length + 1 + 2 + $vendor_defined_length;
      }
      $compound_attributes_value = $compound_attributes_value . "7F" . sprintf("%04x", $compound_length) . $compound_value;
      $compound_attributes_length = $compound_attributes_length + 1 + 2 + $compound_length;
      $attributes_value = $attributes_value . "05" . sprintf("%04x", $compound_attributes_length) . $compound_attributes_value;
      $attributes_length = $attributes_length + 1 + 2 + $compound_attributes_length;
    } elsif ($tlv_type eq "6") {
      $this_attribute_length = int(rand(118)) + 10;
      $attributes_value = $attributes_value . "06" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 3;
      @ISO8859_1 = ("41", "42", "43", "44", "45", "46", "47", "48", "49", "4A",
                    "4B", "4C", "4D", "4E", "4F", "50", "51", "52", "53", "54",
                    "55", "56", "57", "58", "59", "5A", "61", "62", "63", "64",
                    "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E",
                    "6F", "70", "71", "72", "73", "74", "75", "76", "77", "78",
                    "79", "7A", "30", "31", "32", "33", "34", "35", "36", "37",
                    "38", "39", "2D");
      for ($i = 1; $i <= $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . $ISO8859_1[rand(@ISO8859_1)];
      }
      $attributes_length = $attributes_length + $this_attribute_length;
    } elsif ($tlv_type eq "7") {
      @AuthKey = (96, 128, 256);
      $this_attribute_length = $AuthKey[rand(@AuthKey)];
      $attributes_value = $attributes_value . "07" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 3;
      for ($i = 0; $i < $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . random_bits(8, 0xFF);
      }
      $attributes_length = $attributes_length + $this_attribute_length;
    } elsif ($tlv_type eq "8") {
      @TEK = (8, 16);
      $this_attribute_length = $TEK[rand(@TEK)];
      $attributes_value = $attributes_value . "08" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 3;
      for ($i = 0; $i < $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . random_bits(8, 0xFF);
      }
      $attributes_length = $attributes_length + $this_attribute_length;
    } elsif ($tlv_type eq "9") {
      $attributes_value = $attributes_value . "09" . "0004";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . random_bits(32, 0xFFFFFFFF);
      $attributes_length = $attributes_length + 4;
    } elsif ($tlv_type eq "10") {
      $attributes_value = $attributes_value . "0A" . "0001";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . random_bits(8, 0x0F);
      $attributes_length = $attributes_length + 1;
    } elsif ($tlv_type eq "11") {
      $attributes_value = $attributes_value . "0B" . "0014";
      $attributes_length = $attributes_length + 3;
      for ($i = 0; $i < 20; $i++) {
        $attributes_value = $attributes_value . random_bits(8, 0xFF);
      }
      $attributes_length = $attributes_length + 20;
    } elsif ($tlv_type eq "12") {
      $attributes_value = $attributes_value . "0C" . "0002";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . random_bits(16, 0x3FFF);
      $attributes_length = $attributes_length + 2;
    } elsif ($tlv_type eq "13") {
      @TEK = (8, 16);
      $this_attribute_length = $TEK[rand(@TEK)];
      if ($this_attribute_length == 8) {
        $attributes_value = $attributes_value . "0D" . "0021";
        $attributes_length = $attributes_length + 3;
      } elsif ($this_attribute_length == 16) {
        $attributes_value = $attributes_value . "0D" . "0031";
        $attributes_length = $attributes_length + 3;
      }
      $attributes_value = $attributes_value . "08" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 3;
      for ($i = 0; $i < $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . random_bits(8, 0xFF);
      }
      $attributes_length = $attributes_length + $this_attribute_length;
      $attributes_value = $attributes_value . "09" . "0004";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . random_bits(32, 0xFFFFFFFF);
      $attributes_length = $attributes_length + 4;
      $attributes_value = $attributes_value . "0A" . "0001";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . random_bits(8, 0x0F);
      $attributes_length = $attributes_length + 1;
      $attributes_value = $attributes_value . "0F" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 3;
      for ($i = 0; $i < $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . random_bits(8, 0xFF);
      }
      $attributes_length = $attributes_length + $this_attribute_length;
    } elsif ($tlv_type eq "15") {
      @TEK = (8, 16);
      $this_attribute_length = $TEK[rand(@TEK)];
      $attributes_value = $attributes_value . "0F" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 3;
      for ($i = 0; $i < $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . random_bits(8, 0xFF);
      }
      $attributes_length = $attributes_length + $this_attribute_length;
    } elsif ($tlv_type eq "16") {
      $attributes_value = $attributes_value . "10" . "0001";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . sprintf("%02x", int(rand(11)));
      $attributes_length = $attributes_length + 1;
    } elsif ($tlv_type eq "127") {
      $compound_value = "";
      $compound_length = 0;
      $compound_value = $compound_value . "02" . "0003";
      $compound_length = $compound_length +3;
      $compound_value = $compound_value . random_bits(8, 0xFF) . random_bits(8, 0xFF) . random_bits(8, 0xFF);
      $compound_length = $compound_length +3;
      for ($i = 0; $i < rand(10); $i++) {
        $vendor_defined_length = int(rand(12)) + 1;
        $compound_value = $compound_value . random_bits(8, 0xFE) . sprintf("%04x", $vendor_defined_length);
        for ($j = 0; $j < $vendor_defined_length; $j++) {
          $compound_value = $compound_value . random_bits(8, 0xFF);
        }
        $compound_length = $compound_length + 1 + 2 + $vendor_defined_length;
      }
      $attributes_value = $attributes_value . "7F" . sprintf("%04x", $compound_length) . $compound_value;
      $attributes_length = $attributes_length + 1 + 2 + $compound_length;
    } elsif ($tlv_type eq "17") {
      $this_attribute_length = int(rand(128)) + 128;
      $attributes_value = $attributes_value . "11" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 1 + 2 + $this_attribute_length;
      for ($i = 0; $i < $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . random_bits(8, 0xFF);
      }
    } elsif ($tlv_type eq "18") {
      $this_attribute_length = int(rand(128)) + 128;
      $attributes_value = $attributes_value . "12" . sprintf("%04x", $this_attribute_length);
      $attributes_length = $attributes_length + 1 + 2 + $this_attribute_length;
      for ($i = 0; $i < $this_attribute_length; $i++) {
        $attributes_value = $attributes_value . random_bits(8, 0xFF);
      }
    } elsif ($tlv_type eq "19") {
      $attributes_value = $attributes_value . "13" . "000D";
      $attributes_length = $attributes_length + 1 + 2;
      $attributes_value = $attributes_value . "15" . "0006" . "010002000300";
      $attributes_length = $attributes_length + 1 + 2 + 6;
      $attributes_value = $attributes_value . "16" . "0001" . sprintf("%02x", int(rand(2)));
      $attributes_length = $attributes_length + 1 + 2 + 1;
    } elsif ($tlv_type eq "20") {
      @CryptoSuite = ("0100", "0200", "0300");
      $attributes_value = $attributes_value . "14" . "0002" . $CryptoSuite[rand(@CryptoSuite)];
      $attributes_length = $attributes_length + 1 + 2 + 2;
    } elsif ($tlv_type eq "21") {
      $attributes_value = $attributes_value . "15" . "0006" . "010002000300";
      $attributes_length = $attributes_length + 1 + 2 + 6;
    } elsif ($tlv_type eq "22") {
      $attributes_value = $attributes_value . "16" . "0001" . sprintf("%02x", int(rand(2)));
      $attributes_length = $attributes_length + 1 + 2 + 1;
    } elsif ($tlv_type eq "23") {
      $attributes_value = $attributes_value . "17" . "000E";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . "0C" . "0002";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . random_bits(16, 0x3FFF);
      $attributes_length = $attributes_length + 2;
      $attributes_value = $attributes_value . "18" . "0001" . sprintf("%02x", int(rand(3)));
      $attributes_length = $attributes_length + 1 + 2 + 1;
      @CryptoSuite = ("0100", "0200", "0300");
      $attributes_value = $attributes_value . "14" . "0002" . $CryptoSuite[rand(@CryptoSuite)];
      $attributes_length = $attributes_length + 1 + 2 + 2;
    } elsif ($tlv_type eq "24") {
      $attributes_value = $attributes_value . "18" . "0001" . sprintf("%02x", int(rand(3)));
      $attributes_length = $attributes_length + 1 + 2 + 1;
    } elsif ($tlv_type eq "25") {
      $attributes_value = $attributes_value . "19" . "000B";
      $attributes_length = $attributes_length + 3;
      $attributes_value = $attributes_value . "1A" . "0001" . random_bits(8, 0xFF);
      $attributes_length = $attributes_length + 1 + 2 + 1;
      $attributes_value = $attributes_value . "1B" . "0004" . random_bits(32, 0xFEFFFFFF);
      $attributes_length = $attributes_length + 1 + 2 + 4;
    } elsif ($tlv_type eq "26") {
      $attributes_value = $attributes_value . "1A" . "0001" . random_bits(8, 0xFF);
      $attributes_length = $attributes_length + 1 + 2 + 1;
    } elsif ($tlv_type eq "27") {
      $attributes_value = $attributes_value . "1B" . "0004" . random_bits(32, 0xFEFFFFFF);
      $attributes_length = $attributes_length + 1 + 2 + 4;
    } else {
      print "\n  This is not a valid option. Calling EXIT... \n\n";
      exit;
    }
    print "\n  Is this last Attribute for this packet? (Choose: 1 for YES / 0 for NO)  ";
    $last_tlv = <>;
    $tlv_number++;
  }
  # Add Attributes Length
  $packet_value = $packet_value . sprintf("%04x", $attributes_length);
  $packet_length = $packet_length + 2;
  # Add Attributes Value
  $packet_value = $packet_value . $attributes_value;
  $packet_length = $packet_length + $attributes_length;
  return ($packet_value, $packet_length);
}
