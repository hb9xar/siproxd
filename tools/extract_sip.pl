#!/usr/bin/perl
#
#
# extract a buffer dump from siproxd's debug log and
# write the plain content into a file. This file then
# may be used to feed netcat for a replay.#
#
# $ netcat -u   siphost 5060 < buffer.sip
#
# usage:
# reads from STDIN and writes to STDOUT
#
# $ cat  bufferdump.log | extract_sip.pl > buffer.sip

while (<>) {
   # strip off CR/LF
   chomp;

   # cut out the hex digits and store them into an array
   my $line=$_;
   $line =~ s/^ *//;
   my @hex=split(/ /, substr($line, 0, 50));

   for (my $i=0; $i<16; $i++) {
      # write HEX byte as character
      if (hex($hex[$i]) != "") {print chr(hex($hex[$i]));}
   }
}
