#! /usr/bin/perl 
# 
#  Argus Software
#  Copyright (c) 2000-2009 QoSient, LLC
#  All rights reserved.
# 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2, or (at your option)
#  any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
# 
#  ra() based host port use report
#  
#  written by Carter Bullard
#  QoSient, LLC
#
# 
#  $Id: //depot/argus/clients/clients/raports.pl#4 $
#  $DateTime: 2009/03/02 16:33:42 $
#  $Change: 1662 $
# 

#
# Complain about undeclared variables

use strict;

# Used modules
use POSIX;

# Global variables

my $Racluster = "/home/carter/argus/clients/bin/racluster";
my $Rasort    = "/home/carter/argus/clients/bin/rasort";
my $Options   = "-nn";        # Default Options
my $RacOpts   = "-m inode -w - ";   # Default racluster Options
my $VERSION   = "4.0.6";                
my $format    = 'inode';
my $fields    = '-s stime dur inode ias sttl avgdur maxdur mindur trans';
my $model     = '-m trans sttl';
my $filter    = '- icmpmap';
my @arglist   = ();


ARG: while (my $arg = shift(@ARGV)) {
   for ($arg) {
   }
   $arglist[@arglist + 0] = $arg;
}

# Start the program
chomp $Racluster;
chomp $Rasort;

my @cargs = ($Racluster, $Options, $RacOpts, @arglist, $filter);
my @sargs = ($Rasort, $model, $fields, $Options, "-c ,");
my @args = (@cargs, " | ", @sargs);

my (%items, %addrs, $stime, $dur, $inode, $ias, $sttl, $avgdur, $maxdur, $mindur, $trans);

printf "%s", "@args\n";

my $count     = 0;

open(SESAME, "@args |");
my $label = <SESAME>; 
chomp $label;

while (my $data = <SESAME>) {
   ($stime, $dur, $inode, $ias, $sttl, $avgdur, $maxdur, $mindur, $trans) = split(/,/, $data);
   chomp $trans;
   printf "<node type=\"ROUTER\" id=\"$inode\" >\n";
   if ($ias eq "") {
   } else {
      printf "   <property name=\"iAS\" value=\"$ias\" />\n";
   }
   printf "   <property name=\"MinDur\" value=\"$mindur\" />\n";
   printf "   <property name=\"AvgDur\" value=\"$avgdur\" />\n";
   printf "</node>\n";
}
close(SESAME);
exit 0;
