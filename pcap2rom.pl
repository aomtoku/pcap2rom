#!/usr/bin/perl

use Getopt::Long 'GetOptions';
my $rfile = "";
my $wfile = "";
my $pkt_gap = 0;
my $flit_gap = 0;
my $help = 0;
my @output;
#
# Options
#
GetOptions(
	'read_file=s'  => \$rfile,
	'write_file=s' => \$wfile,
	'pkt_gap=i'    => \$pkt_gap,
	'flit_gap=i'   => \$flit_gap,
	'help'         => \$help
);

sub usage {
	print "usage: ./pcap2rom.pl -r <input file> -w <output file> -p <pkt gap> -f <flit gap> -h\n";
	print "\t--read_file=<input file>\n";
	print "\t--write_file=<write file>\n";
	print "\t--pkt_gap=<clock cycles>\n";
	print "\t--flit_gap=<clock cycles>\n";
	print "\t--help\tView usages.\n\n";
}

sub padding {
	my ($length) = @_;
	my $str = "";

	for (my $i = 0; $i < $length; $i++) {
		$str = "$str"."0";
	}

	return $str;
}

sub tkeep {
	my ($length) = @_;
	my $str = "";
	my $len;
	my $cnt = 0;
	for ($len = $length; $len >= 4; $len = $len - 4) {
		$str = "f"."$str";
		$cnt++;
	}
	if ($len eq 3) {
		$str = "7"."$str";
		$cnt++;
	} elsif ($len eq 2) {
		$str = "3"."$str";
		$cnt++;
	} elsif ($len eq 1) {
		$str = "1"."$str";
		$cnt++;
	}
	
	for (my $j = $cnt; $j < 32/4; $j++) {
		$str = "0"."$str";
	}

	return $str;
}

sub tuser {
	my ($length) = @_;
	my $re = sprintf("%04x",  $length);
	my $str = "0000000000000000000000000000"."$re";

	return $str;
}

sub inter_gap {
	my ($gap) = @_;
	my $tmpgap = "0000000000000000000000000000000000000000000000000000000000000000_00000000_00000000000000000000000000000000_0_0\n";
	
	for (my $i = 0; $i < $gap; $i++) {
		push (@output, $tmpgap);
	}
}

sub tlast {
	my ($length, $len, $cnt) = @_;
	$cnt = ($cnt - 1) / 2;
	my $str = "";
	my $sub = 0;
	if ($cnt > 0) {
		$sub = $length - (($cnt * 32) + $len);
	} else {
		$sub = $length - $len;
	}
	if ($sub <= 0) {
		$str = "1";
	} else {
		$str = "0";
	}

	return $str;
}

if ($rfile eq "" or $help eq 1) {
	usage();
	exit(-1);
}

my @pcap;
chop(@pcap = `tshark -r $rfile -x`);
my @size;
chop(@size = `tshark -r $rfile -T fields -e frame.len`);
my $pkt_cnt = 0;
my $tmpline0;
my $tmpline1;
my $line_cnt = 0;
my $length = 0;
# Main
#push (@output, "# Packet["."$pkt_cnt"."]\n");
my $ff = "";
$ff = shift(@size);
foreach my $line (@pcap){
	my @strlist = split(/ /, $line);
	my $i;
	if ($line eq '') {
		$length = length("$tmpline1");
		if ($length < 32) {
			my $outp = padding(64-$length)."$tmpline1"."_".tkeep($length/2)."_".tuser($ff)."_1_".tlast($ff, $length/2, $line_cnt)."\n";
			push (@output, $outp);
		}
		$pkt_cnt++;
		$ff = shift(@size);
		inter_gap($pkt_gap);
		#push (@output, "# Packet["."$pkt_cnt"."]\n");
		$line_cnt = 0;
	} else {
		for ($i = 17; $i > 0; $i = $i - 1) {
			$tmpline0 = "$tmpline0$strlist[$i]";
		}
		if ($line_cnt % 2 eq 0) {
			$tmpline1 = $tmpline0;
		} else {
			$length = length("$tmpline0$tmpline1");
			my $outp = padding(64-$length)."$tmpline0$tmpline1"."_".tkeep($length/2)."_".tuser($ff)."_1_".tlast($ff, $length/2, $line_cnt)."\n";
			push (@output, $outp);
		}
		$tmpline0 = "";
		inter_gap($flit_gap);
		$line_cnt++;
	}
}

if ($wfile eq "") {
	foreach my $lline (@output) {
		print $lline;
	}
} else {
	open(DATAFILE, ">", $wfile) or die("Error:$!");
	foreach my $lline (@output) {
		print DATAFILE $lline;
	}
}

