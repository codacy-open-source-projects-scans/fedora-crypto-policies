#!/usr/bin/perl

use strict;
use warnings;

my $libdir = "./back-ends/";
use lib "back-ends/";

use profiles::common;

my @modules = ("gnutls", "openssl", "opensslcnf", "bind", "java", "krb5", "nss",
	       "openssh", "opensshserver", "libreswan", "libssh", "sequoia",
	       "rpm-sequoia", "openssl_fips");
my ($mod, $contents, $profile);
my @reloadcmds = ();

print "Verifying the contents of individual profile configurations\n";

foreach $mod (@modules) {
	require "$libdir/$mod.pl";
	my $tmp = '';

	mkdir("tests/outputs");
	foreach $profile (@profiles::common::policies) {
		$tmp = generate_temp_policy($profile, 0, $libdir, \@reloadcmds);
		$contents = '';

		if (open my $fh, '<', "tests/outputs/$profile-$mod.txt") {
			$/ = undef;
			$contents = <$fh>;
			close $fh;
			$/ = "\n";

			if ($tmp ne $contents) {
				print "\nError in the contents of $profile-$mod.txt\n";
				print "If the changes in the output policies are expected run make 'reset-outputs' and verify the result\n";
				exit 1;
			}
		} else {
			open my $fh, '>', "tests/outputs/$profile-$mod.txt";
			print $fh $tmp;
			close $fh;
		}

		test_temp_policy($profile, 0, $tmp) if ($profile ne 'EMPTY');
	}
}

exit 0;
