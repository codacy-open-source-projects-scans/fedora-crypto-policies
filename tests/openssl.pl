#!/usr/bin/perl

my $TMPFILE="out-openssl.tmp";

print "Checking the OpenSSL configuration\n";

my $dir = 'tests/outputs';

opendir(DIR, $dir) or die $!;

my @opensslpolicies
    = grep {
        /openssl\./         # has openssl. in name
        && -f "$dir/$_"   # and is a file
    } readdir(DIR);

foreach my $policyfile (@opensslpolicies) {
	my $policy = $policyfile;
	$policy =~ s/-[^-]+$//;

	print "Checking policy $policy\n";

	my $tmp = do {
		local $/ = undef;
		open my $fh, "<", $dir.'/'.$policyfile
			or die "could not open $file: $!";
		<$fh>;
	};

	my %skip_test = map {$_ => 1} ("EMPTY", "GOST-ONLY");

	system("openssl ciphers $tmp >$TMPFILE 2>&1") unless exists $skip_test{$policy};
	if ($? != 0) {
		print "Error in OpenSSL policy for $policy\n";

		print STDERR "openssl ciphers error:\n";
		system("cat $TMPFILE 1>&2");
		print STDERR "ciphers: $tmp\n";
		exit 1;
	}
	unlink($TMPFILE);
}

exit 0;
