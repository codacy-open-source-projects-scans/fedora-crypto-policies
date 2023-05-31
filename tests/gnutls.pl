#!/usr/bin/perl

my $TMPFILE="out-gnutls.tmp";

if ($ENV{OLD_GNUTLS} eq '1') {
    print "Not checking the GnuTLS configuration\n";
    exit 0
}

print "Checking the GnuTLS configuration\n";

my $dir = 'tests/outputs';

opendir(DIR, $dir) or die $!;

my @gnutlspolicies
    = grep {
        /gnutls/          # has gnutls in name
        && -f "$dir/$_"   # and is a file
    } readdir(DIR);

foreach my $policyfile (@gnutlspolicies) {
	my $policy = $policyfile;
	$policy =~ s/-[^-]+$//;

	print "Checking policy $policy\n";
	next if $policy eq 'GOST-ONLY';

	system("GNUTLS_DEBUG_LEVEL=3 GNUTLS_SYSTEM_PRIORITY_FILE=$dir/$policyfile GNUTLS_SYSTEM_PRIORITY_FAIL_ON_INVALID=1 gnutls-cli -l >$TMPFILE 2>&1");
	if ($? == 0 && $policy eq 'EMPTY') {
		print "Error in gnutls empty policy ($policy)\n";
		system("cat $TMPFILE 1>&2");
		exit 1;
	} elsif ($? != 0 && $policy ne 'EMPTY') {
		print "Error in gnutls policy for $policy\n";
		system("cat $TMPFILE 1>&2");
		exit 1;
	}
	unlink($TMPFILE);
}

exit 0;
