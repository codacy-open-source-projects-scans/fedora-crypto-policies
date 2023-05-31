#!/usr/bin/perl

use File::pushd;

my $TMPFILE="out-java.$$.tmp";

print "Checking the Java configuration\n";

print STDERR "Java ciphersuites per policy\n";

system("javac tests/java/CipherList.java 1>&2");
if ($? != 0) {
	exit 77;
}

my $dir = 'tests/outputs';

opendir(DIR, $dir) or die $!;

my @javapolicies
    = grep {
        /java\.txt/       # ends in java.txt
        && -f "$dir/$_"   # and is a file
    } readdir(DIR);


foreach my $policyfile (@javapolicies) {
	my $policy = $policyfile;
	$policy =~ s/-[^-]+$//;

	print "Checking policy $policy\n";

	{
		my $pushdir = pushd('tests/java');

		#catch errors in this script now, since the -D option will ignore
		#missing files.
		if (!-e "../../$dir/$policyfile") {
			print "Policy file ../../$dir/$policyfile missing\n";
			exit 1;
		}
		system("java -Djava.security.disableSystemPropertiesFile=true -Djava.security.properties=\"../../$dir/$policyfile\" CipherList >../../$TMPFILE");
	}

	my $lines=`cat $TMPFILE|wc -l`;
	if ("$policy" eq "EMPTY" or "$policy" eq "GOST-ONLY") {
		if ($lines >= 2) { # we allow the SCSV
			print "Empty policy has ciphersuites!\n";
			exit 1;
		}
	} else {
		system("grep \"TLS_EMPTY_RENEGOTIATION_INFO_SCSV\" $TMPFILE >/dev/null 2>&1");
		
		if ($? != 0) {
			print "Could not find TLS_EMPTY_RENEGOTIATION_INFO_SCSV in $policy\n";
			system("cat $TMPFILE");
			exit 1;
		}

		if ($lines <= 1) {
			print "Policy $policy has no ciphersuites!\n";
			system("cat $TMPFILE");
			exit 1;
		}
	}
	system("cat $TMPFILE 1>&2");
	unlink($TMPFILE);
}

exit 0;
