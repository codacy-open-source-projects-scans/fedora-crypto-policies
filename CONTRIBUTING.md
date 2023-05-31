# Information about our contribution rules and coding style

 Anyone is welcome to contribute to crypto-policies. Be prepared
to defend and justify your enhancements, and get through few rounds
of changes. 

We try to stick to the following rules, so when contributing please
try to follow them too.

# Git commits:

Note that when contributing code you will need to assert that the contribution is
in accordance to the "Developer's Certificate of Origin" as found in the 
file [DCO.txt](doc/DCO.txt).

To indicate that, make sure that your contributions (patches or merge requests),
contain a "Signed-off-by" line, with your real name and e-mail address. 

# Test suite:

   New functionality should be accompanied by a test case which verifies
the correctness of crypto policies' operation on successful use of the new
functionality, as well as on fail cases. The test suite is run with "make check"
on target systems as well as on the CI system.

The tests can also be done at run-time, i.e., with the test_temp_policy()
function provided by back-ends, or on CI/target systems only (via check rule
in Makefile). The former implies the latter.

Any additional tools required for that testing should be listed in the CI
configuration (.gitlab-ci.yml).

