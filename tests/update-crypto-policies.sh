#!/bin/sh

set -e

umask 022

: ${top_srcdir=..}

progname="$0"
script="$top_srcdir/python/update-crypto-policies.py"
testdir=`mktemp -d -t "update-crypto-policies.XXXXXXXX"`
trap 'rm -rf $testdir' 0

profile_dir="$testdir/profile"
mkdir "$profile_dir"

base_dir="$testdir/base"
mkdir "$base_dir"
mkdir "$base_dir/local.d"

(cd "$top_srcdir" ; python/build-crypto-policies.py --reloadcmds policies "$profile_dir" 2>/dev/null)
cp -pr "$top_srcdir/policies" "$profile_dir"
echo DEFAULT > "$profile_dir/default-config"
echo DEFAULT > "$base_dir/config"

check_symlink() {
	for profile_file in "$profile_dir"/"$1"/*.txt; do
		profile_base=$(basename "$profile_file")
		config_file="$base_dir/back-ends/${profile_base%%.txt}.config"
		test -h "$config_file" || {
			echo "$progname: $config_file is not a symlink"
			exit 1
		}
		target_file=$(readlink "$config_file")
		test "$target_file" = "$profile_file" || {
			echo "$progname: $target_file is not a symlink to $profile_file"
			exit 1
		}
	done
}

echo "$0: checking if default profile is properly selected"
profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-reload
check_symlink DEFAULT
echo

check_compare() {
	for profile_file in "$profile_dir"/"$1"/*.txt; do
		profile_base=$(basename "$profile_file")
		config_file="$base_dir/back-ends/${profile_base%%.txt}.config"
		test ! -h "$config_file" || {
			echo "$progname: $config_file is a symlink"
			exit 1
		}
		cmp "$config_file" "$profile_file" || exit 1
	done
}

echo "$0: checking if current policy dump is equal to the original default profile"
mkdir -p "$base_dir/policies"
grep -q "^# Policy DEFAULT dump\$" "$base_dir/state/CURRENT.pol" || {
	echo "$progname: CURRENT.pol does not contain correct policy name"
	exit 1
}
cp "$base_dir/state/CURRENT.pol" "$base_dir/policies"
profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-reload --set CURRENT
check_compare DEFAULT
echo

echo "$0: checking if switching to other profile works"
profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-reload --set LEGACY
check_symlink LEGACY

check_local() {
	profile_file="$profile_dir"/"$1"/"$2".txt
	config_file="$base_dir/back-ends/$2.config"
	test -f "$config_file" || {
		echo "$progname: $config_file is not a regular file"
		exit 1
	}
	cat "$profile_file" "$base_dir/local.d"/"$2"-*.config > "$testdir/merged"
	diff -u "$config_file" "$testdir/merged" || {
		echo "$progname: $config_file is not properly merged"
		exit 1
	}
}
echo

echo "$0: checking if local.d works"

cat > "$base_dir/local.d/nss-foo.config" <<EOF
name=foo
library=foo.so
EOF

cat > "$base_dir/local.d/nss-bar.config" <<EOF
name=bar
library=bar.so
EOF

profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-reload --set DEFAULT
check_local DEFAULT nss

echo

echo "$0: checking if --check works (test 1)"
profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-reload --check

cat >> "$base_dir/back-ends/nss.config" <<EOF
# a change
EOF

if profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-reload --check ; then
	echo "--check didn't detect a modification"
	exit 1
else
	echo "--check works as expected"
fi

echo

echo "$0: checking if --check works (test 2)"
# regenerate "$base_dir/back-ends/nss.config"
profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-reload --set DEFAULT
# test that regen works
profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-reload --check

# convert the symlink to a regular file and then modify it
cat "$base_dir/back-ends/bind.config" > "$base_dir/back-ends/bind.config.new"
rm -f "$base_dir/back-ends/bind.config"
mv "$base_dir/back-ends/bind.config.new" "$base_dir/back-ends/bind.config"
cat >> "$base_dir/back-ends/bind.config" <<EOF
# a change
EOF

if profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-reload --check ; then
	echo "--check didn't detect a modification"
	exit 1
else
	echo "--check works as expected"
fi
