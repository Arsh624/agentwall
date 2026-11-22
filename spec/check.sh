#!/bin/sh
# Model-check the TLA+ specs. Each real model must pass; each broken variant must
# fail with the named invariant, which proves the check can catch that bug.
# Usage: spec/check.sh path/to/tla2tools.jar
set -eu
jar=$1
cd "$(dirname "$0")"
status=0

tlc() { # tlc <cfg> <module>
	java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -nowarning -workers auto \
		-metadir "${TMPDIR:-/tmp}/tlc-$1-$$" -config "$1" "$2" 2>&1
}

pass() { # pass <cfg> <module>
	if out=$(tlc "$1" "$2") && echo "$out" | grep -q "No error has been found"; then
		echo "ok    $2 with $1: holds over $(echo "$out" | grep -o "[0-9]* distinct states" | tail -1)"
	else
		echo "FAIL  $2 with $1 must hold:"; echo "$out"; status=1
	fi
}

fail() { # fail <cfg> <module> <invariant>
	if tlc "$1" "$2" | grep -q "Invariant $3 is violated"; then
		echo "ok    $2 with $1: TLC finds the $3 violation, as it must"
	else
		echo "FAIL  $2 with $1: TLC no longer catches the broken design ($3)"; status=1
	fi
}

pass Trifecta.cfg Trifecta.tla
fail TrifectaBroken.cfg Trifecta.tla NoLeak
pass Ask.cfg Ask.tla
fail AskBroken.cfg Ask.tla OneReply
exit $status
