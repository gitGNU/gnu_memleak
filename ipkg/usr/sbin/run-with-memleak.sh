#!/bin/sh
if [ "$#" -ne 2 ]
then
	echo " Usage: run-with-memleak --full-mode/--scenario-mode program-binary" 
	echo "  --scenario-mode -Scenario based 	--full-mode -Without scenario based"
	exit
fi
if [ "$1" = "--scenario-mode" ] || [ "$1" = "--full-mode" ]
then
	SCENARIO="$1"
	echo $SCENARIO
	export SCENARIO
	LD_PRELOAD=/usr/lib/libmemleak.so $2
else
	echo "Wrong Usage"
	exit
fi
