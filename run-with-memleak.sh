#!/bin/sh
#  Memleak: Detects memory leaks in C or C++ programs
#  Copyright (C) 2010 Ravi Sankar Guntur <ravi.g@samsung.com>
#  Copyright (C) 2010 Prateek Mathur <prateek.m@samsung.com>
  
#  Memleak is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as
#  published by the Free Software Foundation, either version 3
#  of the License, or any later version.
 
#  Memleak is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.

#  You should have received a copy of the GNU General Public License
#  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
#  version: 0.3

usage () {
	echo " Usage: run-with-memleak <--full-mode | --scenario-mode> <program-binary>" 
}

if [ "$#" -ne 2 ]
then
	usage
	exit
fi
if [ "$1" = "--scenario-mode" ] || [ "$1" = "--full-mode" ]
then
	SCENARIO="$1"
	echo $SCENARIO
	export SCENARIO
	export G_SLICE=always-malloc
	LD_PRELOAD=/usr/lib/libmemleak.so $2
else
	usage
	exit
fi
