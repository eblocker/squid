#!/bin/sh
# touches all autotools files to prevent needing regeneration them after
# git checkout 
find . -name configure.ac -o -name aclocal.m4 -o -name config.h.in -o -name Makefile.am -o -name Makefile.in -o -name configure | xargs touch
