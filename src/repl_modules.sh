#!/bin/sh
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

echo "/* automatically generated by $0 $*"
echo " * do not edit"
echo " */"
echo "#include \"squid.h\""
echo "#include \"Store.h\""
echo ""
for module in "$@"; do
   echo "extern REMOVALPOLICYCREATE createRemovalPolicy_${module};"
done
echo "void storeReplSetup(void)"
echo "{"
for module in "$@"; do
   echo "	storeReplAdd(\"$module\", createRemovalPolicy_${module});"
done
echo "}"
