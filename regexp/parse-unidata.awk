#
# parse-unidata.awk - generate a table (unicode_case_mapping_upper)
#
# Copyright (C) 2020 g10 Code GmbH
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.
#

# Parse the unicode data from:
#   https://www.unicode.org/Public/UCD/latest/ucd/UnicodeData.txt
# to generate case mapping table

BEGIN {
    print("/* Generated from UnicodeData.txt */")
    print("")
    print("static const struct casemap unicode_case_mapping_upper[] = {")
    FS = ";"
    count = 0
}

{
    code = int("0x" $1)
    name = $2
    class = $3
    upper = $13
    lower = $14
    title = $15

    if (code <= 127) {
	next
    }
    if (code > 65535) {
	next
    }
    if ($3 !~ /^L.*/) {
	next
    }
    if (upper != "") {
	printf("\t{ 0x" tolower($1) ", 0x" tolower(upper) " },")
	count++
	if ((count % 4) == 0) {
	    print("")
	}
    }
}

END {
    print("\n};")
}
