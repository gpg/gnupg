# Parse the unicode data from:
#   https://unicode.org/Public/UNIDATA/UnicodeData.txt
# to generate case mapping table

BEGIN {
    print("/* Generated from UnicodeData.txt */")
    print("")
    print("static const struct casemap unicode_case_mapping_upper[] = {")
    FS = ";"
    count = 0
}

{
    code = strtonum(("0x" $1))
    name = $2
    class = $3
    upper = $13
    lower = $14
    title = $15

    if (code <= 0x7f) {
	next
    }
    if (code > 0xffff) {
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
