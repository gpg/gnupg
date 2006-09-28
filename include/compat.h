#ifndef _COMPAT_H_
#define _COMPAT_H_

/* Note this isn't identical to a C locale isspace() without \f and
   \v, but works for the purposes used here. */
#define ascii_isspace(a) ((a)==' ' || (a)=='\n' || (a)=='\r' || (a)=='\t')

int hextobyte( const char *s );

#ifndef HAVE_STRSEP
char *strsep (char **stringp, const char *delim);
#endif

#endif /* !_COMPAT_H_ */
