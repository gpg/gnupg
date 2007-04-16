#ifndef _COMPAT_H_
#define _COMPAT_H_

/* Note this isn't identical to a C locale isspace() without \f and
   \v, but works for the purposes used here. */
#define ascii_isspace(a) ((a)==' ' || (a)=='\n' || (a)=='\r' || (a)=='\t')

int hextobyte( const char *s );
int ascii_toupper (int c);
int ascii_tolower (int c);
int ascii_strcasecmp( const char *a, const char *b );
int ascii_strncasecmp( const char *a, const char *b, size_t n);

#ifndef HAVE_STRSEP
char *strsep (char **stringp, const char *delim);
#endif

#endif /* !_COMPAT_H_ */
