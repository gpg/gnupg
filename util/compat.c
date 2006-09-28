int
hextobyte (const char *s)
{
  int c;

  if ( *s >= '0' && *s <= '9' )
    c = 16 * (*s - '0');
  else if ( *s >= 'A' && *s <= 'F' )
    c = 16 * (10 + *s - 'A');
  else if ( *s >= 'a' && *s <= 'f' )
    c = 16 * (10 + *s - 'a');
  else
    return -1;
  s++;
  if ( *s >= '0' && *s <= '9' )
    c += *s - '0';
  else if ( *s >= 'A' && *s <= 'F' )
    c += 10 + *s - 'A';
  else if ( *s >= 'a' && *s <= 'f' )
    c += 10 + *s - 'a';
  else
    return -1;
  return c;
}
