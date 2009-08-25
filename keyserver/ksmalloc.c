/* ksmalloc.c - Walloc wrapper
 * Copyright (C) 2009 Free Software Foundation, Inc.
 *
 * The origin of this code is GnuPG.
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdlib.h>

/* A wrapper around malloc because libcompat requires it.  */
void *
xtrymalloc (size_t n)
{
  return malloc (n);
}


/* A wrapper around free becuase we are used to it.  */
void
xfree (void *p)
{
  if (p)
    free (p);
}

