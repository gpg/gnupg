/* gc-opt-flags.h - gpgconf constants used by the backends.
 * Copyright (C) 2004, 2007  Free Software Foundation, Inc.
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.
 */

#ifndef GNUPG_GC_OPT_FLAGS_H
#define GNUPG_GC_OPT_FLAGS_H

/* Public option flags.  YOU MUST NOT CHANGE THE NUMBERS OF THE
   EXISTING FLAGS, AS THEY ARE PART OF THE EXTERNAL INTERFACE.  See
   gnupg/tools/gpgconf-comp.c for details.  */

#define GC_OPT_FLAG_NONE	0UL

/* The DEFAULT flag for an option indicates that the option has a
   default value.  */
#define GC_OPT_FLAG_DEFAULT	(1UL << 4)

/* The DEF_DESC flag for an option indicates that the option has a
   default, which is described by the value of the default field.  */
#define GC_OPT_FLAG_DEF_DESC	(1UL << 5)

/* The NO_ARG_DESC flag for an option indicates that the argument has
   a default, which is described by the value of the ARGDEF field.  */
#define GC_OPT_FLAG_NO_ARG_DESC	(1UL << 6)

/* The NO_CHANGE flag for an option indicates that the user should not
   be allowed to change this option using the standard gpgconf method.
   Frontends using gpgconf should grey out such options, so that only
   the current value is displayed.  */
#define GC_OPT_FLAG_NO_CHANGE   (1UL <<7)


#endif /*GNUPG_GC_OPT_FLAGS_H*/
