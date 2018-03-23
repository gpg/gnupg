/* shareddefs.h - Constants and helpers useful for all modules
 * Copyright (C) 2013 Free Software Foundation, Inc.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_SHAREDDEFS_H
#define GNUPG_COMMON_SHAREDDEFS_H

/* Values for the pinentry mode.  */
typedef enum
  {
    PINENTRY_MODE_ASK = 0, /* Ask via pinentry (default).  */
    PINENTRY_MODE_CANCEL,  /* Always return a cancel error.  */
    PINENTRY_MODE_ERROR,   /* Return error code for no pinentry.  */
    PINENTRY_MODE_LOOPBACK /* Use an inquiry to get the value.    */
  }
pinentry_mode_t;


/* Values for the request origin.  */
typedef enum
  {
    REQUEST_ORIGIN_LOCAL = 0,
    REQUEST_ORIGIN_REMOTE,
    REQUEST_ORIGIN_BROWSER
  }
request_origin_t;


/*-- agent-opt.c --*/
int parse_pinentry_mode (const char *value);
const char *str_pinentry_mode (pinentry_mode_t mode);

int parse_request_origin (const char *value);
const char *str_request_origin (request_origin_t mode);



#endif /*GNUPG_COMMON_SHAREDDEFS_H*/
