/* srv.h
 * Copyright (C) 2003, 2004 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SRV_H_
#define _SRV_H_

#ifdef USE_DNS_SRV
#ifdef _WIN32
#include <windows.h>
#else
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif /* !_WIN32 */
#endif /* USE_DNS_SRV */
#include "types.h"

#ifndef MAXDNAME
#define MAXDNAME 1025
#endif

struct srventry
{
  u16 priority;
  u16 weight;
  u16 port;
  int run_count;
  char target[MAXDNAME];
};

int getsrv(const char *name,struct srventry **list);

#endif /* !_SRV_H_ */
