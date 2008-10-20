/* w32-afunix.c - AF_UNIX emulation for Windows (Client only).
 * Copyright (C) 2004, 2006 g10 Code GmbH
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Use of this code is preprecated - you better use the sockt wrappers
   from libassuan. */

#ifdef _WIN32
#include <stdio.h>
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <io.h>
#include <errno.h>

#include "w32-afunix.h"



/* The buffer for NONCE needs to be at least 16 bytes.  Returns 0 on
   success. */
static int
read_port_and_nonce (const char *fname, unsigned short *port, char *nonce)
{
  FILE *fp;
  char buffer[50], *p;
  size_t nread;
  int aval;

  fp = fopen (fname, "rb");
  if (!fp)
    return -1;
  nread = fread (buffer, 1, sizeof buffer - 1, fp);
  fclose (fp);
  if (!nread)
    {
      errno = ENOFILE;
      return -1;
    }
  buffer[nread] = 0;
  aval = atoi (buffer);
  if (aval < 1 || aval > 65535)
    {
      errno = EINVAL;
      return -1;
    }
  *port = (unsigned int)aval;
  for (p=buffer; nread && *p != '\n'; p++, nread--)
    ;
  if (*p != '\n' || nread != 17)
    {
      errno = EINVAL;
      return -1;
    }
  p++; nread--;
  memcpy (nonce, p, 16);
  return 0;
}



int
_w32_close (int fd)
{
  int rc = closesocket (fd);
  if (rc && WSAGetLastError () == WSAENOTSOCK)
      rc = close (fd);
  return rc;
}


int
_w32_sock_new (int domain, int type, int proto)
{
  if (domain == AF_UNIX || domain == AF_LOCAL)
    domain = AF_INET;
  return socket (domain, type, proto);
}


int
_w32_sock_connect (int sockfd, struct sockaddr *addr, int addrlen)
{
  struct sockaddr_in myaddr;
  struct sockaddr_un *unaddr;
  unsigned short port;
  char nonce[16];
  int ret;

  (void)addrlen;
      
  unaddr = (struct sockaddr_un *)addr;
  if (read_port_and_nonce (unaddr->sun_path, &port, nonce))
    return -1;
      
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons (port); 
  myaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  
  /* Set return values.  */
  unaddr->sun_family = myaddr.sin_family;
  unaddr->sun_port = myaddr.sin_port;
  unaddr->sun_addr.s_addr = myaddr.sin_addr.s_addr;
  
  ret = connect (sockfd, (struct sockaddr *)&myaddr, sizeof myaddr);
  if (!ret)
    {
      /* Send the nonce. */
      ret = send (sockfd, nonce, 16, 0);
      if (ret >= 0 && ret != 16)
        {
          errno = EIO;
          ret = -1;
        }
    }
  return ret;
}


#endif /*_WIN32*/
