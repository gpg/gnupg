/* t-dns-cert.c - Module test for dns-stuff.c
 * Copyright (C) 2011 Free Software Foundation, Inc.
 * Copyright (C) 2011, 2015 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>


#include "../common/util.h"
#include "dns-stuff.h"

#define PGM "t-dns-stuff"

static int verbose;
static int debug;


static void
init_sockets (void)
{
#ifdef HAVE_W32_SYSTEM
  WSADATA wsadat;

  WSAStartup (0x202, &wsadat);
#endif
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpg_error_t err;
  int any_options = 0;
  int opt_tor = 0;
  int opt_cert = 0;
  int opt_srv = 0;
  int opt_bracket = 0;
  int opt_cname = 0;
  char const *name = NULL;

  gpgrt_init ();
  log_set_prefix (PGM, GPGRT_LOG_WITH_PREFIX);
  if (argc)
    { argc--; argv++; }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " [HOST]\n"
                 "Options:\n"
                 "  --verbose           print timings etc.\n"
                 "  --debug             flyswatter\n"
                 "  --standard-resolver use the system's resolver\n"
                 "  --use-tor           use Tor\n"
                 "  --new-circuit       use a new Tor circuit\n"
                 "  --bracket           enclose v6 addresses in brackets\n"
                 "  --cert              lookup a CERT RR\n"
                 "  --srv               lookup a SRV RR\n"
                 "  --cname             lookup a CNAME RR\n"
                 "  --timeout SECONDS   timeout after SECONDS\n"
                 , stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--use-tor"))
        {
          opt_tor = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--standard-resolver"))
        {
          enable_standard_resolver (1);
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--recursive-resolver"))
        {
          enable_recursive_resolver (1);
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--bracket"))
        {
          opt_bracket = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--cert"))
        {
          any_options = opt_cert = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--srv"))
        {
          any_options = opt_srv = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--cname"))
        {
          any_options = opt_cname = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--timeout"))
        {
          argc--; argv++;
          if (argc)
            {
              set_dns_timeout (atoi (*argv));
              argc--; argv++;
            }
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (!argc && !any_options)
    {
      opt_cert = 1;
      name = "simon.josefsson.org";
    }
  else if (argc == 1)
    name = *argv;
  else
    {
      fprintf (stderr, PGM ": none or too many host names given\n");
      exit (1);
    }

  set_dns_verbose (verbose, debug);
  init_sockets ();

  if (opt_tor)
    enable_dns_tormode (0);

  if (opt_cert)
    {
      unsigned char *fpr;
      size_t fpr_len;
      char *url;
      void *key;
      size_t keylen;

      if (verbose || any_options)
        printf ("CERT lookup on '%s'\n", name);

      err = get_dns_cert (NULL, name, DNS_CERTTYPE_ANY, &key, &keylen,
                          &fpr, &fpr_len, &url);
      if (err)
        printf ("get_dns_cert failed: %s <%s>\n",
                gpg_strerror (err), gpg_strsource (err));
      else if (key)
        {
          if (verbose || any_options)
            printf ("Key found (%u bytes)\n", (unsigned int)keylen);
        }
      else
        {
          if (fpr)
            {
              int i;

              printf ("Fingerprint found (%d bytes): ", (int)fpr_len);
              for (i = 0; i < fpr_len; i++)
                printf ("%02X", fpr[i]);
              putchar ('\n');
            }
          else
            printf ("No fingerprint found\n");

          if (url)
            printf ("URL found: %s\n", url);
          else
            printf ("No URL found\n");

        }

      xfree (key);
      xfree (fpr);
      xfree (url);
    }
  else if (opt_cname)
    {
      char *cname;

      printf ("CNAME lookup on '%s'\n", name);
      err = get_dns_cname (NULL, name, &cname);
      if (err)
        printf ("get_dns_cname failed: %s <%s>\n",
                gpg_strerror (err), gpg_strsource (err));
      else
        {
          printf ("CNAME found: '%s'\n", cname);
        }
      xfree (cname);
    }
  else if (opt_srv)
    {
      struct srventry *srv;
      unsigned int count;
      int i;

      err = get_dns_srv (NULL, name? name : "_hkp._tcp.wwwkeys.pgp.net",
                         NULL, NULL, &srv, &count);
      if (err)
        printf ("get_dns_srv failed: %s <%s>\n",
                gpg_strerror (err), gpg_strsource (err));
      else
        {
          printf ("count=%u\n",count);
          for (i=0; i < count; i++)
            {
              printf("priority=%-8hu  ",srv[i].priority);
              printf("weight=%-8hu  ",srv[i].weight);
              printf("port=%-5hu  ",srv[i].port);
              printf("target=%s\n",srv[i].target);
            }

          xfree(srv);
        }
    }
  else /* Standard lookup.  */
    {
      char *cname;
      dns_addrinfo_t aibuf, ai;
      char *host;

      printf ("Lookup on '%s'\n", name);

      err = resolve_dns_name (NULL, name, 0, 0, SOCK_STREAM, &aibuf, &cname);
      if (err)
        {
          fprintf (stderr, PGM": resolving '%s' failed: %s\n",
                   name, gpg_strerror (err));
          exit (1);
        }

      if (cname)
        printf ("cname: %s\n", cname);
      for (ai = aibuf; ai; ai = ai->next)
        {
          printf ("%s %3d %3d   ",
                  ai->family == AF_INET6? "inet6" :
                  ai->family == AF_INET?  "inet4" : "?    ",
                  ai->socktype, ai->protocol);

          err = resolve_dns_addr (NULL, ai->addr, ai->addrlen,
                                  (DNS_NUMERICHOST
                                   | (opt_bracket? DNS_WITHBRACKET:0)),
                                  &host);
          if (err)
            printf ("[resolve_dns_addr failed: %s]", gpg_strerror (err));
          else
            {
              printf ("%s", host);
              xfree (host);
            }

          err = resolve_dns_addr (NULL, ai->addr, ai->addrlen,
                                  (opt_bracket? DNS_WITHBRACKET:0),
                                  &host);
          if (err)
            printf ("  [resolve_dns_addr failed (2): %s]", gpg_strerror (err));
          else
            {
              if (!is_ip_address (host))
                printf ("  (%s)", host);
              xfree (host);
            }
          putchar ('\n');
        }
      xfree (cname);
      free_dns_addrinfo (aibuf);
    }

  reload_dns_stuff (1); /* Release objects.  */

  return 0;
}
