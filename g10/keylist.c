/* keylist.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003
 *                                             Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "keydb.h"
#include "memory.h"
#include "photoid.h"
#include "util.h"
#include "ttyio.h"
#include "trustdb.h"
#include "main.h"
#include "i18n.h"
#include "status.h"

static void list_all(int);
static void list_one( STRLIST names, int secret);

struct sig_stats
{
  int inv_sigs;
  int no_key;
  int oth_err;
};

static FILE *attrib_fp=NULL;

/****************
 * List the keys
 * If list is NULL, all available keys are listed
 */
void
public_key_list( STRLIST list )
{
  if(opt.with_colons)
    {
      byte trust_model,marginals,completes,cert_depth;
      ulong created,nextcheck;

      read_trust_options(&trust_model,&created,&nextcheck,
			 &marginals,&completes,&cert_depth);

      printf("tru:");

      if(nextcheck && nextcheck <= make_timestamp())
	printf("o");
      if(trust_model!=opt.trust_model)
	printf("t");
      if(opt.trust_model==TM_PGP || opt.trust_model==TM_CLASSIC)
	{
	  if(marginals!=opt.marginals_needed)
	    printf("m");
	  if(completes!=opt.completes_needed)
	    printf("c");
	  if(cert_depth!=opt.max_cert_depth)
	    printf("d");
	}

      printf(":%d:%lu:%lu",trust_model,created,nextcheck);

      /* Only show marginals, completes, and cert_depth in the classic
	 or PGP trust models since they are not meaningful
	 otherwise. */

      if(trust_model==TM_PGP || trust_model==TM_CLASSIC)
	printf(":%d:%d:%d",marginals,completes,cert_depth);

      printf("\n");
    }

  if( !list )
    list_all(0);
  else
    list_one( list, 0 );
}

void
secret_key_list( STRLIST list )
{
    if( !list )
	list_all(1);
    else  /* List by user id */
	list_one( list, 1 );
}

void
print_seckey_info (PKT_secret_key *sk)
{
    u32 sk_keyid[2];
    size_t n;
    char *p;

    keyid_from_sk (sk, sk_keyid);
    tty_printf ("\nsec  %4u%c/%08lX %s   ",
                nbits_from_sk (sk),
                pubkey_letter (sk->pubkey_algo),
                (ulong)sk_keyid[1], datestr_from_sk (sk));
    
    p = get_user_id (sk_keyid, &n);
    tty_print_utf8_string (p, n);
    m_free (p);

    tty_printf ("\n");   
}

void
print_pubkey_info (PKT_public_key *pk)
{
  u32 pk_keyid[2];
  size_t n;
  char *p;

  keyid_from_pk (pk, pk_keyid);
  tty_printf ("\npub  %4u%c/%08lX %s   ",
              nbits_from_pk (pk),
              pubkey_letter (pk->pubkey_algo),
              (ulong)pk_keyid[1], datestr_from_pk (pk));


  p = get_user_id (pk_keyid, &n);
  tty_print_utf8_string (p, n);
  m_free (p);
  
  tty_printf ("\n\n"); 
}

/*
  mode=0 for stdout.
  mode=1 for log_info + status messages
  mode=2 for status messages only
*/

void
show_policy_url(PKT_signature *sig,int indent,int mode)
{
  const byte *p;
  size_t len;
  int seq=0,crit;
  FILE *fp=mode?log_stream():stdout;

  while((p=enum_sig_subpkt(sig->hashed,SIGSUBPKT_POLICY,&len,&seq,&crit)))
    {
      if(mode!=2)
	{
	  int i;
	  char *str;

	  for(i=0;i<indent;i++)
	    putchar(' ');

	  if(crit)
	    str=_("Critical signature policy: ");
	  else
	    str=_("Signature policy: ");
	  if(mode)
	    log_info("%s",str);
	  else
	    printf("%s",str);
	  print_utf8_string(fp,p,len);
	  fprintf(fp,"\n");
	}

      if(mode)
	write_status_buffer ( STATUS_POLICY_URL, p, len, 0 );
    }
}

/*
  mode=0 for stdout.
  mode=1 for log_info + status messages
  mode=2 for status messages only
*/
/* TODO: use this */
void
show_keyserver_url(PKT_signature *sig,int indent,int mode)
{
  const byte *p;
  size_t len;
  int seq=0,crit;
  FILE *fp=mode?log_stream():stdout;

  while((p=enum_sig_subpkt(sig->hashed,SIGSUBPKT_PREF_KS,&len,&seq,&crit)))
    {
      if(mode!=2)
	{
	  int i;
	  char *str;

	  for(i=0;i<indent;i++)
	    putchar(' ');

	  if(crit)
	    str=_("Critical preferred keyserver: ");
	  else
	    str=_("Preferred keyserver: ");
	  if(mode)
	    log_info("%s",str);
	  else
	    printf("%s",str);
	  print_utf8_string(fp,p,len);
	  fprintf(fp,"\n");
	}

      /* TODO: put in a status-fd tag for preferred keyservers */
    }
}

/*
  mode=0 for stdout.
  mode=1 for log_info + status messages
  mode=2 for status messages only
*/

void
show_notation(PKT_signature *sig,int indent,int mode)
{
  const byte *p;
  size_t len;
  int seq=0,crit;
  FILE *fp=mode?log_stream():stdout;

  /* There may be multiple notations in the same sig. */

  while((p=enum_sig_subpkt(sig->hashed,SIGSUBPKT_NOTATION,&len,&seq,&crit)))
    if(len>=8)
      {
	int n1,n2;

	n1=(p[4]<<8)|p[5];
	n2=(p[6]<<8)|p[7];

	if(8+n1+n2!=len)
	  {
	    log_info(_("WARNING: invalid notation data found\n"));
	    return;
	  }

	if(mode!=2)
	  {
	    int i;
	    char *str;

	    for(i=0;i<indent;i++)
	      putchar(' ');

	    /* This is UTF8 */
	    if(crit)
	      str=_("Critical signature notation: ");
	    else
	      str=_("Signature notation: ");
	    if(mode)
	      log_info("%s",str);
	    else
	      printf("%s",str);
	    print_utf8_string(fp,p+8,n1);
	    fprintf(fp,"=");

	    if(*p&0x80)
	      print_utf8_string(fp,p+8+n1,n2);
	    else
	      fprintf(fp,"[ %s ]",_("not human readable"));

	    fprintf(fp,"\n");
	  }

	if(mode)
	  {
	    write_status_buffer ( STATUS_NOTATION_NAME, p+8   , n1, 0 );
	    write_status_buffer ( STATUS_NOTATION_DATA, p+8+n1, n2, 50 );
	  }
      }
  else
    log_info(_("WARNING: invalid notation data found\n"));
}

static void
print_signature_stats(struct sig_stats *s)
{
  if( s->inv_sigs == 1 )
    tty_printf(_("1 bad signature\n") );
  else if( s->inv_sigs )
    tty_printf(_("%d bad signatures\n"), s->inv_sigs );
  if( s->no_key == 1 )
    tty_printf(_("1 signature not checked due to a missing key\n") );
  else if( s->no_key )
    tty_printf(_("%d signatures not checked due to missing keys\n"),s->no_key);
  if( s->oth_err == 1 )
    tty_printf(_("1 signature not checked due to an error\n") );
  else if( s->oth_err )
    tty_printf(_("%d signatures not checked due to errors\n"), s->oth_err );
}

static void
list_all( int secret )
{
    KEYDB_HANDLE hd;
    KBNODE keyblock = NULL;
    int rc=0;
    const char *lastresname, *resname;
    struct sig_stats stats;

    memset(&stats,0,sizeof(stats));

    hd = keydb_new (secret);
    if (!hd)
        rc = G10ERR_GENERAL;
    else
        rc = keydb_search_first (hd);
    if( rc ) {
	if( rc != -1 )
	    log_error("keydb_search_first failed: %s\n", g10_errstr(rc) );
	goto leave;
    }

    lastresname = NULL;
    do {
        rc = keydb_get_keyblock (hd, &keyblock);
        if (rc) {
            log_error ("keydb_get_keyblock failed: %s\n", g10_errstr(rc));
            goto leave;
        }
	if(!opt.with_colons)
	  {
	    resname = keydb_get_resource_name (hd);
	    if (lastresname != resname )
	      {
		int i;

		printf("%s\n", resname );
		for(i=strlen(resname); i; i-- )
		  putchar('-');
		putchar('\n');
		lastresname = resname;
	      }
	  }
        merge_keys_and_selfsig( keyblock );
	list_keyblock( keyblock, secret, opt.fingerprint,
		       opt.check_sigs?&stats:NULL);
	release_kbnode( keyblock ); 
        keyblock = NULL;
    } while (!(rc = keydb_search_next (hd)));
    if( rc && rc != -1 )
	log_error ("keydb_search_next failed: %s\n", g10_errstr(rc));

    if(opt.check_sigs && !opt.with_colons)
      print_signature_stats(&stats);

  leave:
    release_kbnode (keyblock);
    keydb_release (hd);
}


static void
list_one( STRLIST names, int secret )
{
    int rc = 0;
    KBNODE keyblock = NULL;
    GETKEY_CTX ctx;
    const char *resname;
    char *keyring_str = _("Keyring");
    int i;
    struct sig_stats stats;

    memset(&stats,0,sizeof(stats));

    /* fixme: using the bynames function has the disadvantage that we
     * don't know wether one of the names given was not found.  OTOH,
     * this function has the advantage to list the names in the
     * sequence as defined by the keyDB and does not duplicate
     * outputs.  A solution could be do test whether all given have
     * been listed (this needs a way to use the keyDB search
     * functions) or to have the search function return indicators for
     * found names.  Yet another way is to use the keydb search
     * facilities directly. */
    if( secret ) {
	rc = get_seckey_bynames( &ctx, NULL, names, &keyblock );
	if( rc ) {
	    log_error("error reading key: %s\n",  g10_errstr(rc) );
	    get_seckey_end( ctx );
	    return;
	}
	do {
	    if ((opt.list_options&LIST_SHOW_KEYRING) && !opt.with_colons) {
		resname = keydb_get_resource_name (get_ctx_handle(ctx));
		printf("%s: %s\n", keyring_str, resname);
		for(i = strlen(resname) + strlen(keyring_str) + 2; i; i-- )
		    putchar('-');
		putchar('\n');
	    }
	    list_keyblock( keyblock, 1, opt.fingerprint, NULL );
	    release_kbnode( keyblock );
	} while( !get_seckey_next( ctx, NULL, &keyblock ) );
	get_seckey_end( ctx );
    }
    else {
	rc = get_pubkey_bynames( &ctx, NULL, names, &keyblock );
	if( rc ) {
	    log_error("error reading key: %s\n", g10_errstr(rc) );
	    get_pubkey_end( ctx );
	    return;
	}
	do {
	  if ((opt.list_options&LIST_SHOW_KEYRING) && !opt.with_colons) {
		resname = keydb_get_resource_name (get_ctx_handle(ctx));
		printf("%s: %s\n", keyring_str, resname);
		for(i = strlen(resname) + strlen(keyring_str) + 2; i; i-- )
		    putchar('-');
		putchar('\n');
	    }
	    list_keyblock( keyblock, 0, opt.fingerprint,
			   opt.check_sigs?&stats:NULL );
	    release_kbnode( keyblock );
	} while( !get_pubkey_next( ctx, NULL, &keyblock ) );
	get_pubkey_end( ctx );
    }

    if(opt.check_sigs && !opt.with_colons)
      print_signature_stats(&stats);
}

static void
print_key_data( PKT_public_key *pk, u32 *keyid )
{
    int n = pk ? pubkey_get_npkey( pk->pubkey_algo ) : 0;
    int i;

    for(i=0; i < n; i++ ) {
	printf("pkd:%d:%u:", i, mpi_get_nbits( pk->pkey[i] ) );
	mpi_print(stdout, pk->pkey[i], 1 );
	putchar(':');
	putchar('\n');
    }
}

static void
print_capabilities (PKT_public_key *pk, PKT_secret_key *sk, KBNODE keyblock)
{
  if(pk || (sk && sk->protect.s2k.mode!=1001))
    {
      unsigned int use = pk? pk->pubkey_usage : sk->pubkey_usage;
    
      if ( use & PUBKEY_USAGE_ENC )
        putchar ('e');

      if ( use & PUBKEY_USAGE_SIG )
	{
	  putchar ('s');
	  if( pk? pk->is_primary : sk->is_primary )
	    putchar ('c');
	}
    }

    if ( keyblock ) { /* figure out the usable capabilities */
        KBNODE k;
        int enc=0, sign=0, cert=0, disabled=0;

        for (k=keyblock; k; k = k->next ) {
            if ( k->pkt->pkttype == PKT_PUBLIC_KEY 
                 || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
                pk = k->pkt->pkt.public_key;

		if(pk->is_primary)
		  disabled=pk_is_disabled(pk);

                if ( pk->is_valid && !pk->is_revoked && !pk->has_expired ) {
                    if ( pk->pubkey_usage & PUBKEY_USAGE_ENC )
                        enc = 1;
                    if ( pk->pubkey_usage & PUBKEY_USAGE_SIG )
		      {
			sign = 1;
			if(pk->is_primary)
			  cert = 1;
		      }
                }
            }
            else if ( k->pkt->pkttype == PKT_SECRET_KEY 
                      || k->pkt->pkttype == PKT_SECRET_SUBKEY ) {
                sk = k->pkt->pkt.secret_key;
                if ( sk->is_valid && !sk->is_revoked && !sk->has_expired
		     && sk->protect.s2k.mode!=1001 ) {
                    if ( sk->pubkey_usage & PUBKEY_USAGE_ENC )
                        enc = 1;
                    if ( sk->pubkey_usage & PUBKEY_USAGE_SIG )
		      {
			sign = 1;
			if(sk->is_primary)
			  cert = 1;
		      }
                }
            }
        }
        if (enc)
            putchar ('E');
        if (sign)
            putchar ('S');
        if (cert)
            putchar ('C');
        if (disabled)
            putchar ('D');
    }

    putchar(':');
}

void
dump_attribs(const PKT_user_id *uid,PKT_public_key *pk,PKT_secret_key *sk)
{
  int i;

  if(!attrib_fp)
    return;

  for(i=0;i<uid->numattribs;i++)
    {
      if(is_status_enabled())
	{
	  byte array[MAX_FINGERPRINT_LEN], *p;
	  char buf[(MAX_FINGERPRINT_LEN*2)+90];
	  size_t j,n;

	  if(pk)
	    fingerprint_from_pk( pk, array, &n );
	  else if(sk)
	    fingerprint_from_sk( sk, array, &n );
	  else
	    BUG();

	  p = array;
	  for(j=0; j < n ; j++, p++ )
	    sprintf(buf+2*j, "%02X", *p );

	  sprintf(buf+strlen(buf)," %lu %u %u %u %lu %lu %u",
		  (ulong)uid->attribs[i].len,uid->attribs[i].type,i+1,
		  uid->numattribs,(ulong)uid->created,(ulong)uid->expiredate,
		  ((uid->is_primary?0x01:0)|
		   (uid->is_revoked?0x02:0)|
		   (uid->is_expired?0x04:0)));
	  write_status_text(STATUS_ATTRIBUTE,buf);
	}

      fwrite(uid->attribs[i].data,uid->attribs[i].len,1,attrib_fp);
    }
}

static void
list_keyblock_print ( KBNODE keyblock, int secret, int fpr, void *opaque )
{
    int rc = 0;
    KBNODE kbctx;
    KBNODE node;
    PKT_public_key *pk;
    PKT_secret_key *sk;
    u32 keyid[2];
    int any=0;
    struct sig_stats *stats=opaque;
    int newformat=((opt.list_options&LIST_SHOW_VALIDITY) && !secret)
      || (opt.list_options&LIST_SHOW_LONG_KEYID);

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, secret? PKT_SECRET_KEY : PKT_PUBLIC_KEY );
    if( !node ) {
	log_error("Oops; key lost!\n");
	dump_kbnode( keyblock );
	return;
    }

    if( secret )
      {
	pk = NULL;
	sk = node->pkt->pkt.secret_key;
	keyid_from_sk( sk, keyid );

        printf("sec%c  %4u%c/",(sk->protect.s2k.mode==1001)?'#':' ',
	       nbits_from_sk( sk ),pubkey_letter( sk->pubkey_algo ));

	if(opt.list_options&LIST_SHOW_LONG_KEYID)
	  printf("%08lX%08lX",(ulong)keyid[0],(ulong)keyid[1]);
	else
	  printf("%08lX",(ulong)keyid[1]);

	printf(" %s%s",datestr_from_sk( sk ),newformat?"":" " );

	if(newformat && sk->expiredate )
	  printf(_(" [expires: %s]"), expirestr_from_sk( sk ) );
      }
    else
      {
	int validity;
	pk = node->pkt->pkt.public_key;
	sk = NULL;
	keyid_from_pk( pk, keyid );

	validity=get_validity(pk,NULL);

	printf("pub   %4u%c/",
	       nbits_from_pk(pk),pubkey_letter(pk->pubkey_algo));

	if(opt.list_options&LIST_SHOW_LONG_KEYID)
	  printf("%08lX%08lX",(ulong)keyid[0],(ulong)keyid[1]);
	else
	  printf("%08lX",(ulong)keyid[1]);

	printf(" %s%s",datestr_from_pk( pk ),newformat?"":" " );

	/* We didn't include this before in the key listing, but there
	   is room in the new format, so why not? */
	if(newformat && pk->expiredate)
	  printf(_(" [expires: %s]"), expirestr_from_pk( pk ) );

	if(opt.list_options&LIST_SHOW_VALIDITY)
	  printf(" [%s]",trust_value_to_string(validity));
      }

    for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	if( node->pkt->pkttype == PKT_USER_ID && !opt.fast_list_mode ) {
	    int indent;
            /* don't list revoked or expired UIDS unless we are in
             * verbose mode and signature listing has not been
             * requested */
            if ( !opt.verbose && !opt.list_sigs &&
                 (node->pkt->pkt.user_id->is_revoked ||
		  node->pkt->pkt.user_id->is_expired ))
                continue; 

	    if(attrib_fp && node->pkt->pkt.user_id->attrib_data!=NULL)
	      dump_attribs(node->pkt->pkt.user_id,pk,sk);

	    if(!any && newformat)
	      printf("\n");

	    if((opt.list_options&LIST_SHOW_VALIDITY) && pk)
	      {
		const char *validity=
		trust_value_to_string(get_validity(pk,node->pkt->pkt.user_id));

		/* Includes the 3 spaces for [, ], and " ". */
		indent=((opt.list_options&LIST_SHOW_LONG_KEYID)?23:15)
		  -strlen(validity);

		if(indent<0)
		  indent=0;

		printf("uid%*s[%s] ",indent,"",validity);
	      }
	    else if(newformat)
	      printf("uid%*s",26,"");
	    else if(any)
	      printf("uid%*s",29,"");

            if ( node->pkt->pkt.user_id->is_revoked )
                fputs ("[revoked] ", stdout);
            if ( node->pkt->pkt.user_id->is_expired )
                fputs ("[expired] ", stdout);

            print_utf8_string( stdout,  node->pkt->pkt.user_id->name,
                               node->pkt->pkt.user_id->len );
	    putchar('\n');
	    if( !any ) {
		if( fpr )
		    print_fingerprint( pk, sk, 0 );
		if( opt.with_key_data )
		    print_key_data( pk, keyid );
		any = 1;
	    }

	    if((opt.list_options&LIST_SHOW_PHOTOS)
	       && node->pkt->pkt.user_id->attribs!=NULL)
	      show_photos(node->pkt->pkt.user_id->attribs,
			  node->pkt->pkt.user_id->numattribs,pk,sk);
	}
	else if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    u32 keyid2[2];
	    PKT_public_key *pk2 = node->pkt->pkt.public_key;

	    if( !any ) {
		putchar('\n');
		if( fpr )
		    print_fingerprint( pk, sk, 0 ); /* of the main key */
		any = 1;
	    }

	    keyid_from_pk( pk2, keyid2 );
            printf("sub   %4u%c/",
		   nbits_from_pk( pk2 ),pubkey_letter( pk2->pubkey_algo ));
	    if(opt.list_options&LIST_SHOW_LONG_KEYID)
	      printf("%08lX%08lX",(ulong)keyid2[0],(ulong)keyid2[1]);
	    else
	      printf("%08lX",(ulong)keyid2[1]);
	    printf(" %s",datestr_from_pk(pk2));
            if( pk2->expiredate )
	      printf(_(" [expires: %s]"), expirestr_from_pk( pk2 ) );
            putchar('\n');
	    if( fpr > 1 )
		print_fingerprint( pk2, NULL, 0 );
	    if( opt.with_key_data )
		print_key_data( pk2, keyid2 );
	}
	else if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    u32 keyid2[2];
	    PKT_secret_key *sk2 = node->pkt->pkt.secret_key;

	    if( !any ) {
		putchar('\n');
		if( fpr )
		    print_fingerprint( pk, sk, 0 ); /* of the main key */
		any = 1;
	    }

	    keyid_from_sk( sk2, keyid2 );
            printf("ssb   %4u%c/",
		   nbits_from_sk( sk2 ),pubkey_letter( sk2->pubkey_algo ));
	    if(opt.list_options&LIST_SHOW_LONG_KEYID)
	      printf("%08lX%08lX",(ulong)keyid2[0],(ulong)keyid2[1]);
	    else
	      printf("%08lX",(ulong)keyid2[1]);
	    printf(" %s",datestr_from_sk( sk2 ) );
            if( sk2->expiredate )
	      printf(_(" [expires: %s]"), expirestr_from_sk( sk2 ) );
	    putchar('\n');
	    if( fpr > 1 )
		print_fingerprint( NULL, sk2, 0 );
	}
	else if( opt.list_sigs && node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;
	    int sigrc;
            char *sigstr;

	    if( stats ) {
                /*fflush(stdout);*/
		rc = check_key_signature( keyblock, node, NULL );
		switch( rc ) {
		 case 0:		 sigrc = '!'; break;
		 case G10ERR_BAD_SIGN:   stats->inv_sigs++; sigrc = '-'; break;
		 case G10ERR_NO_PUBKEY: 
		 case G10ERR_UNU_PUBKEY: stats->no_key++; continue;
		 default:		 stats->oth_err++; sigrc = '%'; break;
		}

		/* TODO: Make sure a cached sig record here still has
                   the pk that issued it.  See also
                   keyedit.c:print_and_check_one_sig */

	    }
	    else {
		rc = 0;
		sigrc = ' ';
	    }

	    if( !any ) { /* no user id, (maybe a revocation follows)*/
	      /* Check if the pk is really revoked - there could be a
                 0x20 sig packet there even if we are not revoked
                 (say, if a revocation key issued the packet, but the
                 revocation key isn't present to verify it.) */
		if( sig->sig_class == 0x20 && pk->is_revoked )
		    puts("[revoked]");
		else if( sig->sig_class == 0x18 )
		    puts("[key binding]");
		else if( sig->sig_class == 0x28 )
		    puts("[subkey revoked]");
		else
		    putchar('\n');
		if( fpr )
		    print_fingerprint( pk, sk, 0 );
		any=1;
	    }

	    if( sig->sig_class == 0x20 || sig->sig_class == 0x28
				       || sig->sig_class == 0x30 )
	       sigstr = "rev";
	    else if( (sig->sig_class&~3) == 0x10 )
	       sigstr = "sig";
	    else if( sig->sig_class == 0x18 )
	       sigstr = "sig";
	    else if( sig->sig_class == 0x1F )
	       sigstr = "sig";
	    else {
                printf("sig                             "
		       "[unexpected signature class 0x%02x]\n",sig->sig_class );
		continue;
	    }

            fputs( sigstr, stdout );
	    printf("%c%c %c%c%c%c%c%c ",
                   sigrc,(sig->sig_class-0x10>0 &&
                          sig->sig_class-0x10<4)?'0'+sig->sig_class-0x10:' ',
                   sig->flags.exportable?' ':'L',
                   sig->flags.revocable?' ':'R',
                   sig->flags.policy_url?'P':' ',
                   sig->flags.notation?'N':' ',
                   sig->flags.expired?'X':' ',
		   (sig->trust_depth>9)?'T':
		   (sig->trust_depth>0)?'0'+sig->trust_depth:' ');
	    if(opt.list_options&LIST_SHOW_LONG_KEYID)
	      printf("%08lX%08lX",(ulong)sig->keyid[0],(ulong)sig->keyid[1]);
	    else
	      printf("%08lX",(ulong)sig->keyid[1]);
	    printf(" %s", datestr_from_sig(sig));
	    if(opt.list_options&LIST_SHOW_SIG_EXPIRE)
	      printf(" %s", expirestr_from_sig(sig));
	    printf("  ");
	    if( sigrc == '%' )
		printf("[%s] ", g10_errstr(rc) );
	    else if( sigrc == '?' )
		;
	    else if ( !opt.fast_list_mode ) {
		size_t n;
		char *p = get_user_id( sig->keyid, &n );
                print_utf8_string( stdout, p, n );
		m_free(p);
	    }
	    putchar('\n');

	    if(sig->flags.policy_url && (opt.list_options&LIST_SHOW_POLICY))
	      show_policy_url(sig,3,0);

	    if(sig->flags.notation && (opt.list_options&LIST_SHOW_NOTATION))
	      show_notation(sig,3,0);

	    if(sig->flags.pref_ks && (opt.list_options&LIST_SHOW_KEYSERVER))
	      show_keyserver_url(sig,3,0);

	    /* fixme: check or list other sigs here */
	}
    }
    putchar('\n');
}


static void
list_keyblock_colon( KBNODE keyblock, int secret, int fpr )
{
    int rc = 0;
    KBNODE kbctx;
    KBNODE node;
    PKT_public_key *pk;
    PKT_secret_key *sk;
    u32 keyid[2];
    int any=0;
    int trustletter = 0;
    int ulti_hack = 0;

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, secret? PKT_SECRET_KEY : PKT_PUBLIC_KEY );
    if( !node ) {
	log_error("Oops; key lost!\n");
	dump_kbnode( keyblock );
	return;
    }

    if( secret ) {
	pk = NULL;
	sk = node->pkt->pkt.secret_key;
	keyid_from_sk( sk, keyid );
        printf("sec::%u:%d:%08lX%08lX:%s:%s:::",
		    nbits_from_sk( sk ),
		    sk->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    colon_datestr_from_sk( sk ),
		    colon_strtime (sk->expiredate)
		    /* fixme: add LID here */ );
    }
    else {
	pk = node->pkt->pkt.public_key;
	sk = NULL;
	keyid_from_pk( pk, keyid );
        fputs( "pub:", stdout );
        if ( !pk->is_valid )
            putchar ('i');
        else if ( pk->is_revoked )
            putchar ('r');
        else if ( pk->has_expired )
            putchar ('e');
        else if ( opt.fast_list_mode || opt.no_expensive_trust_checks ) 
            ;
        else {
            trustletter = get_validity_info ( pk, NULL );
            if( trustletter == 'u' )
                ulti_hack = 1;
            putchar(trustletter);
        }
        printf(":%u:%d:%08lX%08lX:%s:%s:",
		    nbits_from_pk( pk ),
		    pk->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    colon_datestr_from_pk( pk ),
		    colon_strtime (pk->expiredate) );
        if( pk->local_id )
            printf("%lu", pk->local_id );
        putchar(':');
        if( !opt.fast_list_mode && !opt.no_expensive_trust_checks  )
            putchar( get_ownertrust_info(pk) );
	    putchar(':');
    }
    
    if (opt.fixed_list_mode) {
        /* do not merge the first uid with the primary key */
        putchar(':');
        putchar(':');
        print_capabilities (pk, sk, keyblock);
        putchar('\n');
        if( fpr )
            print_fingerprint( pk, sk, 0 );
        if( opt.with_key_data )
            print_key_data( pk, keyid );
        any = 1;
    }


    for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	if( node->pkt->pkttype == PKT_USER_ID && !opt.fast_list_mode ) {
	    PKT_user_id *uid=node->pkt->pkt.user_id;
	    if(attrib_fp && node->pkt->pkt.user_id->attrib_data!=NULL)
	      dump_attribs(node->pkt->pkt.user_id,pk,sk);
            /*
             * Fixme: We need a is_valid flag here too 
             */
	    if( any ) {
	        int i;
	        char *str=uid->attrib_data?"uat":"uid";
		/* If we're listing a secret key, leave out the
		   validity values for now.  This is handled better in
		   1.9. */
		if ( sk )
        	    printf("%s:::::",str);
                else if ( uid->is_revoked )
        	    printf("%s:r::::",str);
                else if ( uid->is_expired )
        	    printf("%s:e::::",str);
		else if ( opt.no_expensive_trust_checks )
        	    printf("%s:::::",str);
                else {
		    int uid_validity;

		    if( pk && !ulti_hack )
		      uid_validity=get_validity_info (pk, uid);
		    else
			uid_validity = 'u';
		    printf("%s:%c::::",str,uid_validity);
                }

		printf("%s:",colon_strtime(uid->created));
		printf("%s:",colon_strtime(uid->expiredate));

		namehash_from_uid(uid);

		for(i=0; i < 20; i++ )
		  printf("%02X",uid->namehash[i]);

		printf("::");
	    }
	    if(uid->attrib_data)
	      printf("%u %lu",uid->numattribs,uid->attrib_len);
            else
	      print_string(stdout,uid->name,uid->len, ':' );
            putchar(':');
	    if (any)
                putchar('\n');
            else {
                putchar(':');
                print_capabilities (pk, sk, keyblock);
                putchar('\n');
		if( fpr )
		    print_fingerprint( pk, sk, 0 );
		if( opt.with_key_data )
		    print_key_data( pk, keyid );
		any = 1;
	    }
	}
	else if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    u32 keyid2[2];
	    PKT_public_key *pk2 = node->pkt->pkt.public_key;

	    if( !any ) {
                putchar(':');
                putchar(':');
                print_capabilities (pk, sk, keyblock);
                putchar('\n');
		if( fpr )
		    print_fingerprint( pk, sk, 0 ); /* of the main key */
		any = 1;
	    }

	    keyid_from_pk( pk2, keyid2 );
            fputs ("sub:", stdout );
            if ( !pk2->is_valid )
                putchar ('i');
            else if ( pk2->is_revoked )
                putchar ('r');
            else if ( pk2->has_expired )
                putchar ('e');
            else if ( opt.fast_list_mode || opt.no_expensive_trust_checks )
                ;
            else {
	        /* trustletter should always be defined here */
	        if(trustletter)
		  printf("%c", trustletter );
            }
            printf(":%u:%d:%08lX%08lX:%s:%s:",
			nbits_from_pk( pk2 ),
			pk2->pubkey_algo,
			(ulong)keyid2[0],(ulong)keyid2[1],
			colon_datestr_from_pk( pk2 ),
			colon_strtime (pk2->expiredate)
			/* fixme: add LID and ownertrust here */
						);
            if( pk->local_id ) /* use the local_id of the main key??? */
                printf("%lu", pk->local_id );
            putchar(':');
            putchar(':');
            putchar(':');
            putchar(':');
            print_capabilities (pk2, NULL, NULL);
            putchar('\n');
	    if( fpr > 1 )
		print_fingerprint( pk2, NULL, 0 );
	    if( opt.with_key_data )
		print_key_data( pk2, keyid2 );
	}
	else if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    u32 keyid2[2];
	    PKT_secret_key *sk2 = node->pkt->pkt.secret_key;

	    if( !any ) {
                putchar(':');
                putchar(':');
                print_capabilities (pk, sk, keyblock);
		putchar('\n');
		if( fpr )
		    print_fingerprint( pk, sk, 0 ); /* of the main key */
		any = 1;
	    }

	    keyid_from_sk( sk2, keyid2 );
            printf("ssb::%u:%d:%08lX%08lX:%s:%s:::::",
			nbits_from_sk( sk2 ),
			sk2->pubkey_algo,
			(ulong)keyid2[0],(ulong)keyid2[1],
			colon_datestr_from_sk( sk2 ),
			colon_strtime (sk2->expiredate)
                   /* fixme: add LID */ );
            print_capabilities (NULL, sk2, NULL);
            putchar ('\n');
	    if( fpr > 1 )
		print_fingerprint( NULL, sk2, 0 );
	}
	else if( opt.list_sigs && node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;
	    int sigrc,fprokay=0;
            char *sigstr;
	    size_t fplen;
	    byte fparray[MAX_FINGERPRINT_LEN];

	    if( !any ) { /* no user id, (maybe a revocation follows)*/
		if( sig->sig_class == 0x20 )
		    fputs("[revoked]:", stdout);
		else if( sig->sig_class == 0x18 )
		    fputs("[key binding]:", stdout);
		else if( sig->sig_class == 0x28 )
		    fputs("[subkey revoked]:", stdout);
                else
                    putchar (':');
                putchar(':');
                print_capabilities (pk, sk, keyblock);
                putchar('\n');
		if( fpr )
		    print_fingerprint( pk, sk, 0 );
		any=1;
	    }

	    if( sig->sig_class == 0x20 || sig->sig_class == 0x28
				       || sig->sig_class == 0x30 )
	       sigstr = "rev";
	    else if( (sig->sig_class&~3) == 0x10 )
	       sigstr = "sig";
	    else if( sig->sig_class == 0x18 )
	       sigstr = "sig";
	    else if( sig->sig_class == 0x1F )
	       sigstr = "sig";
	    else {
                printf ("sig::::::::::%02x%c:\n",
                        sig->sig_class, sig->flags.exportable?'x':'l');
		continue;
	    }
	    if( opt.check_sigs ) {
	        PKT_public_key *signer_pk=NULL;

		fflush(stdout);
		if(opt.no_sig_cache)
		  signer_pk=m_alloc_clear(sizeof(PKT_public_key));

		rc = check_key_signature2( keyblock, node, NULL, signer_pk,
					   NULL, NULL, NULL );
		switch( rc ) {
		  case 0:		   sigrc = '!'; break;
		  case G10ERR_BAD_SIGN:    sigrc = '-'; break;
		  case G10ERR_NO_PUBKEY: 
		  case G10ERR_UNU_PUBKEY:  sigrc = '?'; break;
		  default:		   sigrc = '%'; break;
		}

		if(opt.no_sig_cache)
		  {
		    if(rc==0)
		      {
			fingerprint_from_pk (signer_pk, fparray, &fplen);
			fprokay=1;
		      }
		    free_public_key(signer_pk);
		  }
	    }
	    else {
		rc = 0;
		sigrc = ' ';
	    }
            fputs( sigstr, stdout );
            putchar(':');
            if( sigrc != ' ' )
                putchar(sigrc);
            printf("::%d:%08lX%08lX:%s:%s:", sig->pubkey_algo,
		   (ulong)sig->keyid[0], (ulong)sig->keyid[1],
		   colon_datestr_from_sig(sig),
		   colon_expirestr_from_sig(sig));

	    if(sig->trust_depth || sig->trust_value)
	      printf("%d %d",sig->trust_depth,sig->trust_value);
	    printf(":");

	    if(sig->trust_regexp)
	      print_string(stdout,sig->trust_regexp,
			   strlen(sig->trust_regexp),':');
	    printf(":");

	    if( sigrc == '%' )
		printf("[%s] ", g10_errstr(rc) );
	    else if( sigrc == '?' )
		;
	    else if ( !opt.fast_list_mode ) {
		size_t n;
		char *p = get_user_id( sig->keyid, &n );
                print_string( stdout, p, n, ':' );
		m_free(p);
	    }
            printf(":%02x%c:", sig->sig_class,sig->flags.exportable?'x':'l');

	    if(opt.no_sig_cache && opt.check_sigs && fprokay)
	      {
		size_t i;

		printf(":");

		for (i=0; i < fplen ; i++ )
		  printf ("%02X", fparray[i] );

		printf(":");
	      }

	    printf("\n");

	    /* fixme: check or list other sigs here */
	}
    }
    if( !any ) {/* oops, no user id */
        putchar(':');
        putchar(':');
        print_capabilities (pk, sk, keyblock);
	putchar('\n');
    }
}

/*
 * Reorder the keyblock so that the primary user ID (and not attribute
 * packet) comes first.  Fixme: Replace this by a generic sort
 * function.  */
void
reorder_keyblock (KBNODE keyblock)
{
    KBNODE primary = NULL, primary0 = NULL, primary2 = NULL;
    KBNODE last, node;

    for (node=keyblock; node; primary0=node, node = node->next) {
	if( node->pkt->pkttype == PKT_USER_ID &&
	    !node->pkt->pkt.user_id->attrib_data &&
            node->pkt->pkt.user_id->is_primary ) {
            primary = primary2 = node;
            for (node=node->next; node; primary2=node, node = node->next ) {
                if( node->pkt->pkttype == PKT_USER_ID 
                    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY 
                    || node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
                    break;
                }
            }
            break;
        }
    }
    if ( !primary )
        return;  /* no primary key flag found (should not happen) */

    for (last=NULL, node=keyblock; node; last = node, node = node->next) {
	if( node->pkt->pkttype == PKT_USER_ID )
            break;
    }
    assert (node);
    assert (last); /* the user ID is never the first packet */
    assert (primary0);  /* ditto (this is the node before primary) */
    if ( node == primary )
        return; /* already the first one */

    last->next = primary;
    primary0->next = primary2->next;
    primary2->next = node;
}

void
list_keyblock( KBNODE keyblock, int secret, int fpr, void *opaque )
{
    reorder_keyblock (keyblock);
    if (opt.with_colons)
        list_keyblock_colon (keyblock, secret, fpr );
    else
        list_keyblock_print (keyblock, secret, fpr, opaque );
}

/*
 * standard function to print the finperprint.
 * mode 0: as used in key listings, opt.with_colons is honored
 *      1: print using log_info ()
 *      2: direct use of tty
 *      3: direct use of tty but only primary key.
 * modes 1 and 2 will try and print both subkey and primary key fingerprints
 */
void
print_fingerprint (PKT_public_key *pk, PKT_secret_key *sk, int mode )
{
    byte array[MAX_FINGERPRINT_LEN], *p;
    size_t i, n;
    FILE *fp;
    const char *text;
    int primary=0;

    if(sk)
      {
	if(sk->main_keyid[0]==sk->keyid[0] && sk->main_keyid[1]==sk->keyid[1])
	  primary=1;
      }
    else
      {
	if(pk->main_keyid[0]==pk->keyid[0] && pk->main_keyid[1]==pk->keyid[1])
	  primary=1;
      }

    /* Just to be safe */
    if(mode&0x80 && !primary)
      {
	log_error("primary key is not really primary!\n");
	return;
      }

    mode&=~0x80;

    if(!primary && (mode==1 || mode==2))
      {
	if(sk)
	  {
	    PKT_secret_key *primary_sk=m_alloc_clear(sizeof(*primary_sk));
	    get_seckey(primary_sk,sk->main_keyid);
	    print_fingerprint(NULL,primary_sk,mode|0x80);
	    free_secret_key(primary_sk);
	  }
	else
	  {
	    PKT_public_key *primary_pk=m_alloc_clear(sizeof(*primary_pk));
	    get_pubkey(primary_pk,pk->main_keyid);
	    print_fingerprint(primary_pk,NULL,mode|0x80);
	    free_public_key(primary_pk);
	  }
      }

    if (mode == 1) {
        fp = log_stream ();
	if(primary)
	  text = _("Primary key fingerprint:");
	else
	  text = _("     Subkey fingerprint:");
    }
    else if (mode == 2) {
        fp = NULL; /* use tty */
        /* Translators: this should fit into 24 bytes to that the fingerprint
         * data is properly aligned with the user ID */
	if(primary)
	  text = _(" Primary key fingerprint:");
	else
	  text = _("      Subkey fingerprint:");
    }
    else if (mode == 3) {
        fp = NULL; /* use tty */
	text = _("      Key fingerprint =");
    }
    else {
        fp = stdout;
	text = _("      Key fingerprint =");
    }
  
    if (sk)
	fingerprint_from_sk (sk, array, &n);
    else
	fingerprint_from_pk (pk, array, &n);
    p = array;
    if (opt.with_colons && !mode) {
	fprintf (fp, "fpr:::::::::");
	for (i=0; i < n ; i++, p++ )
	    fprintf (fp, "%02X", *p );
	putc(':', fp);
    }
    else {
        if (fp)
            fputs (text, fp);
        else
            tty_printf ("%s", text);
	if (n == 20) {
	    for (i=0; i < n ; i++, i++, p += 2 ) {
                if (fp) {
                    if (i == 10 )
                        putc(' ', fp);
                    fprintf (fp, " %02X%02X", *p, p[1] );
                }
                else {
                    if (i == 10 )
                        tty_printf (" ");
                    tty_printf (" %02X%02X", *p, p[1]);
                }
	    }
	}
	else {
	    for (i=0; i < n ; i++, p++ ) {
                if (fp) {
                    if (i && !(i%8) )
                        putc (' ', fp);
                    fprintf (fp, " %02X", *p );
                }
                else {
                    if (i && !(i%8) )
                        tty_printf (" ");
                    tty_printf (" %02X", *p );
                }
	    }
	}
    }
    if (fp)
        putc ('\n', fp);
    else
        tty_printf ("\n");
}

void set_attrib_fd(int fd)
{
  static int last_fd=-1;

  if ( fd != -1 && last_fd == fd )
    return;

  if ( attrib_fp && attrib_fp != stdout && attrib_fp != stderr )
    fclose (attrib_fp);
  attrib_fp = NULL;
  if ( fd == -1 ) 
    return;

  if( fd == 1 )
    attrib_fp = stdout;
  else if( fd == 2 )
    attrib_fp = stderr;
  else
    attrib_fp = fdopen( fd, "w" );
  if( !attrib_fp ) {
    log_fatal("can't open fd %d for attribute output: %s\n",
	      fd, strerror(errno));
  }
  last_fd = fd;
}
