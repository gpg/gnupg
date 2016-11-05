/* t-ssh-utils.c - Module test for ssh-utils.c
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"
#include "ssh-utils.h"


static struct { const char *key; const char *fpr; } sample_keys[] = {
  { "(protected-private-key "
    "(rsa "
    "(n #"
    "00D88E47BCE0DA99D6180E8A9F4E6A673CC16F5BB6CF930E0E868BAABA715A8E1D3E2BEA"
    "5477170E1F6CAFC0F8907B9892993C70AC476BBB301669F68EE0593532FB522DD60755A3"
    "2F8B08649E856271A7F9BCB25F29554DF11707F812EA377683A99DD4698C4DBF797A0ABF"
    "43C8EBB364B9FFC9EE78CBEA348C590507A4EA390312153DDD905EC4F1A63D5DA56C08FD"
    "C3F6E5707BFC5DBDC09D19723B1AC6E466906F13AA2ECDBD258148F86C980D45CF233415"
    "38C5857C2CF0B4C9AB2B4E6A4517FF084FDB009A33553A68907A29691B6FAE994E864F78"
    "7B83F714730BEDB0AF1723D636E034D73EB7EC9BA127BB4BE80FD805813E3F45E7FAE514"
    "AD2ECA9607#)"
    "(e \"#\")"
    "(protected openpgp-s2k3-sha1-aes-cbc "
    "("
    "(sha1 #B5847F9A2DB4E0C5# \"5242880\")"
    "#342D81BDE21301F18FDCE169A99A47C5#)"
    "#23512602219EC7A97DBA89347CCD59D2072D80CE3F7DD6C97A058B83DAB3C829D97DF5"
    "DFE9181F27DBF58258C4CDBD562A5B20BB5BC35EDCA7B1E57B8CDBF92D798F46EE5567BD"
    "8A67EF3BE09908A49D41AA166A3398B64227BC75021C69A8FE8354E2903EF52DC91B1FE3"
    "EF9558E5C2D34CF38BFC29E99A49AE30B0C22CE81EE14FC71E986E7C7CB5FCF807433FDA"
    "EF1D00985767265BA0BE333754E44CCF622CBB98A029D78A6A9AADBC24613127B6448350"
    "23DA355ED31CF089DD11A7FC6003CEEB53FB327A05604D053C99996F9E01CB355983F66E"
    "7BEB9687A9277BBF440ED5FAF1A8396C9B06C9B47BA7A994E1931B08DAD34449952CD343"
    "9A691477682C324EA07CCCE5DF0F0E9DAEFAE3A4717AACA6DC18ED91DD5A820C924BD36B"
    "B3BA85BD63B3180C7F94EE58956940621280B9628FA5CC560BB14331AF1A7B5B499F8F03"
    "0ED464ABD4E26C5FD610697EDD0FD1203983E73418F3776568A613D3CEFF17199473052A"
    "18807A6F5C52A2A643185801D087EE4DC930ABEEB67C5B8A1CB2F29D0ACBD855972BEC0B"
    "DE6E52387CFCC54B4C2B87EE947C97173BFCAE3E2658EB819D87F542C9A9FE6C410D08F5"
    "3CD5451FB50253F4A848DFE136B3A5861D58B76A26A7E3E4E7A8F8D4BD5B80430674A6B9"
    "A2C8EDD53DB37865D1ACBB07E1758DFF64A944E0126F948BF088C0FC0C3607E39522EC94"
    "91483A90D9498D7F6C3C8720124C7E3F6E271E78E1CFFB4EF64F070F7424F30372A07D02"
    "2355D8B17BB0DEBCBE101F621E0526551A35A56830D74E0F5BD6313DF114D1E46D4844AA"
    "E4EB6268637D04B27D200D7F40AFA9AD2CFAA5415E5FC08358FFA79A9E743CCDF6668FE5"
    "D79FA03D61941E57244F066A31F1C9D6A34DC62BC738C52B604F00B19EB9FD0173F3B139"
    "42932066B7DC94DC4C563392F798A1CE2D5D75B8FF93E440433263CFB7016143A9923CD9"
    "634E964A8056946F462B06F320F44449D85B07FA26A324505C858274F89EDBD8346950DE"
    "5F#)"
    "(protected-at \"20110720T135431\")"
    ")"
    "(comment passphrase_is_abc)"
    ")",
    "c7:c6:a7:ec:04:6c:87:59:54:f2:88:58:09:e0:f2:b1"
  },
  {
    "(protected-private-key "
    "(dsa "
    "(p #00FC7DC086F4517079BCCFA7FD229477FE88B0231038DFC21B29CCBD74C6F6FE04FD"
    "7248C0473D5028BE106D7A7C8F54B269225789E781763527D1432CD46E416C2D14DDCA70"
    "27DA4B92D1E222B5BDF4B9C8C761CACCFBD108F7729412E8835653BE5073447287A6BDEB"
    "4645A5411752405EE7F503E44B1DFDCA6054CD3C44630B#)"
    "(q #00D498505BF0E7EE01239EB51F2B400B8EF6329B17#)"
    "(g #00A127B3DD5106F0A463312E42ECB83790E6F3BEA7AC3FAF7A42FB2C00F376323676"
    "C9E48984F0D4AC3FE5856F1C2765E9BC3C8A5C9C9CD3166C057E82569D187C48591AA66B"
    "8966BFF2B827BE36BD0BA4B895B42136F1381D52DDA708B2A3D181F648228DFFFEB153DA"
    "ACCAEBB51EF08A7807CD628024CEFF96FEE97DE95C8CBE#)"
    "(y #008E2B0915A3A299D83B4333C848C5D312F25903773E8C4D50691CAF81C3B768FA41"
    "7D19F0FD437B377CCF51D3AE598649656D4D74D210CDBC2B76209B16EAAFCB14D6F4D691"
    "20164885852AF1CEBB4D8602AD6755DFA7163645B4DB7926CD44D2DD9F840BFEF57F3DB0"
    "933C85EB6B0AAC20BC67E73F47B8DDBEC8EFAA64286EF1#)"
    "(protected openpgp-s2k3-sha1-aes-cbc "
    "("
    "(sha1  \"ü¿jy²üa4\" \"5242880\")"
    "#FF12BEE0B03F842349717AE1AB6D7AC2#)"
    "#95570487C8B5C49492D4E662259F2CF9B6D7E64F728F17A1FE1B2DA616E5976FE32861E"
    "C4B1F0DA03D9006C432CF2136871266E9444377ACEF04340B36B4550B5C1E4CC69AD4380"
    "A709FB0DAA5104A8B#)"
    "(protected-at \"20110720T142801\")"
    ")"
    "(comment sample_dsa_passphrase_is_abc)"
    ")",
    "2d:b1:70:1a:04:9e:41:a3:ce:27:a5:c7:22:fe:3a:a3"
  },
  { /* OpenSSH 6.7p1 generated key:  */
    "(protected-private-key "
    "(ecdsa "
    "(curve \"NIST P-256\")"
    "(q #041F17ED5E3D637181DFA68157270F94A46C089B6F5D4518564600551C0A60A063B3"
    "31EDE027A23CAB58A5BAD469600229DC8DED06380A92F86460ED400F963319#)"
    "(protected openpgp-s2k3-sha1-aes-cbc "
    "("
    "(sha1 #43F887516D94A502# \"20971520\")"
    "#B135DEDA02CF36F126BA661FB22A35CF#)"
    "#37E74BEC054B17723C106BA69214CFDA245512E40F4848ECF5719E3700002C940BC7EEC"
    "283537CA4D8779107E07F03AAA9FAF155BA9BF6286080C35EF72DDAAF303FD9069475B03"
    "C99D9FC93C58CD83A852964D2C7BFD1D803E2ECD1331937C3#)"
    "(protected-at \"20150922T071259\")"
    ")"
    "(comment \"ecdsa w/o comment\")"
    ")", /* Passphrase="abc" */
    "93:4f:08:02:7d:cb:16:9b:0c:39:21:4b:cf:28:5a:19"
  },
  { /* OpenSSH 6.7p1 generated key:  */
    "(protected-private-key "
    "(ecdsa "
    "(curve \"NIST P-384\") "
    "(q #04B6E747AC2F179F96088D1DB58EB8600BB23FAEF5F58EFE712A7478FB7BF735"
    "B015EA2DFBBA965D8C6EB135A2B9B9599D65BF0167D2DB6ABF00F641F0F5FC15A4C3"
    "EFE432DA331B7C8A66D6C4C2B0EBB5ED11A80301C4E57C1EBD25665CEBF123#)"
    "(protected openpgp-s2k3-sha1-aes-cbc "
    "("
    "(sha1 #3B13710B67D756EA# \"20971520\")"
    "#720599AC095BF1BD73ED72F49FB77BFA#)"
    "#F1A522F4533E3A6E40821D67CEA6C28A7FF07ACA4BEE81E0F39193B2E469E0C583D"
    "A42E0E2D52ADB5ACFAB9C4CA7F1C3556FD7FD2770717FB3CE7C59474A3E2A7AF3D93"
    "9EC01E067DAAA60D3D355D9BABCCD1F013E8637C555DDFA61F8FA5AFB010FF02979D"
    "35BBBEED71BFD8BB508F7#)"
    "(protected-at \"20150922T070806\")"
    ")"
    "(comment \"ecdsa w/o comment\")"
    ")", /* Passphrase="abc" */
    "a3:cb:44:c8:56:15:25:62:85:fd:e8:04:7a:26:dc:76"
  },
  { /* OpenSSH 6.7p1 generated key:  */
    "(protected-private-key "
    "(ecdsa "
    "(curve \"NIST P-521\")"
    "(q #04005E460058F37DB5ADA670040203C4D7E18D9FC8A7087165904A4E25EE5EEE"
    "3046406D922616DA7E71016A1CB9E57A45E3D3727D7C8DF0F11AE2BD75FAD3355CAA"
    "E1019D89D33CC77424E5DA233588207444FC9F67BBE428A9528B7DC77AF8261A1D45"
    "ACC1A657C99E361E93C1E5C0F214104C18807670F4CDC1E038B7C950FDBAAECB40#)"
    "(protected openpgp-s2k3-sha1-aes-cbc "
    "("
    "(sha1 #FB2E36984DE2E17C# \"19737600\")"
    "#85DB6445B37012F9A449E5AC0D5017E9#)"
    "#B4C7CCDFE9B5D32B31BA7C763B80485A62EBF34FD68D8E306DA75FD2BDDBABAA098"
    "9B51972BA3B731DA5261E0ADC3FAEF9BB4C8284C53D3E88E738AEF1490941903A5B2"
    "9F3747E83C4D80B6A89E0B7BDEE5C6638332F4AAEA5983F760B2887A43A1C4BE0564"
    "3F72C6943987D97FDAA7D9C235C6D31973A2400DA9BAB564A16EA#)"
    "(protected-at \"20150922T075611\")"
    ")"
    "(comment \"ecdsa w/o comment\")"
    ")", /* Passphrase="abc" */
    "1e:a6:94:ab:bd:81:73:5f:22:bc:0e:c7:89:f6:68:df"
  },
  { /* OpenSSH 6.7p1 generated key:  */
    "(protected-private-key "
    "(ecc "
    "(curve Ed25519)"
    "(flags eddsa)"
    "(q #40A3577AA7830C50EBC15B538E9505DB2F0D2FFCD57EA477DD83dcaea530f3c277#)"
    "(protected openpgp-s2k3-sha1-aes-cbc "
    "("
    "(sha1 #FA8123F1A37CBC1F# \"3812352\")"
    "#7671C7387E2DD931CC62C35CBBE08A28#)"
    "#75e928f4698172b61dffe9ef2ada1d3473f690f3879c5386e2717e5b2fa46884"
    "b189ee409827aab0ff37f62996e040b5fa7e75fc4d8152c8734e2e648dff90c9"
    "e8c3e39ea7485618d05c34b1b74ff59676e9a3d932245cc101b5904777a09f86#)"
    "(protected-at \"20150928T050210\")"
    ")"
    "(comment \"eddsa w/o comment\")"
    ")", /* Passphrase="abc" */
    "f1:fa:c8:a6:40:bb:b9:a1:65:d7:62:65:ac:26:78:0e"
  },
  {
    NULL,
    NULL
  }
};



static char *
read_file (const char *fname, size_t *r_length)
{
  FILE *fp;
  char *buf;
  size_t buflen;
  struct stat st;

  fp = fopen (fname, "rb");
  if (!fp)
    {
      fprintf (stderr, "%s:%d: can't open '%s': %s\n",
               __FILE__, __LINE__, fname, strerror (errno));
      exit (1);
    }

  if (fstat (fileno(fp), &st))
    {
      fprintf (stderr, "%s:%d: can't stat '%s': %s\n",
               __FILE__, __LINE__, fname, strerror (errno));
      exit (1);
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      fprintf (stderr, "%s:%d: error reading '%s': %s\n",
               __FILE__, __LINE__, fname, strerror (errno));
      exit (1);
    }
  fclose (fp);

  *r_length = buflen;
  return buf;
}


static gcry_sexp_t
read_key (const char *fname)
{
  gpg_error_t err;
  char *buf;
  size_t buflen;
  gcry_sexp_t key;

  buf = read_file (fname, &buflen);

  err = gcry_sexp_sscan (&key, NULL, buf, buflen);
  if (err)
    {
      fprintf (stderr, "%s:%d: gcry_sexp_sscan failed: %s\n",
               __FILE__, __LINE__, gpg_strerror (err));
      exit (1);                                 \
    }

  xfree (buf);
  return key;
}


int
main (int argc, char **argv)
{
  gpg_error_t err;
  gcry_sexp_t key;
  char *string;
  int idx;

  if (argc == 2)
    {
      key = read_key (argv[1]);
      err = ssh_get_fingerprint_string (key, &string);
      if (err)
        {
          fprintf (stderr, "%s:%d: error getting fingerprint: %s\n",
                   __FILE__, __LINE__, gpg_strerror (err));
          exit (1);
        }
      puts (string);
      xfree (string);
      gcry_sexp_release (key);
    }
  else
    {
      for (idx=0; sample_keys[idx].key; idx++)
        {
          err = gcry_sexp_sscan (&key, NULL, sample_keys[idx].key,
                                 strlen (sample_keys[idx].key));
          if (err)
            {
              fprintf (stderr, "%s:%d: gcry_sexp_sscan failed for "
                       "sample key %d: %s\n",
                       __FILE__, __LINE__, idx, gpg_strerror (err));
              exit (1);
            }

          err = ssh_get_fingerprint_string (key, &string);
          gcry_sexp_release (key);
          if (err)
            {
              fprintf (stderr, "%s:%d: error getting fingerprint for "
                       "sample key %d: %s\n",
                       __FILE__, __LINE__, idx, gpg_strerror (err));
              exit (1);
            }

          if (strcmp (string, sample_keys[idx].fpr))
            {
              fprintf (stderr, "%s:%d: fingerprint mismatch for "
                       "sample key %d\n",
                       __FILE__, __LINE__, idx);
              fprintf (stderr, "want: %s\n got: %s\n",
                       sample_keys[idx].fpr, string);
              exit (1);
            }
          xfree (string);
        }
    }

  return 0;
}
