/* Keyserver internals */

#ifndef _KEYSERVER_INTERNAL_H_
#define _KEYSERVER_INTERNAL_H_

#include <time.h>
#include "keyserver.h"
#include "iobuf.h"
#include "types.h"

void parse_keyserver_options(char *options);
int parse_keyserver_uri(char *uri,
			const char *configname,unsigned int configlineno);
int keyserver_export(STRLIST users);
int keyserver_import(STRLIST users);
int keyserver_import_fprint(const byte *fprint,size_t fprint_len);
int keyserver_import_keyid(u32 *keyid);
int keyserver_refresh(STRLIST users);
int keyserver_search(STRLIST tokens);
void keyserver_search_prompt(IOBUF buffer,int count,const char *searchstr);

#endif /* !_KEYSERVER_INTERNAL_H_ */
