/* Photo ID functions */

#ifndef _PHOTOID_H_
#define _PHOTOID_H_

#include "packet.h"

PKT_user_id *generate_photo_id(PKT_public_key *pk);
int parse_image_header(const struct user_attribute *attr,byte *type,u32 *len);
char *image_type_to_string(byte type,int style);
void show_photos(const struct user_attribute *attrs,
		 int count,PKT_public_key *pk,PKT_secret_key *sk);

#endif /* !_PHOTOID_H_ */
