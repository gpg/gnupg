/* Photo ID functions */

#ifndef _PHOTOID_H_
#define _PHOTOID_H_

#include "packet.h"

PKT_user_id *generate_photo_id(PKT_public_key *pk);
void show_photo(const struct user_attribute *attr,PKT_public_key *pk);

#endif /* !_PHOTOID_H_ */
