/* tofu.h - TOFU trust model.
 * Copyright (C) 2015 g10 Code GmbH
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

#ifndef G10_TOFU_H
#define G10_TOFU_H

#include <config.h>

/* For each binding, we have a trust policy.  */
enum tofu_policy
  {
    /* This value can be returned by tofu_get_policy to indicate that
       there is no policy set for the specified binding.  */
    TOFU_POLICY_NONE = 0,

    /* We made a default policy decision.  This is only done if there
       is no conflict with another binding (that is, the email address
       is not part of another known key).  The default policy is
       configurable (and specified using: --tofu-default-policy).

       Note: when using the default policy, we save TOFU_POLICY_AUTO
       with the binding, not the policy that was in effect.  This way,
       if the user invokes gpg again, but with a different value for
       --tofu-default-policy, a different decision is made.  */
    TOFU_POLICY_AUTO = 1,

    /* The user explicitly marked the binding as good.  In this case,
       we return TRUST_FULLY.  */
    TOFU_POLICY_GOOD = 2,

    /* The user explicitly marked the binding as unknown.  In this
       case, we return TRUST_UNKNOWN.  */
    TOFU_POLICY_UNKNOWN = 3,

    /* The user explicitly marked the binding as bad.  In this case,
       we always return TRUST_NEVER.  */
    TOFU_POLICY_BAD = 4,

    /* The user deferred a definitive policy decision about the
       binding (by selecting accept once or reject once).  The next
       time we see this binding, we should ask the user what to
       do.  */
    TOFU_POLICY_ASK = 5,


    /* Private value used only within tofu.c.  */
    _tofu_GET_POLICY_ERROR = 100
  };


/* Return a string representation of a trust policy.  Returns "???" if
   POLICY is not valid.  */
const char *tofu_policy_str (enum tofu_policy policy);

/* Convert a binding policy (e.g., TOFU_POLICY_BAD) to a trust level
   (e.g., TRUST_BAD) in light of the current configuration.  */
int tofu_policy_to_trust_level (enum tofu_policy policy);

/* Register the bindings <PK, USER_ID>, for each USER_ID in
   USER_ID_LIST, and the signature described by SIGS_DIGEST and
   SIG_TIME, which it generated.  Origin describes where the signed
   data came from, e.g., "email:claws" (default: "unknown").  Note:
   this function does not interact with the user, If there is a
   conflict, or if the binding's policy is ask, the actual interaction
   is deferred until tofu_get_validity is called.  Set the string
   list FLAG to indicate that a specified user id is expired.  This
   function returns 0 on success and an error code on failure.  */
gpg_error_t tofu_register_signature (ctrl_t ctrl, PKT_public_key *pk,
                                     strlist_t user_id_list,
                                     const byte *sigs_digest,
                                     int sigs_digest_len,
                                     time_t sig_time, const char *origin);

/* Note that an encrypted mail was sent to <PK, USER_ID>, for each
   USER_ID in USER_ID_LIST.  (If USER_ID_LIST is NULL, then all
   non-revoked user ids associated with PK are used.)  If MAY_ASK is
   set, then may interact with the user to resolve a TOFU
   conflict.  */
gpg_error_t tofu_register_encryption (ctrl_t ctrl,
                                      PKT_public_key *pk,
                                      strlist_t user_id_list,
                                      int may_ask);

/* Combine a trust level returned from the TOFU trust model with a
   trust level returned by the PGP trust model.  This is primarily of
   interest when the trust model is tofu+pgp (TM_TOFU_PGP).  */
int tofu_wot_trust_combine (int tofu, int wot);

/* Write a "tfs" record for a --with-colons listing.  */
gpg_error_t tofu_write_tfs_record (ctrl_t ctrl, estream_t fp,
                                   PKT_public_key *pk, const char *user_id);

/* Determine the validity (TRUST_NEVER, etc.) of the binding <PK,
   USER_ID>.  If MAY_ASK is 1, then this function may interact with
   the user.  If not, TRUST_UNKNOWN is returned if an interaction is
   required.  Set the string list FLAGS to indicate that a specified
   user id is expired.  If an error occurs, TRUST_UNDEFINED is
   returned.  */
int tofu_get_validity (ctrl_t ctrl,
                       PKT_public_key *pk, strlist_t user_id_list,
                       int may_ask);

/* Set the policy for all non-revoked user ids in the keyblock KB to
   POLICY.  */
gpg_error_t tofu_set_policy (ctrl_t ctrl, kbnode_t kb, enum tofu_policy policy);

/* Return the TOFU policy for the specified binding in *POLICY.  */
gpg_error_t tofu_get_policy (ctrl_t ctrl,
                             PKT_public_key *pk, PKT_user_id *user_id,
			     enum tofu_policy *policy);

/* When doing a lot of DB activities (in particular, when listing
   keys), this causes the DB to enter batch mode, which can
   significantly speed up operations.  */
void tofu_begin_batch_update (ctrl_t ctrl);
void tofu_end_batch_update (ctrl_t ctrl);

/* Release all of the resources associated with a DB meta-handle.  */
void tofu_closedbs (ctrl_t ctrl);

/* Whenever a key is modified (e.g., a user id is added or revoked, a
 * new signature, etc.), this function should be called to cause TOFU
 * to update its world view.  */
gpg_error_t tofu_notice_key_changed (ctrl_t ctrl, kbnode_t kb);

#endif /*G10_TOFU_H*/
