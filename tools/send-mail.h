/* send-mail.h - Invoke sendmail or other delivery tool.
 * Copyright (C) 2016 g10 Code GmbH
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

#ifndef GNUPG_SEND_MAIL_H
#define GNUPG_SEND_MAIL_H

gpg_error_t send_mail (estream_t fp);
gpg_error_t send_mail_to_file (estream_t fp, const char *fname);


#endif /*GNUPG_SEND_MAIL_H*/
