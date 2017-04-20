/* rsa.h
 * RSA key handling
 * By Ahmad Fatoum <ahmad@a3f.at>
 * Copyright 2017 Ahmad Fatoum
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifndef __TINC_RSA_H__
#define __TINC_RSA_H__

#include <gcrypt.h>
#include <glib.h>

int pcry_private_decrypt2(const guint len, guchar* data, gcry_sexp_t pk, char **err);

extern void rsa_init(void);
extern void rsa_free(void);

#endif
