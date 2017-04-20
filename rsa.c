/* rsa.c
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

#include <stdio.h>
#include <config.h>
#include "rsa.h"


static gcry_sexp_t otserv_key;
void old_rsa_init(void) {
    const char sexp[] = 
    "(private-key (rsa"
    "(n #9b646903b45b07ac956568d87353bd7165139dd7940703b03e6dd079399661b4a837aa60561d7ccb9452fa0080594909882ab5bca58a1a1b35f8b1059b72b1212611c6152ad3dbb3cfbee7adc142a75d3d75971509c321c5c24a5bd51fd460f01b4e15beb0de1930528a5d3f15c1e3cbf5c401d6777e10acaab33dbe8d5b7ff5#)"
    "(e #010001#)"
    "(d #428bd3b5346daf71a761106f71a43102f8c857d6549c54660bb6378b52b0261399de8ce648bac410e2ea4e0a1ced1fac2756331220ca6db7ad7b5d440b7828865856e7aa6d8f45837feee9b4a3a0aa21322a1e2ab75b1825e786cf81a28a8a09a1e28519db64ff9baf311e850c2bfa1fb7b08a056cc337f7df443761aefe8d81#)"
    "(p #91b37307abe12c05a1b78754746cda444177a784b035cbb96c945affdc022d21da4bd25a4eae259638153e9d73c97c89092096a459e5d16bcadd07fa9d504885#)"
    "(q #0111071b206bafb9c7a2287d7c8d17a42e32abee88dfe9520692b5439d9675817ff4f8c94a4abcd4b5f88e220f3a8658e39247a46c6983d85618fd891001a0acb1#)"
   "(u #6b21cd5e373fe462a22061b44a41fd01738a3892e0bd8728dbb5b5d86e7675235a469fea3266412fe9a659f486144c1e593d56eb3f6cfc7b2edb83ba8e95403a#)"
    "))";

    gcry_error_t err = gcry_sexp_new(&otserv_key, sexp, 0, 1);
    if (err) {
        //FIXME: Use expert info
        printf("%s:%d: %s@%s\n", __FILE__, __LINE__, gcry_strerror(err), gcry_strsource(err));
    }
}

void old_rsa_free(void) {
    gcry_sexp_release(otserv_key);
}

int pcry_private_decrypt2(const guint len, guchar *in, gcry_sexp_t key, char **err)
{
    gcry_error_t gerr;
    gcry_sexp_t payload, plain;
    const char *buf;
    size_t i, actual_size;
    *err = "shit";

    if (key == NULL)
        key = otserv_key;

    gerr = gcry_sexp_build(&payload, NULL, "(enc-val (rsa (a %b)))", (int)len, in);
    if (gerr) {
        //FIXME: Use expert info
        printf("%s:%d: %s@%s\n", __FILE__, __LINE__, gcry_strerror(gerr), gcry_strsource(gerr));
        return 0;
    }

    gerr = gcry_pk_decrypt(&plain, payload, key);
    gcry_sexp_release(payload);
    if (gerr) {
        printf("%s:%d: %s@%s\n", __FILE__, __LINE__, gcry_strerror(gerr), gcry_strsource(gerr));
        return 0;
    }

    if (!(buf = gcry_sexp_nth_data(plain, 0, &actual_size)))
    { /* handle properly */
        return 0;
    }

    (void)i;
#if 0
    for (i = 0; i < len - actual_size; i++)
        ret[i] = 0x00;
#endif

    memcpy(in, buf, actual_size);

    gcry_sexp_release(plain);

	return (guint)actual_size;
}

