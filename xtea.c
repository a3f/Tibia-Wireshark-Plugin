#include <glib.h>
#include "xtea.h"

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */

static void decipher(unsigned num_rounds, guint32 v[2], guint32 const key[4]) {
    unsigned i;
    guint32 v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void tibia_xtea_ecb_decrypt(guint32 *buf, size_t len, guint32 const key[4]) {
    size_t i;
    for (i = 0; i < len / 4; i+=2)
        decipher(32, &buf[i], key);
}


