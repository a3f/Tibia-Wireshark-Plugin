#ifndef TIBIA_XTEA_H_
#define TIBIA_XTEA_H_

#include <glib.h>
void tibia_xtea_ecb_decrypt(guint32 *buf, size_t len, guint32 const key[4]);
#endif
