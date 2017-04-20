#ifndef TIBIA_XTEA_H_
#define TIBIA_XTEA_H_

#include <glib.h>
void tibia_xtea_ecb_decrypt(guint32 const key[restrict static 4], unsigned char buf[restrict static 8], size_t len);
#endif
