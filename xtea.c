#include <stdint.h>
#include <stddef.h>
#include <xtea.h>
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                        \
  {                                                \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )        \
        | ( (uint32_t) (b)[(i) + 1] << 16 )        \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )        \
        | ( (uint32_t) (b)[(i) + 3]       );       \
  }
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                        \
  {                                                \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );  \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );  \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );  \
    (b)[(i) + 3] = (unsigned char) ( (n)       );  \
  }
#endif

#ifndef GET_ULONG_LE
#define GET_ULONG_LE(n,b,i)                        \
{                                                  \
    (n) = ( (uint32_t) (b)[(i)    ]       )        \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )        \
        | ( (uint32_t) (b)[(i) + 2] << 16 )        \
        | ( (uint32_t) (b)[(i) + 3] << 24 );       \
}
#endif

#ifndef PUT_ULONG_LE
#define PUT_ULONG_LE(n,b,i)                        \
{                                                  \
    (b)[(i)    ] = (unsigned char) ( (n)       );  \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );  \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );  \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );  \
}
#endif

void xtea_encipher(unsigned num_rounds,
                   unsigned char v[restrict static 8],
                   const guint32 key[restrict static 4]) {

    uint32_t v0, v1, sum = 0, delta = 0x9E3779B9;
	GET_ULONG_BE(v0, v, 0);
	GET_ULONG_BE(v1, v, 4);

    for (unsigned i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }

	PUT_ULONG_BE(v0, v, 0);
	PUT_ULONG_BE(v1, v, 4);
}

void xtea_decipher(unsigned num_rounds,
                             unsigned char v[restrict static 8],
                             const guint32 key[restrict static 4]) {
    uint32_t v0, v1, delta = 0x9E3779B9, sum = delta * num_rounds;
	GET_ULONG_BE(v0, v, 0);
	GET_ULONG_BE(v1, v, 4);

    for (unsigned i = 0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }

	PUT_ULONG_BE(v0, v, 0);
	PUT_ULONG_BE(v1, v, 4);
}

void xtea_le_encipher(unsigned num_rounds,
                      unsigned char v[restrict static 8],
                      const guint32 key[restrict static 4]) {

    uint32_t v0, v1, sum = 0, delta = 0x9E3779B9;
	GET_ULONG_LE(v0, v, 0);
	GET_ULONG_LE(v1, v, 4);

    for (unsigned i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }

	PUT_ULONG_LE(v0, v, 0);
	PUT_ULONG_LE(v1, v, 4);
}

static void xtea_le_decipher(unsigned num_rounds,
                             unsigned char v[restrict static 8],
                             const uint32_t key[restrict static 4]) {
    /* use uint32_t for key FIXME */
    uint32_t v0, v1, delta = 0x9E3779B9, sum = delta * num_rounds;
	GET_ULONG_LE(v0, v, 0);
	GET_ULONG_LE(v1, v, 4);

    for (unsigned i = 0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }

	PUT_ULONG_LE(v0, v, 0);
	PUT_ULONG_LE(v1, v, 4);
}

void tibia_xtea_ecb_decrypt(guint32 const key[restrict static 4], unsigned char buf[restrict static 8], size_t len) {
    for (size_t i = 0; i < len; i += 8)
        xtea_le_decipher(32, &buf[i], key);
}

#include <limits.h>
#if CHAR_BIT != 8
#error "This XTEA implementation requires 8-Bit chars"
#endif
