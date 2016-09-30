# Tibia Wireshark Plugin

Tested working with 8.6, maybe works with more recent versions too. Currently RSA private keys need to be hardcoded in, and no way to specify a XTEA key exists.

If the dissector captures the symmetric key exchange, packets will be decoded correctly afterwards.

## TODO

- Add configuration dialog for selecting different RSA private keys
- Allow specifying a XTEA key directly.
- Test if it works with more up to date Tibia versions
- Remove XTEA/RSA/Adler32 decoding depending on client version
- Post about it somewhere (maybe even contribute it to Wireshark?)
