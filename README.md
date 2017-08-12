# Now Feature Complete! (and Repo no longer builds)

This dissector has been submitted as built-in dissector for [Wireshark Code Review](https://code.wireshark.org/review/#/c/23055/). Let's hope this becomes part of Wireshark v2.6.0. :-)

Some of the functionality necessary here has been proposed as changes to Wireshark utility libraries. Till these are merged, building this project will fail. Instead, just checkout and build the feature branch uploaded for code review:

```
git fetch ssh://a3f@code.wireshark.org:29418/wireshark refs/changes/55/23055/3 && git checkout FETCH_HEAD
```

## Tibia Wireshark Plugin

Tibia is a MMORPG developed by Cipsoft GmbH. OTServ is the open-source implementation of the game server.

This Wireshark dissector decodes the game's communication protocol. It supports all versions from Tibia 7.0 up to Tibia 11.42 (2001-2017). 

Newer versions of the protocol use RSA/XTEA in order to provide a secure communication channel. 
In order to dissect packets on these versions, the symmetric (XTEA) key need be provided manually via the preferences Dialog.
In case the private key is provided, Login packets will be decoded to acquire the XTEA key.
OTServ's private key is included by default, so decoding most OTServ traffic should work out of the box.

Game protocol support is quite incomplete, but it should be able to decrypt all Tibia packets from Tibia 7.00 up.

## Screenshot

![screenshot][macos-screenshot]

## Long Version

Tibia (https://tibia.com) is a Massively Multiplayer Online Role-Playing
Game (MMORPG) by Cipsoft GmbH.

Three official clients exist: The current Qt-based 11.0+ client,
the old C++ client used from Tibia 7.0 till 10.99 and the Flash client.
The latter two are being phased out. They use the same protocol,
except that the session key for the Flash client is transported alongside
the character list over HTTPS. It's possible this is done in the same manner
as in the native client from 10.74 up. We don't support the Flash client.

The dissector supports Tibia versions from 7.0 (2001) till current
11.42 (2017-08-12). Tibia has an active open source server emulator
community (OTServ) that still makes use of older versions and surpasses
the official servers in popularity, therefore compatibility with older
protocol iterations should be maintained.

Transport is over TCP, with recent versions encrypting player interaction
with XTEA. Authentication and key exchange is done with a hard-coded
RSA public key in the client.

Two protocols are dissected: The Tibia login protocol and the Tibia game
protocol. Traditionally, login servers were stateless and only responsible
for providing the addresses of the game servers alongside the character
list upon successful authentication. Then a new authentication request
(this time with character selection) is sent to the game server.
That way, a client who knows the game server address can very well skip
the login server entirely. Starting with 10.61, this is no longer possible,
as the login server provides a session key that needs to be sent to the
game server.

Starting with Tibia 7.61, login server requests can't be reliably
differentiated from game server requests. Therefore we apply some heuristics
to classify packets.

Packets from and to the game server contain commands. Commands are
identified by the first octet and are variable in length. The dissector has
most command names hard-coded. However, a complete implementation of the
game protocol is unlikely.

The RSA private key usually used by OTServ is hard-coded in. Server
administrators may add their own private key in PEM or PKCS#12 format over
an UAT. For servers where the private key is indeed private (like
for official servers), the symmetric XTEA key (retrievable by memory
peeking or MitM) may be provided to the dissector via UAT.

Unsurprisingly, no official specification of the protocol exist, following
resources have been written by the community:

- OTServ: Community effort to replicate a Tibia Server.
- Outcast: A Tibia client implementation of the game protocol as of 2006.
           Comes with a PDF spec written by Khaos
- TibiaAPI: Bot framework, containing a listing of commands as of 2009
- TFS: OTServ-Fork which is kept up-to-date with most of the official protocol
- otclient: Open Source implementation of an up-to-date Tibia client

An official slide set by Cipsoft detailing the architecture of Tibia
from Game Developers Conference Europe 2011 is also available:
http://www.gdcvault.com/play/1014908/Inside-Tibia-The-Technical-Infrastructure

The protocol, as implemented here, has been inferred from network footage
and game client execution traces and was written from scratch. Especially,
no code of Cipsoft GmbH was used.

Tibia is a registered trademark of Cipsoft GmbH.

[macos-screenshot]: https://github.com/a3f/Bowdlator/blob/master/screenshot.png

