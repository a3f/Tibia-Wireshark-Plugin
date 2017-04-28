/* packet-tibia.c
 * Routines for Tibia/OTServ game protocol dissection
 * Copyright 2017, Ahmad Fatoum <ahmad[AT]a3f.at>
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


/* Tibia (https://tibia.com) is a Massively Multiplayer Online Role-Playing
 * Game by Cipsoft GmbH.
 *
 * It's transported over TCP, with recent versions encrypting player
 * interaction with XTEA. Authentication and key exchange is done with
 * a hard-coded RSA key in the client.
 * This dissector supports Tibia versions from 7.1 (2003) till current
 * 11.02 (2017-05-01). Tibia has an active open source server emulater
 * community (OTServ) that still makes use of old current versions and
 * surpasses the official servers in number of available servers and
 * total player number, therefore computability with older protocol
 * iterations is maintained.
 * 
 * The RSA private key usually used by OTServ is hard-coded in. Server
 * admins may add their own private key in PEM or PKCS#12 format over
 * the UAT. For servers where the private key is indeed private (like
 * for official servers), the symmetric XTEA key may be provided
 * to the dissector via UAT.
 * 
 * 
 * Tibia is a registered trademark by Cipsoft GmbH.
 */

#include "config.h"
#include <epan/packet.h>
#include <wsutil/adler32.h>
#include <epan/address.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/conversation.h>
#include <epan/value_string.h>
#include <epan/address.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/report_message.h>
#include <wsutil/xtea.h>
#include <wsutil/strtoi.h>
#include <wsutil/rsa.h>
#include <errno.h>

static gboolean try_otserv_key = TRUE;

/* User Access Tables */
struct rsakeys_assoc {
    char *ipaddr;
    char *port;
    char *keyfile;
    char *password;
};

static void *rsakeys_copy_cb(void *, const void *, size_t);
static void rsakeys_free_cb(void *);
static void rsa_parse_uat(void);
static gboolean rsakeys_uat_fld_password_chk_cb(void *, const char *, guint, const void *, const void *, char **);
static gboolean rsakeys_uat_fld_fileopen_chk_cb(void *, const char *, guint, const void *, const void *, char **);
static gboolean rsakeys_uat_fld_port_chk_cb(void *, const char *, guint, const void *, const void *, char **);
static gboolean rsakeys_uat_fld_ip_chk_cb(void *, const char *, guint, const void *, const void *, char **);

UAT_CSTRING_CB_DEF(rsakeylist_uats,  ipaddr,   struct rsakeys_assoc)
UAT_CSTRING_CB_DEF(rsakeylist_uats,  port,     struct rsakeys_assoc)
UAT_FILENAME_CB_DEF(rsakeylist_uats, keyfile,  struct rsakeys_assoc)
UAT_CSTRING_CB_DEF(rsakeylist_uats,  password, struct rsakeys_assoc)

#define XTEA_KEY_LEN 16

struct xteakeys_assoc {
    guint32 framenum;

    char *key;
};

static void *xteakeys_copy_cb(void *, const void *, size_t);
static void xteakeys_free_cb(void *);
static void xtea_parse_uat(void);
static gboolean xteakeys_uat_fld_key_chk_cb(void *, const char *, guint, const void *, const void *, char **);

UAT_DEC_CB_DEF(xteakeylist_uats, framenum, struct xteakeys_assoc)
UAT_CSTRING_CB_DEF(xteakeylist_uats, key, struct xteakeys_assoc)


static int decode_xtea = 1; /* FIXME remove this */

#define LOGIN_FLAG_GM 0x01

#define CHAR_FLAG_POISON     0x1
#define CHAR_FLAG_FIRE       0x2
#define CHAR_FLAG_ENERGY     0x4
#define CHAR_FLAG_DRUNK      0x8
#define CHAR_FLAG_MANASHIELD 0x10
#define CHAR_FLAG_PARALYZE   0x20
#define CHAR_FLAG_HASTE      0x40
#define CHAR_FLAG_BATTLE     0x80
#define CHAR_FLAG_WATER      0x100
#define CHAR_FLAG_FROZEN     0x200
#define CHAR_FLAG_DAZZLED    0x400
#define CHAR_FLAG_CURSED     0x800

/* Usually the login server is on 7171,
 * For OTServ, the gameserver often listens on the came IP/Port,
 * but occasionly on 7172. Offcial Tibia doesn't host login and
 * game servers on the same IP address
 */

static range_t ports = {
    1, {
        { 7171, 7172 }
    }
};

static gint proto_tibia = -1;
static uat_t *rsakeys_uat = NULL, *xteakeys_uat = NULL;
static struct rsakeys_assoc  *rsakeylist_uats = NULL;
static struct xteakeys_assoc *xteakeylist_uats = NULL;
static guint nrsakeys = 0, nxteakeys = 0;

static gint hf_len = -1;
static gint hf_adler32 = -1;
static gint hf_type = -1;
static gint hf_os = -1;
static gint hf_client_version = -1;
static gint hf_file_versions = -1;
static gint hf_file_version_spr = -1;
static gint hf_file_version_dat = -1;
static gint hf_file_version_pic = -1;
static gint hf_undecoded_rsa_data = -1;
static gint hf_undecoded_xtea_data = -1;
static gint hf_xtea_key = -1;
static gint hf_loginflags_gm = -1;
static gint hf_acc_name = -1;
static gint hf_char_name = -1;
static gint hf_acc_pass = -1;
static gint hf_char_name_convo = -1;
static gint hf_acc_pass_convo = -1;

static gint hf_client_info;
static gint hf_client_locale_id;
static gint hf_client_locale;
static gint hf_client_ram;
static gint hf_client_cpu;
static gint hf_client_clock;
static gint hf_client_clock2;
static gint hf_client_gpu;
static gint hf_client_vram;
static gint hf_client_resolution;

static gint hf_xtea_len = -1;
static gint hf_loginserv_command = -1;
static gint hf_gameserv_command = -1;
static gint hf_client_command = -1;

static gint hf_motd = -1;
static gint hf_dlg_error = -1;
static gint hf_dlg_info = -1;
static gint hf_charlist = -1;
static gint hf_charlist_length = -1;
static gint hf_charlist_entry_name = -1;
static gint hf_charlist_entry_world = -1;
static gint hf_charlist_entry_ip = -1;
static gint hf_charlist_entry_port = -1;
static gint hf_pacc_days = -1;
static gint hf_channel_id = -1;
static gint hf_channel_name = -1;
static gint hf_char_flag_poison = -1;
static gint hf_char_flag_fire = -1;
static gint hf_char_flag_energy = -1;
static gint hf_char_flag_drunk = -1;
static gint hf_char_flag_manashield = -1;
static gint hf_char_flag_paralyze = -1;
static gint hf_char_flag_haste = -1;
static gint hf_char_flag_battle = -1;
static gint hf_char_flag_water = -1;
static gint hf_char_flag_frozen = -1;
static gint hf_char_flag_dazzled = -1;
static gint hf_char_flag_cursed = -1;

static gint hf_chat_msg = -1;
static gint hf_speech_id = -1;


static gint ett_tibia = -1;
static gint ett_command = -1;
static gint ett_file_versions = -1;
static gint ett_client_info = -1;
static gint ett_charlist= -1;

struct rsakey {
    address addr;
    guint16 port;

    gcry_sexp_t privkey;
};
GHashTable *rsakeys, *xteakeys;

#define CONVO_ACTIVE            0x01
#define CONVO_PROTO_HAS_ADLER32 0x02
#define CONVO_PROTO_HAS_XTEA    0x04
#define CONVO_KNOWS_XTEA        0x08
#define CONVO_LOGINSERV         0x10
#define CONVO_PROTO_HAS_RSA     0x20
#define CONVO_PROTO_HAS_ACCNAME 0x40
#define CONVO_PROTO_HAS_HWINFO  0x80
#define CONVO_PROTO_HAS_GMBYTE  0x100

static unsigned version_get_flags(guint16 version) {
    unsigned flags = 0;
    flags |= CONVO_PROTO_HAS_GMBYTE;

    if (version >= 761)
        flags |= CONVO_PROTO_HAS_RSA | CONVO_PROTO_HAS_XTEA;
    if (version >= 830)
        flags |= CONVO_PROTO_HAS_ADLER32 | CONVO_PROTO_HAS_ACCNAME;
    if (version >= 842)
        flags |= CONVO_PROTO_HAS_HWINFO;

    return flags;
}
struct tibia_convo {
    guint16 version;
    guint32 xtea_key[XTEA_KEY_LEN / sizeof (guint32)];
    char *acc, *pass, *char_name;
    unsigned flags;
    guint16 clientport;
    guint16 servport;

    gcry_sexp_t privkey;
};

static struct tibia_convo *
tibia_get_convo(packet_info *pinfo)
{
    struct tibia_convo *convo;
    conversation_t * epan_conversation = find_or_create_conversation(pinfo);

    convo = (struct tibia_convo*)conversation_get_proto_data(epan_conversation, proto_tibia);

    if (!convo) {
        /*printf("creating conversation @%u\n", pinfo->num);*/
        struct rsakey rsa_key;
        convo = wmem_new(wmem_file_scope(), struct tibia_convo);
        convo->char_name = convo->acc = convo->pass = NULL;
        convo->version = 0;
        /* TODO there gotta be a cleaner way..*/
        if (pinfo->srcport >= 0xC000)
        {
            convo->clientport = pinfo->srcport;

            convo->servport = pinfo->destport;
            rsa_key.addr = pinfo->dst;
        } else {
            convo->clientport = pinfo->destport;

            convo->servport = pinfo->srcport;
            rsa_key.addr = pinfo->src;
        }
        rsa_key.port = convo->servport;
        convo->privkey = g_hash_table_lookup(rsakeys, &rsa_key);
        convo->flags = 0;

        conversation_add_proto_data(epan_conversation, proto_tibia, (void *)convo);
    }

    if (!(convo->flags & CONVO_KNOWS_XTEA)) {
        guint8 *xtea_key = g_hash_table_lookup(xteakeys, GUINT_TO_POINTER(pinfo->num));
        if (xtea_key) {
            memcpy(convo->xtea_key, xtea_key, XTEA_KEY_LEN);
            convo->flags |= CONVO_KNOWS_XTEA;
        }
    }

    return convo;
}

static gcry_sexp_t otserv_key;
static gcry_sexp_t
convo_get_privkey(struct tibia_convo *convo)
{
    return convo->privkey ? convo->privkey
         : try_otserv_key ? otserv_key
         : NULL;
}

enum {
    /* from TibiaAPI */
    C_GET_CHARLIST          = 0x1,
    C_LOGIN_CHAR            = 0xA,
    C_PING                  = 0x1E,

    C_AUTO_WALK             = 0x64,
    C_AUTO_WALK_CANCEL      = 0x69,
    C_GO_NORTH              = 0x65,
    C_GO_EAST               = 0x66,
    C_GO_SOUTH              = 0x67,
    C_GO_WEST               = 0x68,
    C_GO_NE                 = 0x6A,
    C_GO_SE                 = 0x6B,
    C_GO_SW                 = 0x6C,
    C_GO_NW                 = 0x6D,
    C_TURN_NORTH            = 0x6F,
    C_TURN_EAST             = 0x70,
    C_TURN_SOUTH            = 0x71,
    C_TURN_WEST             = 0x72,
    C_MOVE_ITEM             = 0x78,
    C_SHOP_BUY              = 0x7A,
    C_SHOP_SELL             = 0x7B,
    C_SHOP_CLOSE            = 0x7C,
    C_ITEM_USE              = 0x82,
    C_ITEM_USE_ON           = 0x83,
    C_ITEM_USE_BATTLELIST   = 0x84,
    C_ITEM_ROTATE           = 0x85,
    C_CONTAINER_CLOSE       = 0x87,
    C_CONTAINER_OPEN_PARENT = 0x88,
    C_LOOK_AT               = 0x8C,
    C_PLAYER_SPEECH         = 0x96,
    C_CHANNEL_LIST          = 0x97,
    C_CHANNEL_OPEN          = 0x98,
    C_CHANNEL_CLOSE         = 0x99,
    C_PRIVATE_CHANNEL_OPEN  = 0x9A,
    C_NPC_CHANNEL_CLOSE     = 0x9E,
    C_FIGHT_MODES           = 0xA0,
    C_ATTACK                = 0xA1,
    C_FOLLOW                = 0xA2,
    C_CANCEL_GO             = 0xBE,
    C_CONTAINER_UPDATE      = 0xCA,
    C_TILE_UPDATE           = 0xC9,
    C_VIP_ADD               = 0xDC,
    C_VIP_REMOVE            = 0xDD,
    C_SET_OUTFIT            = 0xD3
};
static const value_string from_client_packet_types[] = {
    { C_GET_CHARLIST,     "Charlist request" },
    { C_LOGIN_CHAR,       "Character login" },
    { C_PLAYER_SPEECH,    "Speech" },
    { C_PING,             "Pong" },

    { C_AUTO_WALK,        "Map walk" },
    { C_AUTO_WALK_CANCEL, "Map walk cancel" },
    { C_GO_NORTH,         "Go north"},
    { C_GO_EAST,          "Go east"},
    { C_GO_SOUTH,         "Go south"},
    { C_GO_WEST,          "Go west"},
    { C_GO_NE,            "Go north-east"},
    { C_GO_SE,            "Go south-east"},
    { C_GO_SW,            "Go south-west"},
    { C_GO_NW,            "Go north-west"},

    {  C_TURN_NORTH,      "Turn north" },
    {  C_TURN_EAST,       "Turn east" },
    {  C_TURN_SOUTH,      "Turn south" },
    {  C_TURN_WEST,       "Turn west" },
    {  C_MOVE_ITEM,       "Move item" },
    {  C_SHOP_BUY,        "Buy in shop" },
    {  C_SHOP_SELL,       "Sell in shop" },
    {  C_SHOP_CLOSE,      "Close shop" },
    {  C_ITEM_USE,        "Use item" },
    {  C_ITEM_USE_ON,     "Use item on" },

    { C_ITEM_USE_BATTLELIST,   "Use item on battlelist" },
    { C_ITEM_ROTATE,           "Rotate item" },
    { C_CONTAINER_CLOSE,       "Close container" },
    { C_CONTAINER_OPEN_PARENT, "Open parent container" },
    { C_LOOK_AT,               "Look at" },
    { C_CHANNEL_LIST,          "List channels" },
    { C_CHANNEL_OPEN,          "Open public channel" },
    { C_CHANNEL_CLOSE,         "close channel" },
    { C_PRIVATE_CHANNEL_OPEN,  "Open private channel" },
    { C_NPC_CHANNEL_CLOSE,     "Open NPC channel" },
    { C_FIGHT_MODES,           "Set fight modes" },
    { C_ATTACK,                "Attack" },
    { C_FOLLOW,                "Follow" },
    { C_CANCEL_GO,             "Cancel go" },
    { C_CONTAINER_UPDATE,      "Update container" },
    { C_TILE_UPDATE,           "Update tile" },
    { C_VIP_ADD,               "Add VIP" },
    { C_VIP_REMOVE,            "Remove VIP" },
    { C_SET_OUTFIT,            "Set outfit" },

    { 0, NULL }
};

enum { LOGINSERV_DLG_ERROR = 0x0A, LOGINSERV_DLG_MOTD = 0x14, LOGINSERV_DLG_CHARLIST = 0x64 };
static const value_string from_loginserv_packet_types[] = {
    { LOGINSERV_DLG_MOTD,     "MOTD" },
    { LOGINSERV_DLG_CHARLIST, "Charlist" },
    { LOGINSERV_DLG_ERROR,    "Error" },

    { 0, NULL }
};

enum {

    /* Credit to Khaos (OBJECT Networks) */
    S_MAPINIT = 0x0A,        /* Long playerCreatureId  Int unknownU16 (Byte reportBugs?) */
    S_GMACTIONS = 0x0B,      /* Used to be 32 unknown bytes, but with GMs removed it might
                                not be in use anymore */
    S_DLG_ERROR = 0x14,      /* String errorMessage */
    S_DLG_INFO = 0x15,
    S_TOOMANYPLAYERS = 0x16,
    S_PING = 0x1E,
    S_PLAYERLOC = 0x64,      /* Position pos */
    S_GONORTH = 0x65,      /* MapDescription (18,1) */
    S_GOEAST = 0x66,       /* MapDescription (1,14) */
    S_GOSOUTH = 0x67,      /* MapDescription (18,1) */
    S_GOWEST = 0x68,       /* MapDescription (1,14) */
    S_TILEUPDATE = 0x69,     /* Position pos TileDescription td */
    S_ADDITEM = 0x6a,        /* Position pos ThingDescription thing */
    S_REPLACEITEM = 0x6b,    /* Position pos  Byte stackpos ThingDescription thing */
    S_REMOVEITEM = 0x6c,     /* Position pos Byte stackpos */
    S_CREATURE_GO = 0x6D,
    S_CONTAINER = 0x6e,      /* Byte index  Short containerIcon  Byte slotCount ThingDescription item */
    S_CONTAINERCLOSE = 0x6f ,           /* Byte index */
    S_ADDITEMCONTAINER = 0x70 ,         /* Byte index ThingDescription itm */
    S_TRANSFORMITEMCONTAINER = 0x71 ,   /* Byte index Byte slot */
    S_REMOVEITEMCONTAINER = 0x72,       /* Byte index Byte slot */
    S_INVENTORYEMPTY = 0x78,    /* Byte invSlot */
    S_INVENTORYITEM = 0x79 ,    /* Byte invSlot ThingDescription itm */
    S_TRADEREQ = 0x7d ,         /* String otherperson Byte slotCount  ThingDescription itm */
    S_TRADEACK = 0x7e,          /* String otherperson Byte slotCount  ThingDescription itm */
    S_TRADECLOSE = 0x7f,
    S_LIGHTLEVEL = 0x82 ,       /* Byte lightlevel Byte lightcolor */
    S_MAGIC_EFFECT = 0x83,
    S_ANIMATEDTEXT = 0x84,      /* Position pos Byte color String message */
    S_DISTANCESHOT = 0x85,      /* Position pos1  Byte stackposition  Position pos2 */
    S_CREATURESQUARE = 0x86,    /* Long creatureid Byte squarecolor */
    S_CREATURELIGHT = 0x8d ,    /* Long creatureid Byte ?  Byte ? */
    S_CREATURE_HEALTH = 0x8C,
    S_SETOUTFIT = 0x8e,         /* Long creatureid Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType  // can extended look go here too? */
    S_CREATURESPEED = 0x8f,     /* YIKES! I didnt handle this! */
    S_TEXTWINDOW = 0x96,        /* Long windowId Byte icon  Byte maxlength String message */
    S_STATUSMSG = 0xA0,         /* Status status */
    S_SKILLS = 0xA1,            /* Skills skills */
    S_PLAYER_CONDITION = 0xA2,
    S_CANCELATTACK = 0xA3,
    S_SPEAK = 0xAA,
    S_CHANNELSDIALOG = 0xAB,    /* Byte channelCount  (Int channelId  String channelName) */
    S_CHANNEL_OPEN = 0xAC,
    S_OPENPRIV = 0xAD,          /* String playerName */
    S_TEXTMESSAGE = 0xB4,       /* Byte msgClass String string */
    S_CANCELWALK = 0xB5,        /* Byte direction */
    S_FLOORUP = 0xBE,           /* Advanced topic; read separate text */
    S_FLOORDOWN = 0xBF,         /* Advanced topic; read separate text */
    S_OUTFITLIST = 0xC8,        /* Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType Byte firstModel Byte lastModel */
    S_VIPADD = 0xD2,            /* Long guid String name Byte isOnline */
    S_VIPLOGIN = 0xD3,          /* Long guid */
    S_VIPLOGOUT = 0xD4          /* Long guid*/
};
static const value_string from_gameserv_packet_types[] = {

    { S_MAPINIT,        "Initialize map" },
    { S_GMACTIONS,      "GM actions" },
    { S_DLG_ERROR,      "Error" },
    { S_DLG_INFO,       "Info" },
    { S_TOOMANYPLAYERS, "Too many players" },
    { S_PING,           "Ping" },
    { S_PLAYERLOC,      "Set player location" },
    { S_GONORTH,        "Go north" },
    { S_GOEAST,         "Go east" },
    { S_GOSOUTH,        "Go south" },
    { S_GOWEST,         "Go west" },
    { S_TILEUPDATE,     "Update tile" },
    { S_ADDITEM,        "Add item" },
    { S_REPLACEITEM,    "Replace item" },
    { S_REMOVEITEM,     "Remove item" },
    { S_CREATURE_GO,    "Creature goes" },
    { S_CONTAINER,      "Open container" },
    { S_CONTAINERCLOSE, "Close container" },

    { S_ADDITEMCONTAINER,       "Add item in container" },
    { S_TRANSFORMITEMCONTAINER, "Transform item in container" },
    { S_REMOVEITEMCONTAINER,    "Remove item in container" },

    { S_INVENTORYEMPTY,   "Inventory empty" },
    { S_INVENTORYITEM,    "Inventory item" },
    { S_TRADEREQ,         "Trade request" },
    { S_TRADEACK,         "Trade acknowledge" },
    { S_TRADECLOSE,       "Trade over" },
    { S_LIGHTLEVEL,       "Light level" },
    { S_MAGIC_EFFECT,     "Magic effect" },
    { S_ANIMATEDTEXT,     "Animated text" },
    { S_DISTANCESHOT,     "Distance shot" },
    { S_CREATURESQUARE,   "Creature square" },
    { S_CREATURELIGHT,    "Creature light" },
    { S_CREATURE_HEALTH,  "Creature Health" },
    { S_SETOUTFIT,        "Set outfit" },
    { S_CREATURESPEED,    "Set creature speed" },
    { S_TEXTWINDOW,       "Text window" },
    { S_STATUSMSG,        "Status message" },
    { S_SKILLS,           "Skills" },
    { S_PLAYER_CONDITION, "Player condition" },
    { S_CANCELATTACK,     "Cancel attack" },
    { S_SPEAK,            "Creature speech" },
    { S_CHANNELSDIALOG,   "Channels dialog" },
    { S_CHANNEL_OPEN,     "Channel open" },
    { S_OPENPRIV,         "Private channel open" },
    { S_TEXTMESSAGE,      "Text message" },
    { S_CANCELWALK,       "Cancel walk" },
    { S_FLOORUP,          "Floor +1" },
    { S_FLOORDOWN,        "Floor -1" },
    { S_OUTFITLIST,       "Outfit list" },
    { S_VIPADD,           "Add VIP" },
    { S_VIPLOGIN,         "VIP login" },
    { S_VIPLOGOUT,        "VIP logout" },

    { 0, NULL }
};

static guint16 version_from_charlist_request_packet(const guint8 *buf, size_t len) {
    /* credits go to tulio150 on tpforums.org */
    switch (len) {
        case 149: return 830 * (buf[6] == C_GET_CHARLIST);
        case 145: return 761 * (buf[2] == C_GET_CHARLIST);
        default:
                  if (23 <= len && len <= 52) return 700 * (buf[2] == C_GET_CHARLIST);
    }
    return 0;
}

static guint16 version_from_game_login_packet(const guint8 *buf, size_t len) {
    /* credits go to tulio150 on tpforums.org */
    switch (len) {
        case 137: return 830 * (buf[6] == C_LOGIN_CHAR);
        case 133: return 761 * (buf[2] == C_LOGIN_CHAR);
        default:
                  if (23 <= len && len <= 52) return 700 * (buf[2] == C_GET_CHARLIST);
    }
    return 0;
}

static int tibia_dissect_loginserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, packet_info *pinfo, proto_tree *mytree);
static int tibia_dissect_gameserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, packet_info *pinfo, proto_tree *mytree);
static int tibia_dissect_client_packet(struct tibia_convo *convo, tvbuff_t *tvb, packet_info *prinfo, proto_tree *mytree);

static void wmem_free_null(void *buf) { wmem_free(NULL, buf); }

static int
dissect_tibia(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* unknown)
{
    struct tibia_convo *convo;
    enum { GET_CHARLIST, CHAR_LOGIN, PING, GAME_PACKET } kind = GAME_PACKET; 
    static char *kinds[] = {"GET_CHARLIST", "CHAR_LOGIN", "PING", "GAME_PACKET"};
    tvbuff_t *tvb_decrypted;
    int offset = 0, len = 0;
    proto_tree *mytree = NULL, *subtree = NULL;
    proto_item *ti = NULL, *subti = NULL;
    guint16 plen = tvb_get_guint16(tvb, 0, ENC_LITTLE_ENDIAN);
    guint16 loginserv_protover, gameserv_protover;
    (void)unknown; (void)len;

    /*FIXME: if announced length != real length it's not a tibia packet?*/
    if (tvb_captured_length_remaining(tvb, 2) != plen)
        return -1;

    convo = tibia_get_convo(pinfo);

    if (!convo->version) {
        guint32 a32 = tvb_get_guint32(tvb, 2, ENC_LITTLE_ENDIAN);
        gint a32len = tvb_captured_length_remaining(tvb, 6);
        if (a32 == adler32_bytes(tvb_get_ptr(tvb, 6, a32len), a32len))
            convo->flags |= CONVO_PROTO_HAS_ADLER32;
    }
    /* we dont need the rest */

    loginserv_protover = version_from_charlist_request_packet(tvb_get_ptr(tvb, 0, plen), plen);
    gameserv_protover = version_from_game_login_packet(tvb_get_ptr(tvb, 0, plen), plen);
    /*printf("gserv_proto: %d lserv_proto %d\n", gameserv_protover, loginserv_protover);*/
    if (loginserv_protover && !gameserv_protover) {
        kind = GET_CHARLIST;
        convo->flags |= CONVO_LOGINSERV;
        if (!convo->version)
            convo->flags |= version_get_flags(convo->version = loginserv_protover);
    }
    else if (gameserv_protover && !loginserv_protover) {
        kind = CHAR_LOGIN;
        if (!convo->version)
            convo->flags |= version_get_flags(convo->version = gameserv_protover);
    }

    if (convo->flags & CONVO_LOGINSERV)
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Tibia login");
    else if (pinfo->srcport == convo->servport)
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Tibia server");
    else
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Tibia client");

    /* Clear out stuff in the info column */
    /*col_clear(pinfo->cinfo,COL_INFO);*/
    /*col_add_fstr(pinfo->cinfo, COL_INFO, "%s", kinds[kind]);*/

    (void)kinds;
    /* Charlist packets contains addresses that use the same RSA key, so it's
     * beneficial to dissect loginserver communication fully in the first pass
     */
    if (!tree && !(convo->flags & CONVO_LOGINSERV))
        return offset;

    ti = proto_tree_add_item(tree, proto_tibia, tvb, 0, -1, ENC_NA);
    mytree = proto_item_add_subtree(ti, ett_tibia);

    if (convo->char_name) {
        ti = proto_tree_add_string(mytree, hf_acc_name, tvb, offset, 0, convo->acc);
        PROTO_ITEM_SET_GENERATED(ti);

        ti = proto_tree_add_string(mytree, hf_acc_pass_convo, tvb, offset, 0, convo->pass);
        PROTO_ITEM_SET_GENERATED(ti);

        ti = proto_tree_add_string(mytree, hf_char_name_convo, tvb, offset, 0, convo->char_name);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    proto_tree_add_item(mytree, hf_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (convo->flags & CONVO_PROTO_HAS_ADLER32) {
        proto_tree_add_item(mytree, hf_adler32, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    switch (kind) {
        default:

            if (((convo->flags & CONVO_PROTO_HAS_XTEA) && !(convo->flags & CONVO_KNOWS_XTEA)) || !decode_xtea)
            {
                proto_tree_add_item(mytree, hf_undecoded_xtea_data, tvb, offset, plen - offset, ENC_NA);
                return offset;
            }

            ti = proto_tree_add_bytes_with_length(mytree, hf_xtea_key, tvb, 0, 1, (guint8*)convo->xtea_key, XTEA_KEY_LEN);
            PROTO_ITEM_SET_GENERATED(ti);

            /* FIXME: add expert info for XTEA failure */

            tvb_decrypted = tvb;
            len = tvb_captured_length_remaining(tvb, offset);
            if (convo->flags & CONVO_PROTO_HAS_XTEA) {
                guint32 *decrypted_buffer;
                int end = offset + len;
                guint32 *dstblock;
                len = tvb_captured_length_remaining(tvb, offset);
                if (len % 8 != 0)
                    return -1;
                /* copying and then overwriting might seem a waste at first
                 * but it's required as not to break strict aliasing */
                decrypted_buffer = (guint32*)g_malloc(len);

                for (dstblock = decrypted_buffer; offset < end; offset += 2*sizeof(guint32)) {
                    decrypt_xtea_le_ecb(dstblock, tvb_get_ptr(tvb, offset, 2*sizeof(guint32)), convo->xtea_key, 32);
                    dstblock += 2;
                }

                /*TODO: check if failure*/
                tvb_decrypted = tvb_new_child_real_data(tvb, (guint8*)decrypted_buffer, len, len);
                tvb_set_free_cb(tvb_decrypted, g_free);
                add_new_data_source(pinfo, tvb_decrypted, "Decrypted Game Data");
            }

            if (pinfo->srcport == convo->servport && (convo->flags & CONVO_LOGINSERV)) {
                return tibia_dissect_loginserv_packet(convo, tvb_decrypted, pinfo, mytree);
            } else if (pinfo->srcport == convo->servport) {
                return tibia_dissect_gameserv_packet(convo, tvb_decrypted, pinfo, mytree);
            } else {
                return tibia_dissect_client_packet(convo, tvb_decrypted, pinfo, mytree);
            }
        case GET_CHARLIST:
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "Tibia Login");
            convo->flags |= CONVO_LOGINSERV;
        case CHAR_LOGIN:
            {
                gcry_sexp_t privkey = convo_get_privkey(convo);

                proto_tree_add_item(mytree, hf_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
                proto_tree_add_item(mytree, hf_os, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                convo->version = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
                convo->flags |= version_get_flags(convo->version);
                proto_tree_add_item(mytree, hf_client_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                if (kind == GET_CHARLIST) {
                    subti = proto_tree_add_item(mytree, hf_file_versions, tvb, offset, 12, ENC_NA);
                    subtree = proto_item_add_subtree(subti, ett_file_versions);
                    proto_tree_add_item(subtree, hf_file_version_spr, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(subtree, hf_file_version_dat, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(subtree, hf_file_version_pic, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                }

                if (!privkey)
                {
                    proto_tree_add_item(mytree, hf_undecoded_rsa_data, tvb,
                            offset, plen - offset, ENC_NA);
                    return offset;
                }

                /* assume OTServ communication */
                /* (TODO: if it fails, mark TCP communication as non-OTServ (or nah it's just once) */
                {
                    char *err = NULL;
                    /* FIXME USE WS_MALLOC */
                    gint ciphertext_len = tvb_captured_length_remaining(tvb, offset);
                    gint plaintext_len;
                    guint8 *ciphertext = tvb_memdup(NULL, tvb, offset, ciphertext_len);

                    /*TODO: check if failure , FIXME: remove tvb_get_ptr*/

                    if (!(plaintext_len = pcry_private_decrypt(ciphertext_len, ciphertext, privkey, FALSE, &err))) {
                        printf("FAIL: %s!\n", err);
                        /*g_free(err);*/
                        return -1;
                    }
                    tvb_decrypted = tvb_new_child_real_data(tvb, ciphertext, plaintext_len, plaintext_len);
                    tvb_set_free_cb(tvb_decrypted, wmem_free_null);
                    add_new_data_source(pinfo, tvb_decrypted, "Decrypted Login Data");
                }
                offset = 0;

                /* TODO: correct? */


                tvb_memcpy(tvb_decrypted, convo->xtea_key, offset, XTEA_KEY_LEN);
                proto_tree_add_item(mytree, hf_xtea_key, tvb_decrypted, offset, XTEA_KEY_LEN, ENC_BIG_ENDIAN);
                offset += XTEA_KEY_LEN;
                convo->flags |= CONVO_KNOWS_XTEA;

                if (!mytree)
                    return offset;

                if ((convo->flags & CONVO_PROTO_HAS_GMBYTE) && kind == CHAR_LOGIN) {
                    proto_tree_add_item(mytree, hf_loginflags_gm, tvb_decrypted, offset, 1, ENC_NA);
                    offset += 1;
                }
                if (convo->flags & CONVO_PROTO_HAS_ACCNAME) {
                    guint16 acclen = tvb_get_guint16(tvb_decrypted, offset, ENC_LITTLE_ENDIAN);
                    if (offset + acclen + 2 > plen) return -1;
                    if (convo) {
                        convo->acc = (char*)tvb_memdup(wmem_file_scope(), tvb_decrypted, offset + 2, acclen + 1);
                        convo->acc[acclen] = '\0';
                    }
                    proto_tree_add_string_format_value(mytree, hf_acc_name, tvb_decrypted, offset, 2 + acclen, NULL, "%.*s", acclen, tvb_get_ptr(tvb_decrypted, offset + 2, acclen));
                    offset += 2 + acclen;
                } else /* account number */ {
                    /*proto_tree_add_item(mytree, hf_acc_name, tvb_decrypted, offset, 4,  ENC_LITTLE_ENDIAN);*/
                    guint32 accnum = tvb_get_guint32(tvb_decrypted, offset, ENC_LITTLE_ENDIAN);
                    if (convo) {
                        convo->acc = wmem_strdup_printf(wmem_file_scope(), "%lu", (unsigned long)accnum);
                    }
                    proto_tree_add_string_format_value(mytree, hf_acc_name, tvb_decrypted, offset, 4, NULL, "%lu", (unsigned long)accnum); 
                    offset += 4;

                }

                if (kind == CHAR_LOGIN) {
                    len = tvb_get_guint16(tvb_decrypted, offset, ENC_LITTLE_ENDIAN);
                    if (convo) {
                        convo->char_name = (char*)tvb_memdup(wmem_file_scope(), tvb_decrypted, offset + 2, len + 1);
                        convo->char_name[len] = '\0';
                    }

                    proto_tree_add_item(mytree, hf_char_name, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
                    offset += len + 2;
                }

                len = tvb_get_guint16(tvb_decrypted, offset, ENC_LITTLE_ENDIAN);
                if (convo)
                {
                    convo->pass = (char*)tvb_memdup(wmem_file_scope(), tvb_decrypted, offset + 2, len + 1);
                    convo->pass[len] = '\0';
                }
                proto_tree_add_item(mytree, hf_acc_pass, tvb_decrypted, offset, 2,  ENC_LITTLE_ENDIAN | ENC_ASCII);
                offset += len + 2;

                if (kind == GET_CHARLIST)
                {
                    proto_item *item, *cpu;
                    proto_tree *infotree;
                    guint16 clock1, clock2;

                    item = proto_tree_add_item(mytree, hf_client_info, tvb_decrypted, offset, 47, ENC_NA);
                    infotree = proto_item_add_subtree(item, ett_client_info);

                    item = proto_tree_add_item(infotree, hf_client_locale_id, tvb_decrypted, offset, 1, ENC_NA);
                    offset += 1;
                    PROTO_ITEM_SET_HIDDEN(item);

                    item = proto_tree_add_item(infotree, hf_client_locale, tvb_decrypted, offset, 3, ENC_ASCII);
                    proto_item_append_text(item, " (0x%X)", tvb_get_guint8(tvb_decrypted, offset-1));
                    offset += 3;

                    proto_tree_add_item(infotree, hf_client_ram, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    call_data_dissector(tvb_new_subset_length(tvb_decrypted, offset, 6), pinfo, infotree);
                    offset += 6;

                    cpu = proto_tree_add_item(infotree, hf_client_cpu, tvb_decrypted, offset, 9, ENC_ASCII);
                    offset += 9;

                    call_data_dissector(tvb_new_subset_length(tvb_decrypted, offset, 2), pinfo, infotree);
                    offset += 2;

                    clock1 = tvb_get_letohs(tvb_decrypted, offset);
                    item = proto_tree_add_item(infotree, hf_client_clock, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN);
                    PROTO_ITEM_SET_HIDDEN(item);
                    offset += 2;

                    clock2 = tvb_get_letohs(tvb_decrypted, offset);
                    item = proto_tree_add_item(infotree, hf_client_clock2, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN);
                    PROTO_ITEM_SET_HIDDEN(item);
                    offset += 2;

                    proto_item_append_text(cpu, " (%uMhz/%uMhz)", clock2, clock1);



                    call_data_dissector(tvb_new_subset_length(tvb_decrypted, offset, 4), pinfo, infotree);
                    offset += 4;

                    proto_tree_add_item(infotree, hf_client_gpu, tvb_decrypted, offset, 9, ENC_ASCII);
                    offset += 9;

                    item = proto_tree_add_item(infotree, hf_client_vram, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, "MB");
                    offset += 2;

                    item = proto_tree_add_string_format_value(infotree, hf_client_resolution, tvb_decrypted, offset, 5, NULL, "%ux%u @ %uHz",
                            tvb_get_letohs(tvb_decrypted, offset),
                            tvb_get_letohs(tvb_decrypted, offset+2),
                            tvb_get_guint8(tvb_decrypted, offset+4));
                    offset += 5;

                }
            }
    }

    return offset;
}


static int tibia_dissect_loginserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, packet_info *pinfo, proto_tree *mytree)
{
    int offset = 0;
    guint8 cmd;
    guint16 len;
    proto_tree *cmdtree;
    proto_item *subti;
    const char *str;
    (void)convo;(void)pinfo;
    proto_tree_add_item(mytree, hf_xtea_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) + 2;
    if (len > tvb_captured_length_remaining(tvb, offset))
        return -1;
    offset += 2;

    while (offset < len) {
        subti = proto_tree_add_item(mytree, hf_loginserv_command, tvb, offset, 1, ENC_NA);
        cmdtree = proto_item_add_subtree(subti, ett_command);

        switch (cmd = tvb_get_guint8(tvb, offset++)) {
            case LOGINSERV_DLG_ERROR:
            case LOGINSERV_DLG_MOTD:
                {
                    guint16 dlg_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(cmdtree, cmd == LOGINSERV_DLG_MOTD ? hf_motd : hf_dlg_error, tvb, offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
                    offset += dlg_len + 2;
                }
                break;
            case LOGINSERV_DLG_CHARLIST:
                {
                    guint8 char_count = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(cmdtree, hf_charlist_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset++;
                    subti = proto_tree_add_item(cmdtree, hf_charlist, tvb, offset, len - offset - 1, ENC_NA);
                    if (char_count) {
                        proto_tree *subtree = proto_item_add_subtree(subti, ett_charlist);
                        while (char_count --> 0) {
#define tmp_entry (*entry)
                            /*struct rsakey tmp_entry;*/
                            const guint8 *addr;
                                struct rsakey *entry = g_new(struct rsakey, 1);
                            

                            proto_tree_add_item(subtree, hf_charlist_entry_name, tvb, offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
                            offset += tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) + 2;
                            proto_tree_add_item(subtree, hf_charlist_entry_world, tvb, offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
                            offset += tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) + 2;

                            addr = tvb_get_ptr(tvb, offset, 4);
                            alloc_address_tvb(NULL, &tmp_entry.addr, AT_IPv4, 4, tvb, offset);
                            proto_tree_add_item(subtree, hf_charlist_entry_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            

                            tmp_entry.port = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(subtree, hf_charlist_entry_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                            offset += 2;



                            if (!g_hash_table_contains(rsakeys, &tmp_entry)) {
                                /*struct rsakey *entry = g_new(struct rsakey, 1);*/
                                *entry = tmp_entry;
                                entry->privkey = convo->privkey;
#if 0
                                printf("adding IP @%u: %u.%u.%u.%u:%u\n",
                                        pinfo->num,
                                        ((char*)entry->addr.data)[0],
                                        ((char*)entry->addr.data)[1],
                                        ((char*)entry->addr.data)[2],
                                        ((char*)entry->addr.data)[3],
                                        tmp_entry.port
                                      );
#endif

                                g_hash_table_insert(rsakeys, entry, entry->privkey);
                            }
                        }
                    }

                    proto_tree_add_item(cmdtree, hf_pacc_days, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;
                }
            default:
                if (len != offset)
                    call_data_dissector(tvb_new_subset_length(tvb, offset, len - offset), pinfo, cmdtree);

                offset = len;
        }
        proto_item_set_end(cmdtree, tvb, offset);

        str = try_val_to_str(cmd, from_loginserv_packet_types);
        str = str ? str : "Unknown";

        /*TODO: this only shows last packet, should show a csv*/
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%x)", str, cmd);
    }


    return offset;
}

static void dump_table_entry(gpointer key_, gpointer value _U_, gpointer user_data _U_) {
    struct rsakey *key = (struct rsakey*)key_;
    guint8 *addr = (guint8*)key->addr.data;

    printf("IP: %u.%u.%u.%u:%u\n",
            addr[0],
            addr[1],
            addr[2],
            addr[3],
            key->port
      );

}

void dump_table(void) {
    g_hash_table_foreach(rsakeys, dump_table_entry, NULL);
}


static int tibia_dissect_gameserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, packet_info *pinfo, proto_tree *mytree)
{
    int offset = 0;
    guint8 cmd;
    guint16 len, clen;
    proto_tree *subtree, *cmdtree;
    proto_item *subti;
    const char *str;
    (void)convo; (void) subtree; (void)subti;

    proto_tree_add_item(mytree, hf_xtea_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) + 2;
    if (len > tvb_captured_length_remaining(tvb, offset))
        return -1;
    offset += 2;

    while (offset < len) {
        subti = proto_tree_add_item(mytree, hf_gameserv_command, tvb, offset, 1, ENC_NA);
        cmdtree = proto_item_add_subtree(subti, ett_command);

        switch (cmd = tvb_get_guint8(tvb, offset++)) {
            case S_DLG_ERROR:
            case S_DLG_INFO:
                clen = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) + 2;
                proto_tree_add_item(cmdtree, cmd == S_DLG_ERROR ? hf_dlg_error : hf_dlg_info, tvb, offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
                offset += clen;
                break;
            case S_CHANNEL_OPEN:
                clen = tvb_get_guint16(tvb, offset+2, ENC_LITTLE_ENDIAN) + 2;
                proto_tree_add_item(cmdtree, hf_channel_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(cmdtree, hf_channel_name, tvb, offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
                offset += clen;
                break;
            case S_PLAYER_CONDITION:
                proto_tree_add_item(cmdtree, hf_char_flag_poison, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_fire, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_energy, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_drunk, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_manashield, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_paralyze, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_haste, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_battle, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_water, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_frozen, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_dazzled, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(cmdtree, hf_char_flag_cursed, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case S_PING:
                break;
            default:
                call_data_dissector(tvb_new_subset_length(tvb, offset, len - offset), pinfo, cmdtree);

                offset = len;
        }
        proto_item_set_end(cmdtree, tvb, offset);

        str = try_val_to_str(cmd, from_gameserv_packet_types);
        str = str ? str : "Unknown";
        /* TODO: show packet hex id only on unknown packets */
        /*TODO: this only shows last packet, should show a csv*/
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%x)", str, cmd);
    }


    return offset;
}

static int tibia_dissect_client_packet(struct tibia_convo *convo, tvbuff_t *tvb, packet_info *pinfo, proto_tree *mytree)
{
    int offset = 0;
    guint8 cmd;
    guint16 len, clen;
    proto_tree *subtree, *cmdtree;
    proto_item *subti;
    const char *str;
    (void)convo; (void) subtree; (void)subti;

    proto_tree_add_item(mytree, hf_xtea_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) + 2;
    if (len > tvb_captured_length_remaining(tvb, offset))
        return -1;
    offset += 2;

    while (offset < len) {
        subti = proto_tree_add_item(mytree, hf_client_command, tvb, offset, 1, ENC_NA);
        cmdtree = proto_item_add_subtree(subti, ett_command);

        switch (cmd = tvb_get_guint8(tvb, offset++)) {
            /*case C_MOVE_ITEM:*/
            case C_PLAYER_SPEECH:
                clen = tvb_get_guint16(tvb, offset+2, ENC_LITTLE_ENDIAN) + 2;
                proto_tree_add_item(cmdtree, hf_speech_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
                proto_tree_add_item(cmdtree, hf_chat_msg, tvb, offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
                offset += clen;
                break;
            case S_PING:
                break;
            default:
                call_data_dissector(tvb_new_subset_length(tvb, offset, len - offset), pinfo, cmdtree);
                offset = len;
        }
        proto_item_set_end(cmdtree, tvb, offset);

        str = try_val_to_str(cmd, from_client_packet_types);
        str = str ? str : "Unknown";
        /*TODO: this only shows last packet, should show a csv*/
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%x)", str, cmd);
    }


    return offset;
}

static const value_string operating_systems[] = {
    { 2, "Windows" },
    { 0, NULL }
};
static const value_string speech_ids[] = {
    { 1, "Say" },
    { 2, "Whisper" },
    { 3, "Yell" },
    { 0, NULL }
};

static guint rsakey_hash(gconstpointer _rsakey)
{
    const struct rsakey *rsakey = (const struct rsakey *)_rsakey;
    return add_address_to_hash(rsakey->port, &rsakey->addr);
}

static gboolean rsakey_equal(gconstpointer _a, gconstpointer _b)
{
    const struct rsakey *a = (const struct rsakey *)_a,
                           *b = (const struct rsakey *)_b;
    return a->port == b->port && addresses_equal(&a->addr, &b->addr);
}
static void rsakey_free(void *_rsakey)
{
    /*return; // FIXME: crashes*/
    struct rsakey *rsakey = (struct rsakey *)_rsakey;

    /*gcry_sexp_release(rsakey->privkey);*/ // FIXME: private key may be shared
    free_address_wmem(NULL, &rsakey->addr);
    g_free(_rsakey);
}

void proto_reg_handoff_tibia(void);

void
proto_register_tibia(void)
{
    static hf_register_info hf[] = {
        { &hf_len,
            { "Packet length", "tibia.len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_adler32,
            { "Adler32 checksum", "tibia.checksum",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_type,
            { "Packet type", "tibia.type",
                FT_UINT8, BASE_HEX,
                VALS(from_client_packet_types), 0x0,
                NULL, HFILL }
        },
        { &hf_os,
            { "Operating system", "tibia.os",
                FT_UINT16, BASE_HEX,
                VALS(operating_systems), 0x0,
                NULL, HFILL }
        },
        { &hf_client_version,
            { "Client version", "tibia.version",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_file_versions,
            { "File versions", "tibia.version.files",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_file_version_spr,
            { "Tibia.spr version", "tibia.version.spr",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_file_version_dat,
            { "Tibia.dat version", "tibia.version.dat",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_file_version_pic,
            { "Tibia.pic version", "tibia.version.pic",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_undecoded_rsa_data,
            { "RSA Encrypted login data", "tibia.rsa_data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_undecoded_xtea_data,
            { "XTEA Encrypted game data", "tibia.xtea_data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_xtea_key,
            { "Symmetric key (XTEA)", "tibia.xtea",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_loginflags_gm,
            { "Gamemaster", "tibia.login.flags.gm",
                FT_BOOLEAN, 8,
                NULL, LOGIN_FLAG_GM,
                NULL, HFILL }
        },
        { &hf_char_flag_poison,
            { "Poison", "tibia.flag.poison",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_POISON,
                NULL, HFILL }
        },
        { &hf_char_flag_fire,
            { "Fire", "tibia.flag.fire",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_FIRE,
                NULL, HFILL }
        },
        { &hf_char_flag_energy,
            { "Energy", "tibia.flag.energy",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_ENERGY,
                NULL, HFILL }
        },
        { &hf_char_flag_drunk,
            { "Drunk", "tibia.flag.drunk",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_DRUNK,
                NULL, HFILL }
        },
        { &hf_char_flag_manashield,
            { "Manashield", "tibia.flag.manashield",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_MANASHIELD,
                NULL, HFILL }
        },
        { &hf_char_flag_paralyze,
            { "Paralyze", "tibia.flag.paralyze",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_PARALYZE,
                NULL, HFILL }
        },
        { &hf_char_flag_haste,
            { "Haste", "tibia.flag.haste",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_HASTE,
                NULL, HFILL }
        },
        { &hf_char_flag_battle,
            { "Battle lock", "tibia.flag.battle",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_BATTLE,
                NULL, HFILL }
        },
        { &hf_char_flag_water,
            { "Drowning", "tibia.flag.water",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_WATER,
                NULL, HFILL }
        },
        { &hf_char_flag_frozen,
            { "Freezing", "tibia.flag.frozen",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_FROZEN,
                NULL, HFILL }
        },
        { &hf_char_flag_dazzled,
            { "Dazzled", "tibia.flag.dazzled",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_DAZZLED,
                NULL, HFILL }
        },
        { &hf_char_flag_cursed,
            { "Cursed", "tibia.flag.cursed",
                FT_BOOLEAN, 24,
                NULL, CHAR_FLAG_CURSED,
                NULL, HFILL }
        },
        { &hf_acc_name,
            { "Account", "tibia.acc",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_char_name,
            { "Character name", "tibia.char",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acc_pass,
            { "Password", "tibia.pass",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_char_name_convo,
            { "Character name", "tibia.char",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acc_pass_convo,
            { "Password", "tibia.pass",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_info,
            { "Client information", "tibia.client.info",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_locale_id,
            { "Locale ID", "tibia.client.locale_id",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_locale,
            { "Locale", "tibia.client.locale",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_ram,
            { "Total RAM", "tibia.client.ram",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_cpu,
            { "CPU", "tibia.client.cpu",
                FT_STRINGZ, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_clock,
            { "CPU clock", "tibia.client.clock",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_clock2,
            { "CPU clock2", "tibia.client.clock2",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_gpu,
            { "GPU", "tibia.client.gpu",
                FT_STRINGZ, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_vram,
            { "Video RAM", "tibia.client.vram",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_resolution,
            { "Screen resolution", "tibia.client.resolution",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_xtea_len,
            { "Payload length", "tibia.payload.len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_loginserv_command,
            { "Command", "tibia.cmd",
                FT_UINT8, BASE_HEX,
                VALS(from_loginserv_packet_types), 0x0,
                NULL, HFILL }
        },
        { &hf_gameserv_command,
            { "Command", "tibia.cmd",
                FT_UINT8, BASE_HEX,
                VALS(from_gameserv_packet_types), 0x0,
                NULL, HFILL }
        },
        { &hf_client_command,
            { "Command", "tibia.cmd",
                FT_UINT8, BASE_HEX,
                VALS(from_client_packet_types), 0x0,
                NULL, HFILL }
        },
        { &hf_motd,
            { "Message of the day", "tibia.motd",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_dlg_error,
            { "Error message", "tibia.login.err",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_dlg_info,
            { "Info message", "tibia.login.info",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_charlist,
            { "Character list", "tibia.charlist",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_charlist_length,
            { "Character count", "tibia.charlist.count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_charlist_entry_name,
            { "Character name", "tibia.charlist.name",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_charlist_entry_world,
            { "World", "tibia.charlist.world",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_charlist_entry_ip,
            { "IP", "tibia.charlist.ip",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_charlist_entry_port,
            { "Port", "tibia.charlist.port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pacc_days,
            { "Premium days left", "tibia.pacc",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_channel_id,
            { "Channel id", "tibia.channel.id",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_channel_name,
            { "Channel name", "tibia.channel",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_speech_id,
            { "Type", "tibia.speechid",
                FT_UINT8, BASE_HEX,
                VALS(speech_ids), 0x0,
                NULL, HFILL }
        },
        { &hf_chat_msg,
            { "Message", "tibia.msg",
                FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },

    };

    module_t *tibia_module;
    static uat_field_t rsakeylist_uats_flds[] = {
        UAT_FLD_CSTRING_OTHER(rsakeylist_uats, ipaddr, "IP address", rsakeys_uat_fld_ip_chk_cb, "IPv4 or IPv6 address"),
        UAT_FLD_CSTRING_OTHER(rsakeylist_uats, port, "Port", rsakeys_uat_fld_port_chk_cb, "Port Number"),
        UAT_FLD_FILENAME_OTHER(rsakeylist_uats, keyfile, "Key File", rsakeys_uat_fld_fileopen_chk_cb, "Private keyfile."),
        UAT_FLD_CSTRING_OTHER(rsakeylist_uats, password,"Password", rsakeys_uat_fld_password_chk_cb, "Password (for keyfile)"),
        UAT_END_FIELDS
    };

    static uat_field_t xteakeylist_uats_flds[] = {
        UAT_FLD_DEC(xteakeylist_uats, framenum, "Frame Number", "XTEA key"),
        UAT_FLD_CSTRING_OTHER(xteakeylist_uats, key, "XTEA Key", xteakeys_uat_fld_key_chk_cb, "Symmetric (XTEA) key"),
        UAT_END_FIELDS
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_tibia,
        &ett_command,
        &ett_file_versions,
        &ett_client_info,
        &ett_charlist,
    };
    proto_tibia = proto_register_protocol (
            "Tibia Protocol", /* name */
            "Tibia",          /* short name */
            "tibia"           /* abbrev */
            );
    proto_register_field_array(proto_tibia, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    tibia_module = prefs_register_protocol(proto_tibia, proto_reg_handoff_tibia);

    prefs_register_bool_preference(tibia_module, "try_otserv_key", "Try OTServ's RSA key",
        "Try the default RSA key in use by nearly all Open Tibia servers", &try_otserv_key);

    rsakeys = g_hash_table_new_full(rsakey_hash, rsakey_equal, rsakey_free, NULL);

    rsakeys_uat = uat_new("RSA Keys",
            sizeof(struct rsakeys_assoc),
            "tibia_rsa_keys",        /* filename */
            TRUE,                    /* from_profile */
            &rsakeylist_uats,        /* data_ptr */
            &nrsakeys,               /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,  /* affects dissection of packets, but not set of named fields */
            NULL,                    /* Help section (currently a wiki page) */
            rsakeys_copy_cb,
            NULL,
            rsakeys_free_cb,
            rsa_parse_uat,
            NULL,
            rsakeylist_uats_flds/*, FALSE*/);
    prefs_register_uat_preference(tibia_module, "rsakey_table",
            "RSA keys list",
            "A table of RSA keys for decrypting protocols newer than 7.61",
            rsakeys_uat
    );

    xteakeys = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    xteakeys_uat = uat_new("XTEA Keys",
            sizeof(struct xteakeys_assoc),
            "tibia_xtea_keys",       /* filename */
            TRUE,                    /* from_profile */
            &xteakeylist_uats,       /* data_ptr */
            &nxteakeys,              /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,  /* affects dissection of packets, but not set of named fields */
            NULL,                    /* Help section (currently a wiki page) */
            xteakeys_copy_cb,
            NULL,
            xteakeys_free_cb,
            xtea_parse_uat,
            NULL,
            xteakeylist_uats_flds/*, FALSE*/);
    prefs_register_uat_preference(tibia_module, "xteakey_table",
            "XTEA keys list",
            "A table of XTEA keys for decrypting protocols newer than 7.61",
            xteakeys_uat
    );


    // FIXME best way to store this in source
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

void
proto_reg_handoff_tibia(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t tibia_handle;

    if (!initialized) {
        tibia_handle = create_dissector_handle(dissect_tibia, proto_tibia);
        initialized = TRUE;
    } else {
        dissector_delete_uint_range("tcp.port", &ports, tibia_handle);
    }

    dissector_add_uint_range("tcp.port", &ports, tibia_handle);
}


#if defined(HAVE_LIBGNUTLS)
static void
rsa_parse_uat(void)
{
    gnutls_x509_privkey_t priv_key;
    gcry_sexp_t           private_key;
    struct rsakey        *entry;

    FILE *fp = NULL;
    char *err = NULL;
    guint i;
    guint octet;
    guint8 ipaddr[4];
    const char *octetptr;

    g_hash_table_remove_all(rsakeys);

    for (i = 0; i < nrsakeys; i++) {
        struct rsakeys_assoc *uats = &rsakeylist_uats[i];

        /* try to load keys file first */
        fp = ws_fopen(uats->keyfile, "rb");
        if (!fp) {
            report_open_failure(uats->keyfile, errno, FALSE);
            return;
        }

        if (*uats->password) {
            priv_key = rsa_load_pkcs12(fp, uats->password, &err);
            if (err) {
                report_failure("%s\n", err);
                g_free(err);
            }
        } else {
            priv_key = rsa_load_pem_key(fp, &err);
            if (err) {
                report_failure("%s\n", err);
                g_free(err);
            }
        }
        fclose(fp);

        if (!priv_key) {
            report_failure("Can't load private key from %s\n", uats->keyfile);
            return;
        }

        private_key = rsa_privkey_to_sexp(priv_key, &err);
        if (!private_key) {
            g_free(err);
            report_failure("Can't extract private key parameters for %s", uats->keyfile);
            goto end;
        }

        entry = g_new(struct rsakey, 1);
        ws_strtou16(uats->port, NULL, &entry->port);
        octetptr = uats->ipaddr;
        for (octet = 0; octet < 4; octet++) {
            ws_strtou8(octetptr, &octetptr, &ipaddr[octet]);
            octetptr++;
        }
        alloc_address_wmem(NULL, &entry->addr, AT_IPv4, sizeof ipaddr, ipaddr);
        entry->privkey = private_key;


        g_hash_table_insert(rsakeys, entry, entry->privkey);

end:
        gnutls_x509_privkey_deinit(priv_key);
    }
}
#else
static void
rsa_parse_uat(void)
{
    report_failure("Can't load private key files, support is not compiled in.");
}
#endif

static void
rsakeys_free_cb(void *r)
{
    struct rsakeys_assoc *h = (struct rsakeys_assoc *)r;

    g_free(h->ipaddr);
    g_free(h->port);
    g_free(h->keyfile);
    g_free(h->password);
}

static void*
rsakeys_copy_cb(void *dst_, const void *src_, size_t len _U_)
{
    const struct rsakeys_assoc *src = (const struct rsakeys_assoc *)src_;
    struct rsakeys_assoc       *dst = (struct rsakeys_assoc *)dst_;

    dst->ipaddr    = g_strdup(src->ipaddr);
    dst->port      = g_strdup(src->port);
    dst->keyfile   = g_strdup(src->keyfile);
    dst->password  = g_strdup(src->password);

    return dst;
}

static gboolean
rsakeys_uat_fld_ip_chk_cb(void* r _U_, const char* ipaddr, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    /* I never seen an IPv6 Tibia server, but why not?
     * Replace this with proper IPv6 API if Wireshark provides it
     */
    if (ipaddr && g_hostname_is_ip_address(ipaddr) && strchr(ipaddr, '.'))
    {
        *err = NULL;
        return TRUE;
    }

    *err = g_strdup_printf("No IPv4 address given.");
    return FALSE;
}

static gboolean
rsakeys_uat_fld_port_chk_cb(void *_record _U_, const char *str, guint len _U_, const void *chk_data _U_, const void *fld_data _U_, char **err)
{
    guint16 val;
    if (!ws_strtou16(str, NULL, &val))
    {
        *err = g_strdup("Invalid argument. Expected a decimal between [0-65535]");
        return FALSE;
    }
    *err = NULL;
    return TRUE;
}

static gboolean
rsakeys_uat_fld_fileopen_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    ws_statb64 st;

    if (p && *p) {
        if (ws_stat64(p, &st) != 0) {
            *err = g_strdup_printf("File '%s' does not exist or access is denied.", p);
            return FALSE;
        }
    } else {
        *err = g_strdup("No filename given.");
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}

static gboolean
rsakeys_uat_fld_password_chk_cb(void *r _U_, const char *p _U_, guint len _U_, const void *u1 _U_, const void *u2 _U_, char **err)
{
#ifdef HAVE_LIBGNUTLS
    struct rsakeys_assoc*  f = (struct rsakeys_assoc *)r;
    FILE *fp = NULL;
    if (p && *p) {
        fp = ws_fopen(f->keyfile, "rb");
        if (fp) {
            char *msg = NULL;
            gnutls_x509_privkey_t priv_key = rsa_load_pkcs12(fp, p, &msg);
            if (!priv_key) {
                fclose(fp);
                *err = g_strdup_printf("Could not load PKCS#12 key file: %s", msg);
                g_free(msg);
                return FALSE;
            }
            g_free(msg);
            gnutls_x509_privkey_deinit(priv_key);
            fclose(fp);
        } else {
            *err = g_strdup_printf("Leave this field blank if the keyfile is not PKCS#12.");
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
#else
    *err = g_strdup("Cannot load key files, support is not compiled in.");
    return FALSE;
#endif
}

static void
xtea_parse_uat(void)
{
    guint i;
    g_hash_table_remove_all(xteakeys);

    for (i = 0; i < nxteakeys; i++) {
        struct xteakeys_assoc *uats = &xteakeylist_uats[i];
        guint offset;
        guint8 *key = g_malloc(XTEA_KEY_LEN);

        for (offset = 0; offset < XTEA_KEY_LEN; offset++)
            key[offset] = (g_ascii_xdigit_value(uats->key[2*offset]) << 4)
                        +  g_ascii_xdigit_value(uats->key[2*offset + 1]);
        
        g_hash_table_insert(xteakeys, GUINT_TO_POINTER(uats->framenum), key);
    }
}

static void
xteakeys_free_cb(void *r)
{
    struct xteakeys_assoc *h = (struct xteakeys_assoc *)r;

    g_free(h->key);
}

static void*
xteakeys_copy_cb(void *dst_, const void *src_, size_t len _U_)
{
    const struct xteakeys_assoc *src = (const struct xteakeys_assoc *)src_;
    struct xteakeys_assoc       *dst = (struct xteakeys_assoc *)dst_;

    dst->framenum = src->framenum;
    dst->key      = g_strdup(src->key);

    return dst;
}

static gboolean
xteakeys_uat_fld_key_chk_cb(void* r _U_, const char* key, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (len == XTEA_KEY_LEN*2) {
        for (; g_ascii_isxdigit(*key); key++)
            ;

        if (*key == '\0') {
            *err = NULL;
            return TRUE;
        }

    }

    *err = g_strdup_printf("XTEA keys are 32 character long hex strings.");
    return FALSE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
