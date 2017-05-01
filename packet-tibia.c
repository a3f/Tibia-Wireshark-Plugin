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
 * Game (MMORPG) by Cipsoft GmbH.
 *
 * Transport is over TCP, with recent versions encrypting player interaction
 * with XTEA. Authentication and key exchange is done with a hard-coded
 * RSA key in the client.
 *
 * Three official clients exist: The current Qt-based 11.0+ client,
 * the old C++ client used from Tibia 7.0 till 10.99 and the Flash client.
 * The latter two are being phased out. They use the same protocol,
 * except for different key exchange in the Flash client. The flash client is
 * not supported by this dissector.
 *
 * The dissector supports Tibia versions from 7.0 (2002) till current
 * 10.99 (2017-05-01). Tibia has an active open source server emulater
 * community (OTServ) that still makes use of older versions and surpasses
 * the official servers in popularity, therefore compatability with older
 * protocol iterations should be maintained.
 *
 * The RSA private key usually used by OTServ is hard-coded in. Server
 * admins may add their own private key in PEM or PKCS#12 format over
 * the UAT. For servers where the private key is indeed private (like
 * for official servers), the symmetric XTEA key (retrievable by memory
 * peeking or MitM) may be provided to the dissector via UAT.
 *
 *
 * Tibia is a registered trademark of Cipsoft GmbH.
 */

#include "config.h"
#include <epan/packet.h>
#include <wsutil/adler32.h>
#include <epan/address.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/conversation.h>
#include <epan/value_string.h>
#include <epan/expert.h>
#include <epan/address.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/report_message.h>
#include <wsutil/xtea.h>
#include <wsutil/strtoi.h>
#include <wsutil/rsa.h>
#include <errno.h>

static gboolean try_otserv_key        = TRUE,
                show_char_name        = TRUE,
                show_acc_info         = TRUE,
                show_xtea_key         = FALSE,
                dissect_game_commands = TRUE;

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

/* The login server has been traditionally on 7171,
 * For OTServ, the gameserver often listens on the came IP/Port,
 * but occasionly on 7172. Offcial Tibia doesn't host login and
 * game servers on the same IP address
 */

static range_t ports = { 1, {{ 7171, 7172 }} };

static gint proto_tibia = -1;
static uat_t *rsakeys_uat = NULL, *xteakeys_uat = NULL;
static struct rsakeys_assoc  *rsakeylist_uats = NULL;
static struct xteakeys_assoc *xteakeylist_uats = NULL;
static guint nrsakeys = 0, nxteakeys = 0;

static gint hf_len                  = -1;
static gint hf_adler32              = -1;
static gint hf_type                 = -1;
static gint hf_os                   = -1;
static gint hf_proto_version        = -1;
static gint hf_client_version       = -1;
static gint hf_file_versions        = -1;
static gint hf_file_version_spr     = -1;
static gint hf_file_version_dat     = -1;
static gint hf_file_version_pic     = -1;
static gint hf_game_preview_state   = -1;
static gint hf_content_revision     = -1;
static gint hf_undecoded_rsa_data   = -1;
static gint hf_undecoded_xtea_data  = -1;
static gint hf_xtea_key             = -1;
static gint hf_loginflags_gm        = -1;
static gint hf_acc_name             = -1;
static gint hf_session_key          = -1;
static gint hf_char_name            = -1;
static gint hf_acc_pass             = -1;
static gint hf_char_name_convo      = -1;
static gint hf_acc_pass_convo       = -1;
static gint hf_session_key_convo    = -1;

static gint hf_client_info          = -1;
static gint hf_client_locale_id     = -1;
static gint hf_client_locale        = -1;
static gint hf_client_ram           = -1;
static gint hf_client_cpu           = -1;
static gint hf_client_clock         = -1;
static gint hf_client_clock2        = -1;
static gint hf_client_gpu           = -1;
static gint hf_client_vram          = -1;
static gint hf_client_resolution    = -1;

static gint hf_payload_len          = -1;
static gint hf_loginserv_command    = -1;
static gint hf_gameserv_command     = -1;
static gint hf_client_command       = -1;

static gint hf_motd                 = -1;
static gint hf_dlg_error            = -1;
static gint hf_dlg_info             = -1;
static gint hf_charlist             = -1;
static gint hf_charlist_length      = -1;
static gint hf_charlist_entry_name  = -1;
static gint hf_charlist_entry_world = -1;
static gint hf_charlist_entry_ip    = -1;
static gint hf_charlist_entry_port  = -1;
static gint hf_pacc_days            = -1;
static gint hf_channel_id           = -1;
static gint hf_channel_name         = -1;
static gint hf_char_flag_poison     = -1;
static gint hf_char_flag_fire       = -1;
static gint hf_char_flag_energy     = -1;
static gint hf_char_flag_drunk      = -1;
static gint hf_char_flag_manashield = -1;
static gint hf_char_flag_paralyze   = -1;
static gint hf_char_flag_haste      = -1;
static gint hf_char_flag_battle     = -1;
static gint hf_char_flag_water      = -1;
static gint hf_char_flag_frozen     = -1;
static gint hf_char_flag_dazzled    = -1;
static gint hf_char_flag_cursed     = -1;

static gint hf_chat_msg             = -1;
static gint hf_speech_id            = -1;

static gint hf_coords_x = -1;
static gint hf_coords_y = -1;
static gint hf_coords_z = -1;
static gint hf_coords   = -1;
static gint hf_stackpos = -1;

static gint hf_item            = -1;
static gint hf_container       = -1;
static gint hf_container_slot  = -1;
static gint hf_container_slots = -1;
static gint hf_inventory       = -1;
static gint hf_vip             = -1;
static gint hf_player          = -1;
static gint hf_creature        = -1;
static gint hf_window          = -1;

static gint hf_u8  = -1;
static gint hf_u16 = -1;
static gint hf_u32 = -1;
static gint hf_str = -1;

static gint ett_tibia         = -1;
static gint ett_command       = -1;
static gint ett_file_versions = -1;
static gint ett_client_info   = -1;
static gint ett_charlist      = -1;

static expert_field ei_xtea_len_toobig = EI_INIT;

struct rsakey {
    address addr;
    guint16 port;

    gcry_sexp_t privkey;
};
GHashTable *rsakeys, *xteakeys;

#define CONVO_STATE_FRESH              0x0
#define CONVO_STATE_LOGIN              0x1
#define CONVO_STATE_INGAME             0x2

struct tibia_convo {
    guint16 proto_version;
    guint32 client_version;
    guint32 xtea_key[XTEA_KEY_LEN / sizeof (guint32)];
    guint32 xtea_framenum;
    char *acc, *pass, *char_name, *session_key;
    struct proto_traits {
        guint32 adler32:1, rsa_blocks:2, xtea:1, acc_name:1, nonce:1,
                extra_gpu_info:1, gmbyte:1, hwinfo:1;
        guint32 outfit_addons:1, stamina:1, lvl_on_msg:1;
        guint32 ping:1, client_version:1, game_preview:1, auth_token:1, session_key:1;
        guint32 game_content_revision:1, worldlist_in_charlist:1;
    } has;

    guint32 state:2;
    guint32 loginserv_is_peer : 1;
    guint16 clientport;
    guint16 servport;

    gcry_sexp_t privkey;
};

static struct proto_traits
get_version_traits(guint16 version)
{
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
    struct proto_traits has = {0};
    has.gmbyte = TRUE;

    if (version >= 761) {
        has.xtea = TRUE;
        has.rsa_blocks++;
    }
    if (version >= 780)
        has.outfit_addons = has.stamina = has.lvl_on_msg = TRUE;
    if (version >= 830)
        has.adler32 = has.acc_name = TRUE;
    if (version >= 841)
        has.hwinfo = has.nonce = TRUE;
    if (version >= 953)
        has.ping = TRUE;
    if (version >= 980)
        has.client_version = has.game_preview = TRUE;
    if (version >= 1010)
        has.worldlist_in_charlist = TRUE;
    if (version >= 1061) {
        has.extra_gpu_info = TRUE;
        /*has.rsa_blocks++;*/
    }
    if (version >= 1071)
        has.game_content_revision = TRUE;
    if (version >= 1072)
        has.auth_token = TRUE;
    if (version >= 1074)
        has.session_key = TRUE;

    return has;
}

guint16 get_version_get_charlist_packet_size(struct proto_traits *has)
{
    gsize size = 0;
    size += 4 * has->adler32;
    size += 17;
    size += 222 * has->extra_gpu_info;
    size += has->rsa_blocks * 128;

    return size;
}
guint16 get_version_char_login_packet_size(struct proto_traits *has)
{
    gsize size = 0;
    size += 4 * has->adler32;
    size += 5;
    size += 4 * has->client_version;
    size += 2 * has->game_content_revision;
    size += 1 * has->game_preview;
    size += has->rsa_blocks * 128;

    return size;
}


#define XTEA_FROM_UAT 0
#define XTEA_UNKNOWN  0xFFFFFFFF

static struct tibia_convo *
tibia_get_convo(packet_info *pinfo)
{
    struct tibia_convo *convo;
    conversation_t *epan_conversation = find_or_create_conversation(pinfo);

    convo = (struct tibia_convo*)conversation_get_proto_data(epan_conversation, proto_tibia);

    if (!convo) {
        struct rsakey rsa_key;
        convo = wmem_new0(wmem_file_scope(), struct tibia_convo);
        convo->char_name = convo->acc = convo->pass = convo->session_key = NULL;
        convo->proto_version = convo->client_version = 0;

        printf("Creating convo %u\n", pinfo->num);

        /* FIXME there gotta be a cleaner way...*/
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
        convo->state = CONVO_STATE_FRESH;
        memset(&convo->has, '\0', sizeof convo->has);
        convo->xtea_framenum = XTEA_UNKNOWN;

        conversation_add_proto_data(epan_conversation, proto_tibia, (void *)convo);
    }

    if (convo->xtea_framenum == XTEA_UNKNOWN) {
        guint8 *xtea_key = g_hash_table_lookup(xteakeys, GUINT_TO_POINTER(pinfo->num));
        if (xtea_key) {
            memcpy(convo->xtea_key, xtea_key, XTEA_KEY_LEN);
            convo->xtea_framenum = XTEA_FROM_UAT;
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
    C_GET_CHARLIST          = 0x01,
    C_LOGIN_CHAR            = 0x0A,
    C_PING                  = 0x1E,
    C_LOGOUT                = 0x14,

    C_AUTO_WALK             = 0x64,
    C_GO_NORTH              = 0x65,
    C_GO_EAST               = 0x66,
    C_GO_SOUTH              = 0x67,
    C_GO_WEST               = 0x68,
    C_AUTO_WALK_CANCEL      = 0x69,
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
    C_TILE_UPDATE           = 0xC9,
    C_CONTAINER_UPDATE      = 0xCA,
    C_SET_OUTFIT            = 0xD3,
    C_VIP_ADD               = 0xDC,
    C_VIP_REMOVE            = 0xDD
};
static const value_string from_client_packet_types[] = {
    { C_GET_CHARLIST,     "Charlist request" },
    { C_LOGIN_CHAR,       "Character login" },
    { C_PLAYER_SPEECH,    "Speech" },
    { C_PING,             "Pong" },
    { C_LOGOUT,           "Logout" },

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

enum { LOGINSERV_DLG_ERROR = 0x0A, LOGINSERV_DLG_ERROR2 = 0x0B, LOGINSERV_DLG_MOTD = 0x14, LOGINSERV_DLG_CHARLIST = 0x64 };
static const value_string from_loginserv_packet_types[] = {
    { LOGINSERV_DLG_MOTD,     "MOTD" },
    { LOGINSERV_DLG_CHARLIST, "Charlist" },
    { LOGINSERV_DLG_ERROR,     "Error" },
    { LOGINSERV_DLG_ERROR2,    "Error" },

    { 0, NULL }
};

enum server_commands{
    /* Credit to Khaos (OBJECT Networks) */
    S_MAPINIT =                0x0A, /* Long playerCreatureId Int unknownU16 (Byte reportBugs?) */
    S_GMACTIONS =              0x0B, /* Used to be 32 unknown bytes, but with GMs removed it                                      might not be in use anymore */
    S_DLG_ERROR =              0x14, /* String errorMessage */
    S_DLG_INFO =               0x15,
    S_DLG_TOOMANYPLAYERS =     0x16,
    S_PING =                   0x1E,
    S_NONCE =                  0x1F,
    S_PLAYERLOC =              0x64, /* Coord pos */
    S_GO_NORTH =               0x65, /* MapDescription (18,1) */
    S_GO_EAST =                0x66, /* MapDescription (1,14) */
    S_GO_SOUTH =               0x67, /* MapDescription (18,1) */
    S_GO_WEST =                0x68, /* MapDescription (1,14) */
    S_TILEUPDATE =             0x69, /* Coord pos TileDescription td */
    S_ADDITEM =                0x6a, /* Coord pos ThingDescription thing */
    S_REPLACEITEM =            0x6b, /* Coord pos Byte stackpos ThingDescription thing */
    S_REMOVEITEM =             0x6c, /* Coord pos Byte stackpos */
    S_MOVE_THING =             0x6d,
    S_CONTAINER =              0x6e, /* Byte index Short containerIcon Byte slotCount ThingDescription item */
    S_CONTAINERCLOSE =         0x6f, /* Byte index */
    S_ADDITEMCONTAINER =       0x70, /* Byte index ThingDescription itm */
    S_TRANSFORMITEMCONTAINER = 0x71, /* Byte index Byte slot */
    S_REMOVEITEMCONTAINER =    0x72, /* Byte index Byte slot */
    S_INVENTORYEMPTY =         0x78, /* Byte invSlot */
    S_INVENTORYITEM =          0x79, /* Byte invSlot ThingDescription itm */
    S_TRADEREQ =               0x7d, /* String otherperson Byte slotCount ThingDescription itm */
    S_TRADEACK =               0x7e, /* String otherperson Byte slotCount ThingDescription itm */
    S_TRADECLOSE =             0x7f,
    S_LIGHTLEVEL =             0x82, /* Byte lightlevel Byte lightcolor */
    S_MAGIC_EFFECT =           0x83,
    S_ANIMATEDTEXT =           0x84, /* Coord pos Byte color String message */
    S_DISTANCESHOT =           0x85, /* Coord pos1 Byte stackposition Coord pos2 */
    S_CREATURESQUARE =         0x86, /* Long creatureid Byte squarecolor */
    S_CREATURE_HEALTH =        0x8C,
    S_CREATURELIGHT =          0x8d, /* Long creatureid Byte ? Byte ? */
    S_SETOUTFIT =              0x8e, /* Long creatureid Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType // can extended look go here too? */
    S_CREATURESPEED =          0x8f, /* YIKES! I didnt handle this! */
    S_TEXTWINDOW =             0x96, /* Long windowId Byte icon Byte maxlength String message */
    S_STATUSMSG =              0xA0, /* Status status */
    S_SKILLS =                 0xA1, /* Skills skills */
    S_PLAYER_CONDITION =       0xA2,
    S_CANCELATTACK =           0xA3,
    S_SPEAK =                  0xAA,
    S_CHANNELSDIALOG =         0xAB, /* Byte channelCount (Int channelId String channelName) */
    S_CHANNEL_OPEN =           0xAC,
    S_OPENPRIV =               0xAD, /* String playerName */
    S_TEXTMESSAGE =            0xB4, /* Byte msgClass String string */
    S_CANCELWALK =             0xB5, /* Byte direction */
    S_FLOORUP =                0xBE, /* Advanced topic; read separate text */
    S_FLOORDOWN =              0xBF, /* Advanced topic; read separate text */
    S_OUTFITLIST =             0xC8, /* Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType Byte firstModel Byte lastModel */
    S_VIPADD =                 0xd2, /* long guid string name byte isonline */
    S_VIPLOGIN =               0xd3, /* long guid */
    S_VIPLOGOUT =              0xd4  /* long guid*/
};
static const value_string from_gameserv_packet_types[] = {

    { S_MAPINIT,            "Initialize map" },
    { S_GMACTIONS,          "GM actions" },
    { S_DLG_ERROR,          "Error" },
    { S_DLG_INFO,           "Info" },
    { S_DLG_TOOMANYPLAYERS, "Too many players" },
    { S_PING,           "Ping" },
    { S_NONCE,          "Nonce" },
    { S_PLAYERLOC,      "Set player location" },
    { S_GO_NORTH,        "Go north" },
    { S_GO_EAST,         "Go east" },
    { S_GO_SOUTH,        "Go south" },
    { S_GO_WEST,         "Go west" },
    { S_TILEUPDATE,     "Update tile" },
    { S_ADDITEM,        "Add item" },
    { S_REPLACEITEM,    "Replace item" },
    { S_REMOVEITEM,     "Remove item" },
    { S_MOVE_THING,     "Move thing" },
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


static int tibia_dissect_loginserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, guint16 len, packet_info *pinfo, proto_tree *mytree);
static int dissect_game_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *mytree, gboolean is_xtea_encrypted);

static void wmem_free_null(void *buf) { wmem_free(NULL, buf); }

static int
dissect_tibia(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    struct tibia_convo *convo;
    tvbuff_t *tvb_decrypted = tvb;
    int offset = 0, len;
    proto_tree *mytree = NULL, *subtree = NULL;
    proto_item *ti = NULL, *subti = NULL;
    gboolean is_xtea_encrypted = TRUE;
    gcry_sexp_t privkey;
    guint16 plen = tvb_get_guint16(tvb, 0, ENC_LITTLE_ENDIAN);

    /* if announced length != real length it's not a tibia packet */
    if (tvb_captured_length_remaining(tvb, 2) != plen)
        return -1;

    convo = tibia_get_convo(pinfo);

    proto_tree_add_debug_text(tree, "Traits: Adler32=%d RSA-blocks=%d",
            convo->has.adler32,
            convo->has.rsa_blocks
            );

    /* if (convo->state == CONVO_STATE_FRESH) */ {
        guint hash_bytes = 0;
        int off = offset + 2;
        gint a32len = tvb_captured_length_remaining(tvb, off + 4);
        guint32 a32 = tvb_get_guint32(tvb, off, ENC_LITTLE_ENDIAN);
        if (a32 == adler32_bytes(tvb_get_ptr(tvb, off + 4, a32len), a32len)) {
            convo->has.adler32 = TRUE;
            hash_bytes = 4;
            proto_tree_add_debug_text(tree, "Adler32 ok");
        } else {
            convo->has.adler32 = FALSE;
            proto_tree_add_debug_text(tree, "Adler32 not ok");
        }
        off += hash_bytes;

        is_xtea_encrypted = FALSE;
        convo->state = CONVO_STATE_INGAME;

        /* Is it a nonce? */
        if (tvb_get_guint16(tvb, off, ENC_LITTLE_ENDIAN) == plen - off
        && tvb_get_guint8(tvb, off+2) == S_NONCE) {
            /* FIXME: SET FRESH FOR ONE FOLLOWING NONCE? */
        } else {
            guint8 cmd;
            guint16 version;
            struct proto_traits version_has;
            cmd = tvb_get_guint8(tvb, off);
            off += 1;
            off += 2;
            version = tvb_get_guint16(tvb, off, ENC_LITTLE_ENDIAN);
            version_has = get_version_traits(version);
    proto_tree_add_debug_text(tree, "version: %u get_charlist_plen=%u char_login_plen=%u", convo->proto_version, get_version_get_charlist_packet_size(&version_has),  get_version_char_login_packet_size(&version_has));
            switch(cmd) {
                case C_GET_CHARLIST:
                    if ((700 <= version && version < 740 && 23 <= plen && plen <= 52)
                    || get_version_get_charlist_packet_size(&version_has) == plen) {
                        convo->state = CONVO_STATE_LOGIN;
                        convo->loginserv_is_peer = TRUE;
                    }
                    break;
                case C_LOGIN_CHAR:
                    if ((700 <= version && version < 740 && 23 <= plen && plen <= 52)
                    ||  get_version_char_login_packet_size(&version_has) == plen)
                        convo->state = CONVO_STATE_LOGIN;
                    break;
                default:
                    is_xtea_encrypted = TRUE;
            }
        }
    }

    if (convo->state == CONVO_STATE_LOGIN)
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Tibia login");
    else if (pinfo->srcport == convo->servport)
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Tibia server");
    else
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Tibia client");

    /* Clear out stuff in the info column */
    /*col_clear(pinfo->cinfo,COL_INFO);*/
    /*col_add_fstr(pinfo->cinfo, COL_INFO, "%s", kinds[kind]);*/

    /* Charlist packets contains addresses that use the same RSA key, so it's
     * beneficial to dissect loginserver communication fully in the first pass
     */
    if (!tree && !convo->loginserv_is_peer)
        return offset;

    ti = proto_tree_add_item(tree, proto_tibia, tvb, 0, -1, ENC_NA);
    mytree = proto_item_add_subtree(ti, ett_tibia);

    proto_tree_add_item(mytree, hf_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (convo->has.adler32) {
        proto_tree_add_item(mytree, hf_adler32, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (convo->state == CONVO_STATE_INGAME)
        return dissect_game_packet(convo, tvb, offset, pinfo, mytree, is_xtea_encrypted);

    proto_tree_add_item(mytree, hf_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(mytree, hf_os, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    convo->proto_version = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    convo->has = get_version_traits(convo->proto_version);
    proto_tree_add_debug_text(tree, "convo->proto_version: %d", convo->proto_version);
    proto_tree_add_item(mytree, hf_proto_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (convo->has.client_version) {
        proto_tree_add_item(mytree, hf_client_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    if (convo->loginserv_is_peer) {
        subti = proto_tree_add_item(mytree, hf_file_versions, tvb, offset, 12, ENC_NA);
        subtree = proto_item_add_subtree(subti, ett_file_versions);
        proto_tree_add_item(subtree, hf_file_version_spr, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_file_version_dat, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_file_version_pic, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else if (convo->has.game_content_revision) {
        proto_tree_add_item(mytree, hf_content_revision, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    if (convo->has.game_preview) {
        proto_tree_add_item(mytree, hf_game_preview_state, tvb_decrypted, offset, 1, ENC_NA);
        offset += 1;
    }

    if (!(privkey = convo_get_privkey(convo))) {
        proto_tree_add_item(mytree, hf_undecoded_rsa_data, tvb, offset, plen - offset, ENC_NA);
        return offset;
    }

    /* assume OTServ communication */
    /* (TODO: if it fails, mark TCP communication as non-OTServ (or nah it's just once) */
    if (convo->has.rsa_blocks) {
        char *err = NULL;
        /* FIXME USE WS_MALLOC */

        gint plaintext_len;
        guint8 *ciphertext;
        /*guint rsa_size = convo->has.rsa_blocks * 128;*/
        guint ciphertext_len = tvb_captured_length_remaining(tvb, offset);
#if 0
        if (ciphertext_len > rsa_size) {
            call_data_dissector(tvb_new_subset_length(tvb, offset, ciphertext_len - rsa_size), pinfo, mytree);
            offset += ciphertext_len - rsa_size;
            ciphertext_len = rsa_size;
        }
#endif

        ciphertext = tvb_memdup(NULL, tvb, offset, ciphertext_len);
        proto_tree_add_debug_text(mytree, "RSA from: %u len %u\n", offset, ciphertext_len);


        /*TODO: check if failure , FIXME: remove tvb_get_ptr*/

        if (!(plaintext_len = pcry_private_decrypt(128 /*ciphertext_len*/, ciphertext, privkey, FALSE, &err))) {
            printf("FAIL: %s!\n", err);
            /*g_free(err);*/
            return -1;
        }
        tvb_decrypted = tvb_new_child_real_data(tvb, ciphertext, plaintext_len, plaintext_len);
        tvb_set_free_cb(tvb_decrypted, wmem_free_null);
        add_new_data_source(pinfo, tvb_decrypted, "Decrypted Login Data");

        offset = 0;

        /* XXX what about leading zeroes in XTEA key? */
        tvb_memcpy(tvb_decrypted, convo->xtea_key, offset, XTEA_KEY_LEN);
        proto_tree_add_item(mytree, hf_xtea_key, tvb_decrypted, offset, XTEA_KEY_LEN, ENC_BIG_ENDIAN);
        offset += XTEA_KEY_LEN;
        convo->xtea_framenum = pinfo->num;
    }

    /* TODO: correct? */

    if (!mytree)
        return offset;

    if (!convo->loginserv_is_peer && convo->has.gmbyte) {
        proto_tree_add_item(mytree, hf_loginflags_gm, tvb_decrypted, offset, 1, ENC_NA);
        offset += 1;
    }

    if (convo->has.session_key) {
        len = tvb_get_guint16(tvb_decrypted, offset, ENC_LITTLE_ENDIAN);
        if (offset + len + 2 > plen) return -1;
        if (convo) {
            convo->session_key = (char*)tvb_memdup(wmem_file_scope(), tvb_decrypted, offset + 2, len + 1);
            convo->session_key[len] = '\0';
        }

        proto_tree_add_item(mytree, hf_session_key, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
        offset += len + 2;
    } else if (convo->has.acc_name) {
        guint16 acclen = tvb_get_guint16(tvb_decrypted, offset, ENC_LITTLE_ENDIAN);
        if (offset + acclen + 2 > plen) return -1;
        if (convo) {
            convo->acc = (char*)tvb_memdup(wmem_file_scope(), tvb_decrypted, offset + 2, acclen + 1);
            convo->acc[acclen] = '\0';
        }
        proto_tree_add_string_format_value(mytree, hf_acc_name, tvb_decrypted, offset, 2 + acclen, NULL, "%.*s", acclen, tvb_get_ptr(tvb_decrypted, offset + 2, acclen));
        offset += 2 + acclen;
    } else /* account number */ {
        guint32 accnum = tvb_get_guint32(tvb_decrypted, offset, ENC_LITTLE_ENDIAN);
        if (convo) {
            convo->acc = wmem_strdup_printf(wmem_file_scope(), "%lu", (unsigned long)accnum);
        }
        proto_tree_add_string_format_value(mytree, hf_acc_name, tvb_decrypted, offset, 4, NULL, "%lu", (unsigned long)accnum);
        offset += 4;

    }

    if (!convo->loginserv_is_peer) {
        len = tvb_get_guint16(tvb_decrypted, offset, ENC_LITTLE_ENDIAN);
        if (convo) {
            convo->char_name = (char*)tvb_memdup(wmem_file_scope(), tvb_decrypted, offset + 2, len + 1);
            convo->char_name[len] = '\0';
        }

        proto_tree_add_item(mytree, hf_char_name, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
        offset += len + 2;
    }

    if (!convo->has.session_key) {
        len = tvb_get_guint16(tvb_decrypted, offset, ENC_LITTLE_ENDIAN);
        if (convo) {
            convo->pass = (char*)tvb_memdup(wmem_file_scope(), tvb_decrypted, offset + 2, len + 1);
            convo->pass[len] = '\0';
        }
        proto_tree_add_item(mytree, hf_acc_pass, tvb_decrypted, offset, 2,  ENC_LITTLE_ENDIAN | ENC_ASCII);
        offset += len + 2;
    }

    if (convo->loginserv_is_peer && convo->has.hwinfo) {
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

    /* TODO Extended GPU info (plan) and authentication token (RSA-encrypted again)*/

    return offset;
}

static int tibia_dissect_gameserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, guint16 len, packet_info *pinfo, proto_tree *mytree);
static int tibia_dissect_client_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, guint16 len, packet_info *prinfo, proto_tree *mytree);

static int
dissect_game_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *mytree, gboolean is_xtea_encrypted)
{
    proto_item *ti = NULL;
    tvbuff_t *tvb_decrypted = tvb;
    guint16 len = tvb_captured_length_remaining(tvb, offset);

    if (show_acc_info) {
        if (convo->has.session_key) {
            if (convo->session_key) {
                ti = proto_tree_add_string(mytree, hf_session_key_convo, tvb, offset, 0, convo->session_key);
                PROTO_ITEM_SET_GENERATED(ti);
            }
        } else {
            if (convo->acc) {
                ti = proto_tree_add_string(mytree, hf_acc_name, tvb, offset, 0, convo->acc);
                PROTO_ITEM_SET_GENERATED(ti);
            }

            if (convo->pass) {
                ti = proto_tree_add_string(mytree, hf_acc_pass_convo, tvb, offset, 0, convo->pass);
                PROTO_ITEM_SET_GENERATED(ti);
            }
        }
    }

    if (show_char_name && convo->char_name) {
        ti = proto_tree_add_string(mytree, hf_char_name_convo, tvb, offset, 0, convo->char_name);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    // TODO: check how well this all works without XTEA
    if (is_xtea_encrypted) {
        if (convo->has.xtea && pinfo->num < convo->xtea_framenum)
            return offset;

        if (show_xtea_key && convo->has.xtea) {
            ti = proto_tree_add_bytes_with_length(mytree, hf_xtea_key, tvb, 0, 1, (guint8*)convo->xtea_key, XTEA_KEY_LEN);
            PROTO_ITEM_SET_GENERATED(ti);
        }

        tvb_decrypted = tvb;
        if (pinfo->num > convo->xtea_framenum) {
            guint32 *decrypted_buffer;
            int end;
            guint32 *dstblock;
            end = offset + len;

            if (len % 8 != 0)
                return -1;
            /* copying and then overwriting might seem a waste at first
             * but it's required as not to break strict aliasing */
            decrypted_buffer = (guint32*)g_malloc(len);

            for (dstblock = decrypted_buffer; offset < end; offset += 2*sizeof(guint32)) {
                decrypt_xtea_le_ecb(dstblock, tvb_get_ptr(tvb, offset, 2*sizeof(guint32)), convo->xtea_key, 32);
                dstblock += 2;
            }

            tvb_decrypted = tvb_new_child_real_data(tvb, (guint8*)decrypted_buffer, len, len);
            tvb_set_free_cb(tvb_decrypted, g_free);
            add_new_data_source(pinfo, tvb_decrypted, "Decrypted Game Data");

            offset = 0;
        }
    }
    if (convo->has.xtea) {
        len = offset + tvb_get_guint16(tvb_decrypted, offset, ENC_LITTLE_ENDIAN) + 2;
        ti = proto_tree_add_item(mytree, hf_payload_len, tvb_decrypted, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        if (len - offset > tvb_captured_length_remaining(tvb_decrypted, 0) - 2)
        {
            expert_add_info(pinfo, ti, &ei_xtea_len_toobig);
            return offset;
        }
    }


    if (pinfo->srcport == convo->servport && convo->loginserv_is_peer)
        return tibia_dissect_loginserv_packet(convo, tvb_decrypted, offset, len, pinfo, mytree);
    
    if (!dissect_game_commands) {
        call_data_dissector(tvb_new_subset_length(tvb, offset, len), pinfo, mytree);
        return offset + len;
    }

    if (pinfo->srcport == convo->servport)
        return tibia_dissect_gameserv_packet(convo, tvb_decrypted, offset, len, pinfo, mytree);
    else
        return tibia_dissect_client_packet(convo, tvb_decrypted, offset, len, pinfo, mytree);
}

struct state {
    struct tibia_convo *convo;
    tvbuff_t *tvb;
    gint offset;
    packet_info *pinfo;
    proto_tree *tree;
};

/** Game commands **/

static inline void dissect_unknown(struct state *s, guint len) {
    call_data_dissector(tvb_new_subset_length(s->tvb, s->offset, len), s->pinfo, s->tree);
    s->offset += len;
}
static inline void dissect_string(struct state *s, gint hfid, const char *msg _U_) {
    guint16 len = tvb_get_guint16(s->tvb, s->offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(s->tree, hfid, s->tvb, s->offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
    s->offset += 2 + len;
}
static inline guint8 dissect_u8(struct state *s, gint hfid, const char *msg _U_) {
    guint8 ret = tvb_get_guint8(s->tvb, s->offset);
    proto_tree_add_item(s->tree, hfid, s->tvb, s->offset, 1, ENC_NA);
    s->offset += sizeof (guint8);
    return ret;
}
static inline guint16 dissect_u16(struct state *s, gint hfid, const char *msg _U_) {
    guint16 ret = tvb_get_guint16(s->tvb, s->offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(s->tree, hfid, s->tvb, s->offset, 2, ENC_LITTLE_ENDIAN);
    s->offset += sizeof (guint16);
    return ret;
}
static inline guint32 dissect_u32(struct state *s, gint hfid, const char *msg _U_) {
    guint32 ret = tvb_get_guint32(s->tvb, s->offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(s->tree, hfid, s->tvb, s->offset, 4, ENC_LITTLE_ENDIAN);
    s->offset += sizeof (guint32);
    return ret;
}
static inline void dissect_channel_open(struct state *s) {
    dissect_u16(s, hf_channel_id, NULL);
    dissect_string(s, hf_channel_name, NULL);
}
static inline void dissect_player_condition(struct state *s) {
    proto_tree_add_item(s->tree, hf_char_flag_poison,     s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_fire,       s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_energy,     s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_drunk,      s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_manashield, s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_paralyze,   s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_haste,      s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_battle,     s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_water,      s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_frozen,     s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_dazzled,    s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(s->tree, hf_char_flag_cursed,     s->tvb, s->offset, 2, ENC_BIG_ENDIAN);
    s->offset += 2;
}

static const value_string speech_ids[] = {
    { 0x1, "Say" },
    { 0x2, "Whisper" },
    { 0x3, "Yell" },
    { 0x7, "Public Channel" },
    { 0, NULL }
};

static inline void dissect_speech(struct state *s) {
    guint8 type = dissect_u8(s, hf_speech_id, NULL);
    if (type == 0x7) dissect_u16(s, hf_channel_id, NULL);
    dissect_string(s, hf_chat_msg, NULL);
}
static inline void dissect_coord(struct state *s) {
    proto_item *ti;
    guint base_offset = s->offset;
    guint x, y, z;
    ti = proto_tree_add_item_ret_uint(s->tree, hf_coords_x, s->tvb, s->offset, 2, ENC_LITTLE_ENDIAN, &x);
    PROTO_ITEM_SET_HIDDEN(ti);
    s->offset += sizeof (guint16);
    ti = proto_tree_add_item_ret_uint(s->tree, hf_coords_y, s->tvb, s->offset, 2, ENC_LITTLE_ENDIAN, &y);
    PROTO_ITEM_SET_HIDDEN(ti);
    s->offset += sizeof (guint16);
    ti = proto_tree_add_item_ret_uint(s->tree, hf_coords_z, s->tvb, s->offset, 1, ENC_NA, &z);
    PROTO_ITEM_SET_HIDDEN(ti);
    s->offset += sizeof (guint8);

    proto_tree_add_string_format_value(s->tree, hf_coords, s->tvb, base_offset, s->offset - base_offset,
            NULL, "(%u, %u, %u)", x, y, z);

}

static inline void dissect_stackpos(struct state *s) {
    dissect_u8(s, hf_stackpos, NULL);
}
#if 0
static inline void dissect_item(struct state *s) {
    dissect_u16(s, hf_item, NULL);
}
#endif
static inline void dissect_container(struct state *s) {
    dissect_u8(s, hf_container, NULL);
}
static inline void dissect_inventory(struct state *s) {
    dissect_u16(s, hf_inventory, NULL);
}
static inline void dissect_vip(struct state *s) {
    dissect_u32(s, hf_vip, NULL);
}

static void rsakey_free(void *_rsakey);

static int tibia_dissect_loginserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, guint16 len, packet_info *pinfo, proto_tree *mytree)
{
    enum server_commands cmd;
    const char *str;
    struct state s;

    s.convo  = convo;
    s.tvb    = tvb;
    s.offset = offset;
    s.pinfo  = pinfo;

    while (s.offset < len) {
        proto_item *subti = proto_tree_add_item(mytree, hf_loginserv_command, s.tvb, s.offset, 1, ENC_NA);
        s.tree = proto_item_add_subtree(subti, ett_command);

        switch (cmd = tvb_get_guint8(s.tvb, s.offset++)) {
            case LOGINSERV_DLG_ERROR:
            case LOGINSERV_DLG_ERROR2:
            case LOGINSERV_DLG_MOTD:
                dissect_string(&s, cmd == LOGINSERV_DLG_MOTD ? hf_motd : hf_dlg_error, NULL);
                break;
            case LOGINSERV_DLG_CHARLIST:
                {
                    guint8 char_count = tvb_get_guint8(s.tvb, s.offset);
                    proto_tree_add_item(s.tree, hf_charlist_length, s.tvb, s.offset, 1, ENC_LITTLE_ENDIAN);
                    s.offset++;
                    subti = proto_tree_add_item(s.tree, hf_charlist, s.tvb, s.offset, len - s.offset - 1, ENC_NA);
                    if (char_count) {
                        guint16 port;
                        int ipv4_offset;
                        proto_tree *subtree = proto_item_add_subtree(subti, ett_charlist);
                        while (char_count --> 0) {
                            proto_tree_add_item(subtree, hf_charlist_entry_name, s.tvb, s.offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
                            s.offset += tvb_get_guint16(s.tvb, s.offset, ENC_LITTLE_ENDIAN) + 2;
                            proto_tree_add_item(subtree, hf_charlist_entry_world, s.tvb, s.offset, 2, ENC_LITTLE_ENDIAN | ENC_ASCII);
                            s.offset += tvb_get_guint16(s.tvb, s.offset, ENC_LITTLE_ENDIAN) + 2;

                            ipv4_offset = s.offset;
                            proto_tree_add_item(subtree, hf_charlist_entry_ip, s.tvb, s.offset, 4, ENC_BIG_ENDIAN);
                            s.offset += 4;


                            port = tvb_get_guint16(s.tvb, s.offset, ENC_LITTLE_ENDIAN);

                            proto_tree_add_item(subtree, hf_charlist_entry_port, s.tvb, s.offset, 2, ENC_LITTLE_ENDIAN);
                            s.offset += 2;



                            if (convo->has.rsa_blocks) {
                                struct rsakey *entry = g_new(struct rsakey, 1);
                                alloc_address_tvb(NULL, &entry->addr, AT_IPv4, 4, s.tvb, ipv4_offset);
                                entry->port = port;
                                if (!g_hash_table_contains(rsakeys, entry)) {
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
                                } else {
                                    rsakey_free(entry);
                                }
                            }
                        }
                    }

                    proto_tree_add_item(s.tree, hf_pacc_days, s.tvb, s.offset, 2, ENC_LITTLE_ENDIAN);
                    s.offset += 2;
                }
                break;
            default:
                dissect_unknown(&s, len - s.offset);
        }

        proto_item_set_end(s.tree, s.tvb, s.offset);

        str = try_val_to_str(cmd, from_loginserv_packet_types);
        str = str ? str : "Unknown";
        /* TODO: show packet hex id only on unknown packets */
        /*TODO: this only shows last packet, should show a csv*/
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%x)", str, cmd);
    }

    return s.offset;
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


static int tibia_dissect_gameserv_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, guint16 len, packet_info *pinfo, proto_tree *mytree)
{
    enum server_commands cmd;
    const char *str;
    struct state s;

    s.convo  = convo;
    s.tvb    = tvb;
    s.offset = offset;
    s.pinfo  = pinfo;

    while (s.offset < len) {
        proto_item *subti = proto_tree_add_item(mytree, hf_gameserv_command, s.tvb, s.offset, 1, ENC_NA);
        s.tree = proto_item_add_subtree(subti, ett_command);

        switch (cmd = tvb_get_guint8(s.tvb, s.offset++)) {
            case S_DLG_INFO:
            case S_DLG_ERROR:
            case S_DLG_TOOMANYPLAYERS:
                dissect_string(&s, cmd == S_DLG_ERROR ? hf_dlg_error : hf_dlg_info, NULL);
                break;
            case S_MAPINIT: /* 0x0A, Long playerCreatureId Int unknownU16 (Byte reportBugs?) */
                dissect_unknown(&s, len - s.offset);
                break;
            case S_GMACTIONS: /* 0x0B, Used to be 32 unknown bytes, but with GMs removed it                                     might not be in use anymore */
                dissect_unknown(&s, 32);
                break;
            case S_PLAYERLOC: /* 0x64,Coord pos */
                dissect_coord(&s);
                break;
            case S_TILEUPDATE: /* 0x69,Coord pos TileDescription td */
                dissect_coord(&s);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_ADDITEM: /* 0x6a,Coord pos ThingDescription thing */
                dissect_coord(&s);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_REPLACEITEM: /* 0x6b,Coord pos Byte stackpos ThingDescription thing */
                dissect_coord(&s);
                dissect_stackpos(&s);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_REMOVEITEM: /* 0x6c,Coord pos Byte stackpos */
                dissect_coord(&s);
                dissect_stackpos(&s);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_MOVE_THING: /* 0x6d, */
                dissect_coord(&s);
                dissect_stackpos(&s);
                dissect_coord(&s);
                break;
            case S_CONTAINER: /* 0x6e,Byte index Short containerIcon Byte slotCount ThingDescription item */
                dissect_container(&s);
                dissect_u16(&s, hf_u16, "Container icon");
                dissect_u16(&s, hf_container_slots, NULL);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_CONTAINERCLOSE: /* 0x6f,Byte index */
                dissect_container(&s);
                break;
            case S_ADDITEMCONTAINER: /* 0x70,Byte index ThingDescription itm */
                dissect_container(&s);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_TRANSFORMITEMCONTAINER:/* 0x71,Byte index Byte slot */
                dissect_container(&s);
                dissect_u8(&s, hf_container_slot, NULL);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_REMOVEITEMCONTAINER: /* 0x72,Byte index Byte slot */
                dissect_container(&s);
                dissect_u8(&s, hf_container_slot, NULL);
                break;
            case S_INVENTORYEMPTY: /* 0x78,Byte invSlot */
                dissect_u8(&s, hf_inventory, NULL);
                break;
            case S_INVENTORYITEM: /* 0x79,Byte invSlot ThingDescription itm */
                dissect_u8(&s, hf_inventory, NULL);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_TRADEREQ: /* 0x7d,String otherperson Byte slotCount ThingDescription itm */
                dissect_string(&s, hf_player, NULL);
                dissect_inventory(&s);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_TRADEACK: /* 0x7e,String otherperson Byte slotCount ThingDescription itm */
                dissect_string(&s, hf_player, NULL);
                dissect_inventory(&s);
                dissect_unknown(&s, len - s.offset);
                break;

            case S_TRADECLOSE: /* 0x7f, */
                break;
            case S_LIGHTLEVEL: /* 0x82,Byte lightlevel Byte lightcolor */
                dissect_u8(&s, hf_u8, "Level");
                dissect_u8(&s, hf_u8, "Color");
                break;
            case S_MAGIC_EFFECT: /* 0x83, */
                dissect_coord(&s);
                dissect_u8(&s, hf_u8, "Effect ID");
                break;
            case S_ANIMATEDTEXT: /* 0x84,Coord pos Byte color String message */
                dissect_coord(&s);
                dissect_u8(&s, hf_u8, "Color");
                dissect_string(&s, hf_str, "Message");
                break;
            case S_DISTANCESHOT: /* 0x85,Coord pos1 Byte stackposition Coord pos2 */
                dissect_coord(&s);
                dissect_u8(&s, hf_u8, "Projectile");
                dissect_coord(&s);
                break;
            case S_CREATURESQUARE: /* 0x86,Long creatureid Byte squarecolor */
                dissect_u32(&s, hf_creature, NULL);
                dissect_u8(&s, hf_u8, "Color");
                break;
            case S_CREATURE_HEALTH: /* 0x8C, */
                dissect_u32(&s, hf_creature, NULL);
                dissect_u8(&s, hf_u8, "Percent");
                break;
            case S_CREATURELIGHT: /* 0x8d,Long creatureid Byte ? Byte ? */
                dissect_u32(&s, hf_creature, NULL);
                dissect_unknown(&s, 2);
                break;
            case S_SETOUTFIT: /* 0x8e,Long creatureid Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType // can extended look go here too? */
                dissect_u32(&s, hf_creature, NULL);
                dissect_unknown(&s, len - s.offset);
                break;
            case S_TEXTWINDOW: /* 0x96,Long windowId Byte icon Byte maxlength String message */
                dissect_u32(&s, hf_window, NULL);
                dissect_u8(&s, hf_u8, "Icon");
                dissect_u8(&s, hf_u8, "Max length");
                dissect_string(&s, hf_str, "Message");
                break;
            case S_PLAYER_CONDITION: /* 0xA2, */
                dissect_player_condition(&s);
                break;
            case S_CANCELATTACK: /* 0xA3, */
                break;
            case S_CHANNEL_OPEN:
                dissect_channel_open(&s);
                break;
            case S_OPENPRIV: /* 0xAD,String playerName */
                dissect_string(&s, hf_player, NULL);
                break;
            case S_TEXTMESSAGE: /* 0xB4,Byte msgClass String string */
                dissect_u8(&s, hf_u8, "Class");
                dissect_string(&s, hf_player, NULL);
                break;
            case S_CANCELWALK: /* 0xB5,Byte direction */
                dissect_u8(&s, hf_u8, "Direction");
                break;
            case S_VIPADD: /* 0xd2,long guid string name byte isonline */
                dissect_vip(&s);
                dissect_string(&s, hf_player, NULL);
                dissect_unknown(&s, 1);
                break;
            case S_VIPLOGIN: /* 0xd3,long guid */
                dissect_vip(&s);
                break;
            case S_VIPLOGOUT: /* 0xd4long guid*/
                dissect_vip(&s);
                break;
            case S_PING:
                break;

            case S_OUTFITLIST: /* 0xC8,Byte lookType Byte headType Byte bodyType Byte legsType Byte feetType Byte firstModel Byte lastModel */
                /* TODO This changed with mounts and outfit */
                break;
            case S_FLOORUP: /* 0xBE,Advanced topic; read separate text */
                break;
            case S_FLOORDOWN: /* 0xBF,Advanced topic; read separate text */
                break;
            case S_SPEAK: /* 0xAA, */
            case S_CHANNELSDIALOG: /* 0xAB,Byte channelCount (Int channelId String channelName) */
            case S_STATUSMSG: /* 0xA0,Status status */
            case S_SKILLS: /* 0xA1,Skills skills */
            case S_CREATURESPEED: /* 0x8f,YIKES! I didnt handle this! */
            case S_NONCE: /* 0x1F, */
            case S_GO_NORTH: /* 0x65,MapDescription (18,1) */
            case S_GO_EAST: /* 0x66,MapDescription (1,14) */
            case S_GO_SOUTH: /* 0x67,MapDescription (18,1) */
            case S_GO_WEST: /* 0x68,MapDescription (1,14) */
            default:
                dissect_unknown(&s, len - s.offset);
        }

        proto_item_set_end(s.tree, s.tvb, s.offset);

        str = try_val_to_str(cmd, from_gameserv_packet_types);
        str = str ? str : "Unknown";
        /* TODO: show packet hex id only on unknown packets */
        /*TODO: this only shows last packet, should show a csv*/
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%x)", str, cmd);
    }


    return s.offset;
}

static int tibia_dissect_client_packet(struct tibia_convo *convo, tvbuff_t *tvb, int offset, guint16 len, packet_info *pinfo, proto_tree *mytree)
{
    guint8 cmd;
    const char *str;
    struct state s;

    s.convo  = convo;
    s.tvb    = tvb;
    s.offset = offset;
    s.pinfo  = pinfo;

    while (s.offset < len) {
        proto_item *subti = proto_tree_add_item(mytree, hf_client_command, s.tvb, s.offset, 1, ENC_NA);
        s.tree = proto_item_add_subtree(subti, ett_command);

        switch (cmd = tvb_get_guint8(s.tvb, s.offset++)) {
            /*case C_MOVE_ITEM:*/
            case C_PLAYER_SPEECH:
                dissect_speech(&s);
                break;
            case S_PING:
                break;
            default:
                dissect_unknown(&s, len - s.offset);
        }
        proto_item_set_end(s.tree, s.tvb, s.offset);

        str = try_val_to_str(cmd, from_client_packet_types);
        str = str ? str : "Unknown";
        /*TODO: this only shows last packet, should show a csv*/
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%x)", str, cmd);
    }


    return s.offset;
}

static const value_string operating_systems[] = {
    { 2, "Windows" },
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
        { &hf_proto_version,
            { "Protocol version", "tibia.version",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_client_version,
            { "Client version", "tibia.client_version",
                FT_UINT32, BASE_DEC,
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
        { &hf_content_revision,
            { "Content revision", "tibia.version.content",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_undecoded_rsa_data,
            { "RSA-encrypted login data", "tibia.rsa_data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_undecoded_xtea_data,
            { "XTEA-encrypted game data", "tibia.xtea_data",
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
                NULL, 0x1,
                NULL, HFILL }
        },
        { &hf_game_preview_state,
            { "Game Preview State", "tibia.login.flags.preview",
                FT_BOOLEAN, 8,
                NULL, 0x1,
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
        { &hf_session_key,
            { "Session key", "tibia.session_key",
                FT_UINT_STRING, BASE_NONE,
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
        { &hf_session_key_convo,
            { "Session key", "tibia.session_key",
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
        { &hf_payload_len,
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
                FT_UINT16, BASE_HEX,
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
        { &hf_coords_x,
            { "X-Coordinate", "tibia.coord.x",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_coords_y,
            { "Y-Coordinate", "tibia.coords.y",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_coords_z,
            { "Z-Coordinate", "tibia.coords.z",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_coords,
            { "Coordinates", "tibia.coords",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_stackpos,
            { "Stack position", "tibia.stackpos",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_item,
            { "Item ID", "tibia.item",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_container,
            { "Container index", "tibia.container",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_container_slot,
            { "Container slot", "tibia.container.slot",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_container_slots,
            { "Container slots", "tibia.container.slots",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_inventory,
            { "Inventory slot", "tibia.inventory",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_vip,
            { "VIP GUID", "tibia.vip",
                FT_GUID, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_player,
            { "Player name", "tibia.player",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_creature,
            { "Creature", "tibia.creature",
                FT_GUID, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_window,
            { "Window", "tibia.window",
                FT_GUID, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_u8,
            { "1-octet value", "tibia.u8",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_u16,
            { "2-octet value", "tibia.u16",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_u32,
            { "4-octet value", "tibia.u32",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_str,
            { "String value", "tibia.str",
                FT_UINT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

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

    static ei_register_info ei[] = {
        { &ei_xtea_len_toobig,
            { "tibia.error.xtea.length.toobig", PI_DECRYPTION, PI_ERROR,
                "XTEA-encrypted length exceeds packet", EXPFILL }
        }
    };

    module_t *tibia_module;
    expert_module_t *expert_tibia;

    proto_tibia = proto_register_protocol (
            "Tibia Protocol", /* name */
            "Tibia",          /* short name */
            "tibia"           /* abbrev */
            );
    proto_register_field_array(proto_tibia, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_tibia = expert_register_protocol(proto_tibia);
    expert_register_field_array (expert_tibia, ei, array_length (ei));

    tibia_module = prefs_register_protocol(proto_tibia, proto_reg_handoff_tibia);

    prefs_register_bool_preference(tibia_module, "try_otserv_key", "Try OTServ's RSA key",
        "Try the default RSA key in use by nearly all Open Tibia servers", &try_otserv_key);

    prefs_register_bool_preference(tibia_module, "show_char_name", "Show character name for each packet",
        "Shows active character for every packet", &show_char_name);
    prefs_register_bool_preference(tibia_module, "show_acc_info", "Show account info for each packet",
        "Shows account name/password or session key for every packet", &show_acc_info);
    prefs_register_bool_preference(tibia_module, "show_xtea_key", "Show symmetric key used for each packet",
        "Shows which XTEA key was applied for a packet", &show_xtea_key);
    prefs_register_bool_preference(tibia_module, "dissect_game_commands", "Attempt dissection of game packet commands",
        "Only decrypt packets and dissect login packets. Pass game commands to the data dissector", &dissect_game_commands);

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
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
