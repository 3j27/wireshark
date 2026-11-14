/* packet-manolito.c
 * Routines for Blubster/Piolet Manolito Protocol dissection
 * Copyright 2003-2004, Jeff Connelly <shellreef+mp2p@gmail.com>
 *
 * Official home page: http://openlito.sourceforge.net/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

void proto_register_manolito(void);
void proto_reg_handoff_manolito(void);

static dissector_handle_t manolito_handle;

#define MANOLITO_PORT   41170 /* Not IANA registered */

static int proto_manolito;

static int hf_manolito_checksum;
static int hf_manolito_checksum_status;
static int hf_manolito_checksum_calculated;
static int hf_manolito_checksum_padding;
static int hf_manolito_seqno;
static int hf_manolito_src;
static int hf_manolito_dest;
static int hf_manolito_options_short;
static int hf_manolito_options;
static int hf_manolito_string;
static int hf_manolito_integer;

static int ett_manolito;

static expert_field ei_manolito_type;
static expert_field ei_manolito_checksum_bad;

/* The sender converts its ANSI string to Unicode (VB6 StrConv(s, vbUnicode))
 * before checksumming, so the result depends on the sender's code page.
 * The pages differ in 0x80..0x9f for all of them, and 0xa0..0xff differs for
 * the non-Western pages, so the checksum depends on the sender's locale. */
enum manolito_ansi_page {
	MANOLITO_CP1252 = 0,	/* Western European (default) */
	MANOLITO_CP1250,	/* Central European */
	MANOLITO_CP1251,	/* Cyrillic */
	MANOLITO_LATIN1		/* ISO-8859-1, no 0x80..0x9f remapping */
};

static int pref_ansi_page = MANOLITO_CP1252;

#define MANOLITO_STRING  1
#define MANOLITO_INTEGER 0

static const value_string field_longname[] = {
	{ 0x4144, "???" },
	{ 0x4252, "Bit Rate" },
	{ 0x434b, "Checksum" },
	{ 0x434e, "Client Name" },
	{ 0x4356, "Client Version" },
	{ 0x4643, "Frequency" },
	{ 0x464c, "File Length" },
	{ 0x464e, "Filename" },
	{ 0x484e, "???" },
	{ 0x4944, "Identification" },
	{ 0x4d45, "Message" },
	{ 0x4e43, "Num. Connections" },
	{ 0x4e49, "Network ID" },
	{ 0x4e4e, "Nickname" },
	{ 0x5054, "Port" },
	{ 0x5346, "Shared Files" },
	{ 0x534b, "Shared Kilobytes" },
	{ 0x534c, "Song Length (s)" },
	{ 0x5354, "???" },
	{ 0x564c, "Velocity" },
	{ 0, NULL }
};
static value_string_ext field_longname_ext = VALUE_STRING_EXT_INIT(field_longname);

static const value_string manolito_checksum_status[] = {
	{ PROTO_CHECKSUM_E_BAD,        "Bad" },
	{ PROTO_CHECKSUM_E_GOOD,       "Good" },
	{ PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
	{ PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },
	{ 0, NULL }
};

static const value_string manolito_ansi_page_vals[] = {
	{ MANOLITO_CP1252, "Windows-1252 (Western European, default)" },
	{ MANOLITO_CP1250, "Windows-1250 (Central European)" },
	{ MANOLITO_CP1251, "Windows-1251 (Cyrillic)" },
	{ MANOLITO_LATIN1, "ISO-8859-1 (no 0x80..0x9f remapping)" },
	{ 0, NULL }
};
/* --- manolito checksum core: begin --- */

/* CRC-16/CCITT: poly 0x1021, MSB first, init 0, no final xor. */
#define MANOLITO_CRC16_POLY	0x1021
#define MANOLITO_CRC16_INIT	0x0000

static uint16_t
manolito_crc16_byte(uint16_t crc, uint8_t byte)
{
	unsigned bit;

	crc ^= (uint16_t)byte << 8;
	for (bit = 0; bit < 8; bit++) {
		if (crc & 0x8000)
			crc = (uint16_t)((crc << 1) ^ MANOLITO_CRC16_POLY);
		else
			crc = (uint16_t)(crc << 1);
	}
	return crc;
}

/* Code page tables.  CP1252 agrees with Unicode for 0xa0..0xff, so only its
 * C1 range needs a table; CP1250 and CP1251 differ across 0x80..0xff.  Bytes
 * that the code page leaves undefined keep their value, which is what
 * MultiByteToWideChar() does for these pages. */
static const uint16_t manolito_c1_cp1252[32] = {
	0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
	0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
	0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178
};

static const uint16_t manolito_high_cp1250[128] = {
	0x20AC, 0x0081, 0x201A, 0x0083, 0x201E, 0x2026, 0x2020, 0x2021,
	0x0088, 0x2030, 0x0160, 0x2039, 0x015A, 0x0164, 0x017D, 0x0179,
	0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x0098, 0x2122, 0x0161, 0x203A, 0x015B, 0x0165, 0x017E, 0x017A,
	0x00A0, 0x02C7, 0x02D8, 0x0141, 0x00A4, 0x0104, 0x00A6, 0x00A7,
	0x00A8, 0x00A9, 0x015E, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x017B,
	0x00B0, 0x00B1, 0x02DB, 0x0142, 0x00B4, 0x00B5, 0x00B6, 0x00B7,
	0x00B8, 0x0105, 0x015F, 0x00BB, 0x013D, 0x02DD, 0x013E, 0x017C,
	0x0154, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x0139, 0x0106, 0x00C7,
	0x010C, 0x00C9, 0x0118, 0x00CB, 0x011A, 0x00CD, 0x00CE, 0x010E,
	0x0110, 0x0143, 0x0147, 0x00D3, 0x00D4, 0x0150, 0x00D6, 0x00D7,
	0x0158, 0x016E, 0x00DA, 0x0170, 0x00DC, 0x00DD, 0x0162, 0x00DF,
	0x0155, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x013A, 0x0107, 0x00E7,
	0x010D, 0x00E9, 0x0119, 0x00EB, 0x011B, 0x00ED, 0x00EE, 0x010F,
	0x0111, 0x0144, 0x0148, 0x00F3, 0x00F4, 0x0151, 0x00F6, 0x00F7,
	0x0159, 0x016F, 0x00FA, 0x0171, 0x00FC, 0x00FD, 0x0163, 0x02D9
};

static const uint16_t manolito_high_cp1251[128] = {
	0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021,
	0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F,
	0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x0098, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F,
	0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7,
	0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
	0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7,
	0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457,
	0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,
	0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F,
	0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427,
	0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F,
	0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437,
	0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F,
	0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,
	0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F
};

static uint16_t
manolito_ansi_to_unicode(uint8_t b, int page)
{
	if (b < 0x80)
		return b;

	switch (page) {
	case MANOLITO_CP1250:
		return manolito_high_cp1250[b - 0x80];
	case MANOLITO_CP1251:
		return manolito_high_cp1251[b - 0x80];
	case MANOLITO_LATIN1:
		return b;
	default:
		return (b <= 0x9f) ? manolito_c1_cp1252[b - 0x80] : b;
	}
}

/* Checksum of an ANSI message: the CRC runs over the UTF-16LE bytes of the
 * Unicode string the sender built, i.e. every byte contributes two bytes. */
static uint16_t
manolito_checksum_buf(const uint8_t *buf, unsigned len, int page)
{
	uint16_t crc = MANOLITO_CRC16_INIT;
	unsigned i;

	for (i = 0; i < len; i++) {
		uint16_t u = manolito_ansi_to_unicode(buf[i], page);

		crc = manolito_crc16_byte(crc, (uint8_t)(u & 0x00ff));
		crc = manolito_crc16_byte(crc, (uint8_t)(u >> 8));
	}
	return crc;
}
/* --- manolito checksum core: end --- */


static int
dissect_manolito(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* dissector_data _U_)
{
	unsigned offset = 0;
	proto_item *ti;
	proto_tree *manolito_tree;
	char *packet_type = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MANOLITO");

	ti = proto_tree_add_item(tree, proto_manolito, tvb, offset, -1, ENC_NA);

	manolito_tree = proto_item_add_subtree(ti, ett_manolito);

	/* MANOLITO packet header (network byte order) */
	/* The 32-bit field only carries a 16-bit checksum (bytes 2..3 are always
	 * zero).  It covers everything after it, but the sender hashed the
	 * UTF-16 form of the message, not the raw bytes. */
	{
		unsigned plen = tvb_reported_length(tvb);
		uint16_t computed = 0;

		if (plen > 4) {
			uint8_t *msg = (uint8_t *)tvb_memdup(pinfo->pool, tvb, 4, plen - 4);

			computed = manolito_checksum_buf(msg, plen - 4, pref_ansi_page);
		}

		proto_tree_add_checksum(manolito_tree, tvb, offset, hf_manolito_checksum,
		    hf_manolito_checksum_status, &ei_manolito_checksum_bad, pinfo,
		    computed, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
		proto_tree_add_uint(manolito_tree, hf_manolito_checksum_calculated,
		    tvb, offset, 0, computed);
		proto_tree_add_item(manolito_tree, hf_manolito_checksum_padding,
		    tvb, offset + 2, 2, ENC_BIG_ENDIAN);

		if (plen > 4 && computed != tvb_get_ntohs(tvb, offset))
			proto_item_append_text(ti, " (bad checksum)");
	}
	offset += 4;
	proto_tree_add_item(manolito_tree,
	    hf_manolito_seqno, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(manolito_tree,
	    hf_manolito_src, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(manolito_tree,
	    hf_manolito_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	if (tvb_reported_length_remaining(tvb, offset) == 3) {
		proto_tree_add_item(manolito_tree,
		    hf_manolito_options_short, tvb, offset, 3, ENC_BIG_ENDIAN);
		offset += 3;
		col_set_str(pinfo->cinfo, COL_INFO, "Ping (truncated)");
		return offset;
	}

	proto_tree_add_item(manolito_tree,
			hf_manolito_options, tvb, 16, 4, ENC_BIG_ENDIAN);
	offset += 4;

	if (tvb_reported_length_remaining(tvb, offset) == 0) {
		col_set_str(pinfo->cinfo, COL_INFO, "Ping");
		return offset;
	}

	/* fields format: 2-byte name, optional NULL, 1-byte lenlen, */
	/* that many bytes(len or data), for NI,CN,VL is len, more */
	/* (that many bytes) data follows; else is raw data. */
	do
	{
		uint16_t    field_name;        /* 16-bit field name */
		uint8_t     dtype;             /* data-type */
		uint8_t     length;            /* length */
		int         start;             /* field starting location */
		uint8_t    *field_name_str;

		start = offset;

		/* 2-byte field name */
		field_name = tvb_get_ntohs(tvb, offset);
		field_name_str = tvb_get_string_enc(pinfo->pool, tvb, offset, 2, ENC_ASCII);
		if (!packet_type) {
			/* Identify the packet based on existing fields */
			/* Maybe using the options fields is a better idea...*/
			if (field_name == 0x434b)    /* CK */
				packet_type = "Search Hit";
			if (field_name == 0x4e43)    /* NC */
				packet_type = "User Information";
			if (field_name == 0x464e)    /* FN - if only field */
				packet_type = "Search Query";
			if (field_name == 0x4944)    /* ID ?? search by CK? */
				packet_type = "Search Query (by hash)";
			if (field_name == 0x5054)    /* PT */
				packet_type = "Download Request";
			if (field_name == 0x4d45)    /* ME */
				packet_type = "Chat";
		}
		offset += 2;

		/* 1-byte data type */
		dtype = tvb_get_uint8(tvb, offset);
		offset++;
		length = tvb_get_uint8(tvb, offset);
		offset++;

		if (dtype == MANOLITO_STRING) {
			const char *str;

			str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII);
			proto_tree_add_string_format(manolito_tree, hf_manolito_string, tvb, start,
					4+length, str, "%s (%s): %s",
					field_name_str,
					val_to_str_ext_const(field_name, &field_longname_ext, "unknown"),
					str);
			offset += length;
		}
		else if (dtype == MANOLITO_INTEGER) {
			bool len_ok = true;
			uint64_t n = 0;

			/* integers can be up to 5 bytes */
			switch(length)
			{
				case 5:
					n = tvb_get_ntoh40(tvb, offset);
					break;
				case 4:
					n = tvb_get_ntohl(tvb, offset);
					break;
				case 3:
					n = tvb_get_ntoh24(tvb, offset);
					break;
				case 2:
					n = tvb_get_ntohs(tvb, offset);
					break;
				case 1:
					n = tvb_get_uint8(tvb, offset);
					break;

				default:
					len_ok = false;
			}

			if (len_ok) {
				proto_tree_add_uint64_format(manolito_tree, hf_manolito_integer, tvb, start,
						4+length, n, "%s (%s): %" PRIu64,
						field_name_str,
						val_to_str_ext_const(field_name, &field_longname_ext, "unknown"),
						n);
			}
			else {
				/* XXX - expert info */
			}
			offset += length;
		}
		else {
			proto_tree_add_expert_format(manolito_tree, pinfo, &ei_manolito_type,
					tvb, start, offset - start, "Unknown type %d", dtype);
		}

	} while(tvb_reported_length_remaining(tvb, offset));

	if (packet_type)
		col_set_str(pinfo->cinfo, COL_INFO, packet_type);

	return offset;
}


void
proto_register_manolito(void)
{
	static hf_register_info hf[] = {
		{ &hf_manolito_checksum,
		  { "Checksum", "manolito.checksum",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Checksum over the rest of the packet", HFILL }
		},
		{ &hf_manolito_checksum_status,
		  { "Checksum Status", "manolito.checksum.status",
		    FT_UINT8, BASE_DEC, VALS(manolito_checksum_status), 0,
		    NULL, HFILL }
		},
		{ &hf_manolito_checksum_calculated,
		  { "Calculated Checksum", "manolito.checksum.calculated",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Checksum computed from this packet", HFILL }
		},
		{ &hf_manolito_checksum_padding,
		  { "Checksum Padding", "manolito.checksum.padding",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Always zero; the field is 32 bits wide but only 16 are used", HFILL }
		},
		{ &hf_manolito_seqno,
		  { "Sequence Number", "manolito.seqno",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "Incremental sequence number", HFILL }
		},
		{ &hf_manolito_src,
		  { "Forwarded IP Address", "manolito.src",
		    FT_IPv4, BASE_NONE, NULL, 0,
		    "Host packet was forwarded from (or 0)", HFILL }
		},
		{ &hf_manolito_dest,
		  { "Destination IP Address", "manolito.dest",
		    FT_IPv4, BASE_NONE, NULL, 0,
		    "Destination IPv4 address", HFILL }
		},
		{ &hf_manolito_options_short,
		  { "Options", "manolito.options",
		    FT_UINT24, BASE_HEX, NULL, 0,
		    "Packet-dependent data", HFILL }
		},
		{ &hf_manolito_options,
		  { "Options", "manolito.options",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "Packet-dependent data", HFILL }
		},
		{ &hf_manolito_string,
		  { "String field", "manolito.string",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_manolito_integer,
		  { "Integer field", "manolito.integer",
		    FT_UINT40, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_manolito,
	};

	static ei_register_info ei[] = {
		{ &ei_manolito_type, { "manolito.type.unknown", PI_PROTOCOL, PI_WARN, "Unknown type", EXPFILL }},
		{ &ei_manolito_checksum_bad, { "manolito.checksum.bad", PI_CHECKSUM, PI_WARN, "Bad checksum", EXPFILL }},
	};

	expert_module_t* expert_manolito;
	module_t *manolito_module;

	proto_manolito = proto_register_protocol("Blubster/Piolet MANOLITO Protocol", "Manolito", "manolito");

	proto_register_field_array(proto_manolito, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_manolito = expert_register_protocol(proto_manolito);
	expert_register_field_array(expert_manolito, ei, array_length(ei));

	manolito_module = prefs_register_protocol(proto_manolito, NULL);
	prefs_register_enum_preference(manolito_module, "ansi_code_page",
	    "ANSI code page of the sender",
	    "Code page Blubster used to convert the message to Unicode before "
	    "checksumming.  Only matters for bytes >= 0x80.",
	    &pref_ansi_page, manolito_ansi_page_vals, false);

	manolito_handle = register_dissector("manolito", dissect_manolito, proto_manolito);
}


void
proto_reg_handoff_manolito(void)
{
	dissector_add_uint_with_preference("udp.port", MANOLITO_PORT, manolito_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
