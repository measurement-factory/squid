/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/***********************************************************
    Copyright 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

#include "squid.h"
#include "asn1.h"
#include "cache_snmp.h"
#include "parse.h"
#include "snmp_debug.h"
#include "snmp_pdu.h"
#include "snmp_vars.h"
#include "util.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif

/*
 * This is one element of an object identifier with either an integer subidentifier,
 * or a textual string label, or both.
 * The subid is -1 if not present, and label is NULL if not present.
 */
struct subid {
    int subid;
    char *label;
};

/*
 * A linked list of nodes.
 */
struct node {
    struct node *next;
    char label[64];     /* This node's (unique) textual name */
    u_int subid;        /* This node's integer subidentifier */
    char parent[64];        /* The parent's textual name */
    int type;           /* The type of object this represents */
    struct enum_list *enums;    /* (optional) list of enumerated integers (otherwise NULL) */
};

/* types of tokens */
#define CONTINUE    -1
#define ENDOFFILE   0
#define LABEL       1
#define SUBTREE     2
#define SYNTAX      3
#undef OBJID
#define OBJID       4
#define OCTETSTR    5
#undef INTEGER
#define INTEGER     6
#define NETADDR     7
#define IPADDR      8
#define COUNTER     9
#define GAUGE       10
#define TIMETICKS   11
#define SNMP_OPAQUE     12
#define NUL     13
#define SEQUENCE    14
#define OF      15      /* SEQUENCE OF */
#define OBJTYPE     16
#define ACCESS      17
#define READONLY    18
#define READWRITE   19
#define WRITEONLY   20
#undef NOACCESS
#define NOACCESS    21
#define SNMP_STATUS 22
#define MANDATORY   23
#define SNMP_OPTIONAL    24
#define OBSOLETE    25
#define RECOMMENDED 26
#define PUNCT       27
#define EQUALS      28
#define NUMBER      29
#define LEFTBRACKET 30
#define RIGHTBRACKET 31
#define LEFTPAREN   32
#define RIGHTPAREN  33
#define COMMA       34
/* For SNMPv2 SMI pseudo-compliance */
#define DESCRIPTION 35
#define INDEX       36
#define QUOTE       37

struct tok {
    const char *name;           /* token name */
    int len;            /* length not counting nul */
    int token;          /* value */
    int hash;           /* hash of name */
    struct tok *next;       /* pointer to next in hash table */
};

#define HASHSIZE    32
#define BUCKET(x)   (x & 0x01F)

#define NHASHSIZE    128
#define NBUCKET(x)   (x & 0x7F)



























