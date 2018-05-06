/* sniffer.h
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



#ifndef WOLFSSL_SNIFFER_H
#define WOLFSSL_SNIFFER_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef _WIN32
    #ifdef SSL_SNIFFER_EXPORTS
        #define SSL_SNIFFER_API __declspec(dllexport)
    #else
        #define SSL_SNIFFER_API __declspec(dllimport)
    #endif
#else
    #define SSL_SNIFFER_API
#endif /* _WIN32 */


#ifdef __cplusplus
    extern "C" {
#endif

/* @param typeK: (formerly keyType) was shadowing a global declaration in
 *                wolfssl/wolfcrypt/asn.h line 175
 */
WOLFSSL_API
SSL_SNIFFER_API int ssl_SetPrivateKey(const char* address, int port,
                                      const char* keyFile, int typeK,
                                      const char* password, char* error);

WOLFSSL_API
SSL_SNIFFER_API int ssl_SetNamedPrivateKey(const char* name,
                                           const char* address, int port,
                                           const char* keyFile, int typeK,
                                           const char* password, char* error);

WOLFSSL_API
SSL_SNIFFER_API int ssl_DecodePacket(const unsigned char* packet, int length,
                                     unsigned char** data, char* error);

WOLFSSL_API
SSL_SNIFFER_API int ssl_FreeDecodeBuffer(unsigned char** data, char* error);

WOLFSSL_API
SSL_SNIFFER_API int ssl_FreeZeroDecodeBuffer(unsigned char** data, int sz,
                                             char* error);

WOLFSSL_API
SSL_SNIFFER_API int ssl_Trace(const char* traceFile, char* error);

WOLFSSL_API
SSL_SNIFFER_API int ssl_EnableRecovery(int onOff, int maxMemory, char* error);

WOLFSSL_API
SSL_SNIFFER_API int ssl_GetSessionStats(unsigned int* active,
                                        unsigned int* total,
                                        unsigned int* peak,
                                        unsigned int* maxSessions,
                                        unsigned int* missedData,
                                        unsigned int* reassemblyMemory,
                                        char* error);

WOLFSSL_API void ssl_InitSniffer(void);

WOLFSSL_API void ssl_FreeSniffer(void);



#define WOLFSSL_FLAG_IGNORE_ACKS		0x0001
#define WOLFSSL_FLAG_IGNORE_UNKNOWN_HS	0x0002

WOLFSSL_API
SSL_SNIFFER_API void ssl_GetErrorMessage(int idx, char *error);

WOLFSSL_API
SSL_SNIFFER_API int ssl_DecodePacketExtVlan(const unsigned char* packet, int length,
										unsigned short vlan,
										unsigned char** data, char* error, int* err);
WOLFSSL_API
SSL_SNIFFER_API int ssl_IsServerRegistered(unsigned long addr, unsigned short port);

WOLFSSL_API
SSL_SNIFFER_API int ssl_IsNamedServerRegistered(char *sni, unsigned long addr, unsigned short port);

WOLFSSL_API
SSL_SNIFFER_API void ssl_SetSessionTimeout(int session_timeout_sec);

WOLFSSL_API
SSL_SNIFFER_API void ssl_GetSnifferSessionStats(unsigned long *active, unsigned long *expired, unsigned long *total, unsigned long *peak, unsigned long *allocd, unsigned long *freed);

WOLFSSL_API
SSL_SNIFFER_API void ssl_ReleaseSession(const unsigned char* packet, int length, unsigned short vlan);

WOLFSSL_API
SSL_SNIFFER_API void ssl_SetFlags(unsigned int flags);

/* ssl_SetPrivateKey typeKs */
enum {
    FILETYPE_PEM = 1,
    FILETYPE_DER = 2,
};


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* wolfSSL_SNIFFER_H */

