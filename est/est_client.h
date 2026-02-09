/**
 * @file est_client.h
 * @brief EST client
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2024-2026 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneEST Open.
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.0
 **/

#ifndef _EST_CLIENT_H
#define _EST_CLIENT_H

//Dependencies
#include "est_config.h"
#include "core/net.h"
#include "http/http_client.h"


/*
 * CycloneEST Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneEST Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneEST Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneEST Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#ifndef GPL_LICENSE_TERMS_ACCEPTED
   #error Before compiling CycloneEST Open, you must accept the terms of the GPL license
#endif

//Version string
#define CYCLONE_EST_VERSION_STRING "2.6.0"
//Major version
#define CYCLONE_EST_MAJOR_VERSION 2
//Minor version
#define CYCLONE_EST_MINOR_VERSION 6
//Revision number
#define CYCLONE_EST_REV_NUMBER 0

//EST client support
#ifndef EST_CLIENT_SUPPORT
   #define EST_CLIENT_SUPPORT DISABLED
#elif (EST_CLIENT_SUPPORT != ENABLED && EST_CLIENT_SUPPORT != DISABLED)
   #error EST_CLIENT_SUPPORT parameter is not valid
#endif

//RSA key support
#ifndef EST_CLIENT_RSA_SUPPORT
   #define EST_CLIENT_RSA_SUPPORT ENABLED
#elif (EST_CLIENT_RSA_SUPPORT != ENABLED && EST_CLIENT_RSA_SUPPORT != DISABLED)
   #error EST_CLIENT_RSA_SUPPORT parameter is not valid
#endif

//ECDSA key support
#ifndef EST_CLIENT_ECDSA_SUPPORT
   #define EST_CLIENT_ECDSA_SUPPORT ENABLED
#elif (EST_CLIENT_ECDSA_SUPPORT != ENABLED && EST_CLIENT_ECDSA_SUPPORT != DISABLED)
   #error EST_CLIENT_ECDSA_SUPPORT parameter is not valid
#endif

//Default timeout
#ifndef EST_CLIENT_DEFAULT_TIMEOUT
   #define EST_CLIENT_DEFAULT_TIMEOUT 20000
#elif (EST_CLIENT_DEFAULT_TIMEOUT < 1000)
   #error EST_CLIENT_DEFAULT_TIMEOUT parameter is not valid
#endif

//Size of the buffer for input/output operations
#ifndef EST_CLIENT_BUFFER_SIZE
   #define EST_CLIENT_BUFFER_SIZE 4096
#elif (EST_CLIENT_BUFFER_SIZE < 512)
   #error EST_CLIENT_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of host names
#ifndef EST_CLIENT_MAX_HOST_LEN
   #define EST_CLIENT_MAX_HOST_LEN 64
#elif (EST_CLIENT_MAX_HOST_LEN < 1)
   #error EST_CLIENT_MAX_HOST_LEN parameter is not valid
#endif

//Maximum length of URIs
#ifndef EST_CLIENT_MAX_URI_LEN
   #define EST_CLIENT_MAX_URI_LEN 64
#elif (EST_CLIENT_MAX_URI_LEN < 1)
   #error EST_CLIENT_MAX_URI_LEN parameter is not valid
#endif

//Maximum length of media types
#ifndef EST_CLIENT_MAX_CONTENT_TYPE_LEN
   #define EST_CLIENT_MAX_CONTENT_TYPE_LEN 40
#elif (EST_CLIENT_MAX_CONTENT_TYPE_LEN < 1)
   #error EST_CLIENT_MAX_CONTENT_TYPE_LEN parameter is not valid
#endif

//Maximum length of CSR
#ifndef EST_CLIENT_MAX_CSR_LEN
   #define EST_CLIENT_MAX_CSR_LEN 1024
#elif (EST_CLIENT_MAX_CSR_LEN < 1)
   #error EST_CLIENT_MAX_CSR_LEN parameter is not valid
#endif

//Maximum length of certificate
#ifndef EST_CLIENT_MAX_CERT_LEN
   #define EST_CLIENT_MAX_CERT_LEN 2048
#elif (EST_CLIENT_MAX_CERT_LEN < 1)
   #error EST_CLIENT_MAX_CERT_LEN parameter is not valid
#endif

//Maximum length of CA certificates
#ifndef EST_CLIENT_MAX_CA_CERTS_LEN
   #define EST_CLIENT_MAX_CA_CERTS_LEN 4096
#elif (EST_CLIENT_MAX_CA_CERTS_LEN < 1)
   #error EST_CLIENT_MAX_CA_CERTS_LEN parameter is not valid
#endif

//Application specific context
#ifndef EST_CLIENT_PRIVATE_CONTEXT
   #define EST_CLIENT_PRIVATE_CONTEXT
#endif

//Forward declaration of EstClientContext structure
struct _EstClientContext;
#define EstClientContext struct _EstClientContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief EST client states
 **/

typedef enum
{
   EST_CLIENT_STATE_DISCONNECTED         = 0,
   EST_CLIENT_STATE_CONNECTING           = 1,
   EST_CLIENT_STATE_CONNECTED            = 2,
   EST_CLIENT_STATE_GET_CA               = 3,
   EST_CLIENT_STATE_CSR_GEN              = 4,
   EST_CLIENT_STATE_ENROLL               = 5,
   EST_CLIENT_STATE_REENROLL             = 6,
   EST_CLIENT_STATE_DISCONNECTING        = 7
} EstClientState;


/**
 * @brief HTTP request states
 */

typedef enum
{
   EST_REQ_STATE_INIT           = 0,
   EST_REQ_STATE_FORMAT_HEADER  = 1,
   EST_REQ_STATE_SEND_HEADER    = 2,
   EST_REQ_STATE_FORMAT_BODY    = 3,
   EST_REQ_STATE_SEND_BODY      = 4,
   EST_REQ_STATE_RECEIVE_HEADER = 5,
   EST_REQ_STATE_PARSE_HEADER   = 6,
   EST_REQ_STATE_RECEIVE_BODY   = 7,
   EST_REQ_STATE_CLOSE_BODY     = 8,
   EST_REQ_STATE_COMPLETE       = 9
} EstRequestState;


/**
 * @brief TLS initialization callback function
 **/

typedef error_t (*EstClientTlsInitCallback)(EstClientContext *context,
   TlsContext *tlsContext);


/**
 * @brief CSR generation callback function
 **/

typedef error_t (*EstClientCsrGenCallback)(EstClientContext *context,
   const char_t *challengePwd, uint8_t *buffer, size_t size, size_t *length);


/**
 * @brief EST client context
 **/

struct _EstClientContext
{
   EstClientState state;                                    ///<EST client state
   EstRequestState requestState;                            ///<HTTP request state
   NetContext *netContext;                                  ///<TCP/IP stack context
   NetInterface *interface;                                 ///<Underlying network interface
   systime_t timeout;                                       ///<Timeout value
   const PrngAlgo *prngAlgo;                                ///<Pseudo-random number generator to be used
   void *prngContext;                                       ///<Pseudo-random number generator context
   HttpClientContext httpClientContext;                     ///<HTTP client context
   EstClientTlsInitCallback tlsInitCallback;                ///<TLS initialization callback function
   EstClientCsrGenCallback csrGenCallback;                  ///<CSR generation callback function
   char_t serverName[EST_CLIENT_MAX_HOST_LEN + 1];          ///<Host name of the EST server
   uint16_t serverPort;                                     ///<TCP port number
   char_t pathPrefix[EST_CLIENT_MAX_URI_LEN + 1];           ///<Path prefix
   X509KeyType keyType;                                     ///<Public key type
#if (EST_CLIENT_RSA_SUPPORT == ENABLED)
   RsaPublicKey rsaPublicKey;                               ///<RSA public key
   RsaPrivateKey rsaPrivateKey;                             ///<RSA private key
#endif
#if (EST_CLIENT_ECDSA_SUPPORT == ENABLED)
   EcPublicKey ecPublicKey;                                 ///<EC public key
   EcPrivateKey ecPrivateKey;                               ///<EC private key
#endif
   uint8_t csr[EST_CLIENT_MAX_CSR_LEN];                     ///<CSR
   size_t csrLen;                                           ///<Length of the CSR, in bytes
   uint8_t cert[EST_CLIENT_MAX_CERT_LEN];                   ///<Client's certificate
   size_t certLen;                                          ///<Length of the client's certificate, in bytes
   char_t caCerts[EST_CLIENT_MAX_CA_CERTS_LEN];             ///<CA certificates
   size_t caCertsLen;                                       ///<Length of the CA certificates, in bytes
   uint8_t buffer[EST_CLIENT_BUFFER_SIZE];                  ///<Memory buffer for input/output operations
   size_t bufferLen;                                        ///<Length of the buffer, in bytes
   size_t bufferPos;                                        ///<Current position in the buffer
   bool_t useExplicitTa;                                    ///<Use of explicit TA database
   uint_t allowedAuthModes;                                 ///<Allowed HTTP authentication modes
   HttpAuthMode selectedAuthMode;                           ///<Selected HTTP authentication mode
   uint_t statusCode;                                       ///<HTTP status code
   char_t contentType[EST_CLIENT_MAX_CONTENT_TYPE_LEN + 1]; ///<Content type of the response
   EST_CLIENT_PRIVATE_CONTEXT                               ///<Application specific context
};


//EST client related functions
error_t estClientInit(EstClientContext *context);

error_t estClientRegisterTlsInitCallback(EstClientContext *context,
   EstClientTlsInitCallback callback);

error_t estClientRegisterCsrGenCallback(EstClientContext *context,
   EstClientCsrGenCallback callback);

error_t estClientSetPrng(EstClientContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t estClientSetTimeout(EstClientContext *context, systime_t timeout);

error_t estClientSetHost(EstClientContext *context, const char_t *host);

error_t estClientSetPathPrefix(EstClientContext *context,
   const char_t *pathPrefix);

error_t estClientSetAllowedAuthModes(EstClientContext *context,
   uint_t allowedAuthModes);

error_t estClientSetAuthInfo(EstClientContext *context, const char_t *username,
   const char_t *password);

error_t estClientBindToInterface(EstClientContext *context,
   NetInterface *interface);

error_t estClientConnect(EstClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort);

error_t estClientLoadKeyPair(EstClientContext *context,
   const char_t *publicKey, size_t publicKeyLen, const char_t *privateKey,
   size_t privateKeyLen, const char_t *password);

void estClientUnloadKeyPair(EstClientContext *context);

error_t estClientLoadCert(EstClientContext *context,
   const char_t *input, size_t length);

error_t estClientStoreCert(EstClientContext *context,
   char_t *output, size_t *written);

error_t estClientLoadCaCerts(EstClientContext *context,
   const char_t *input, size_t length);

error_t estClientStoreCaCerts(EstClientContext *context,
   char_t *output, size_t *written);

error_t estClientGetCaCerts(EstClientContext *context);
error_t estClientEnroll(EstClientContext *context);
error_t estClientReEnroll(EstClientContext *context);

error_t estClientDisconnect(EstClientContext *context);
error_t estClientClose(EstClientContext *context);

void estClientDeinit(EstClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
