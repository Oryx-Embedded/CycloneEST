/**
 * @file est_client_misc.c
 * @brief Helper functions for EST client
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2024-2025 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.5.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL EST_TRACE_LEVEL

//Dependencies
#include "est/est_client.h"
#include "est/est_client_misc.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_create.h"
#include "cipher/cipher_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (EST_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Generate PKCS #10 certificate request
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientGenerateCsr(EstClientContext *context)
{
   error_t error;
   size_t n;
   char_t buffer[64];

   //Any registered callback?
   if(context->csrGenCallback != NULL)
   {
      //The client generating the CSR obtains the "tls-unique" value from the TLS
      //subsystem as described in RFC 5929 (refer to RFC 7030, section 3.5)
      error = tlsExportChannelBinding(context->httpClientContext.tlsContext,
         "tls-unique", (uint8_t *) buffer, &n);

      //For (D)TLS 1.3, Appendix C.5 of RFC 8446 describes the lack of channel
      //bindings similar to "tls-unique"
      if(error == ERROR_INVALID_VERSION)
      {
         //"tls-exporter" can be used instead to derive a 32-byte tls-exporter
         //binding from the (D)TLS 1.3 master secret (refer to RFC 9148,
         //section 3)
         error = tlsExportChannelBinding(context->httpClientContext.tlsContext,
            "tls-exporter", (uint8_t *) buffer, &n);
      }

      //Check status code
      if(!error)
      {
         //The "tls-unique" value is base64 encoded
         base64Encode(buffer, n, buffer, &n);

         //The resulting string is placed in the certification request
         //challenge-password field
         error = context->csrGenCallback(context, buffer, context->csr,
            EST_CLIENT_MAX_CSR_LEN, &context->csrLen);
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_CSR;
   }

   //Return status code
   return error;
}


/**
 * @brief TLS initialization
 * @param[in] httpClientContext Pointer to the HTTP client context
 * @param[in] tlsContext Pointer to the TLS context
 * @param[in] param Pointer to the EST client context
 * @return Error code
 **/

error_t estClientInitTlsContext(HttpClientContext *httpClientContext,
   TlsContext *tlsContext, void *param)
{
   error_t error;
   EstClientContext *context;

   //Point to the EST client context
   context = (EstClientContext *) param;

   //TLS 1.1 (or a later version) must be used for all EST communications
   //(refer to RFC 7030, section 3.3)
   error = tlsSetVersion(tlsContext, TLS_VERSION_1_1, TLS_VERSION_1_3);

   //Check status code
   if(!error)
   {
      //Set the PRNG algorithm to be used
      error = tlsSetPrng(tlsContext, context->prngAlgo, context->prngContext);
   }

   //If the client disables the implicit TA database, and if the EST server
   //certificate was verified using an implicit TA database entry, then the
   //client must include the "Trusted CA Indication" extension in future TLS
   //sessions (refer to RFC 7030, section 4.1.3)
   if(context->useExplicitTa)
   {
#if (TLS_TRUSTED_CA_KEYS_SUPPORT == ENABLED)
      //Check status code
      if(!error)
      {
         //The "Trusted CA Indication" extension indicates to the server that
         //only an EST server certificate authenticatable by the explicit TA
         //database entry is now acceptable
         error = tlsEnableTrustedCaKeys(tlsContext, TRUE);
      }
#endif

#if (TLS_CERT_AUTHORITIES_SUPPORT == ENABLED)
      //Check status code
      if(!error)
      {
         //The "trusted_ca_keys" extension is not used in TLS 1.3
         error = tlsEnableCertAuthorities(tlsContext, TRUE);
      }
#endif
   }

   //Check status code
   if(!error)
   {
      //Perform TLS related initialization
      if(context->tlsInitCallback != NULL)
      {
         //Invoke callback function
         error = context->tlsInitCallback(context, tlsContext);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }
   }

   //Check status code
   if(!error)
   {
      //The EST client implicit or explicit TA database is used to validate the
      //EST server certificate
      error = tlsSetTrustedCaList(tlsContext, context->caCerts,
         context->caCertsLen);
   }

   //Return status code
   return error;
}

#endif
