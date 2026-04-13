/**
 * @file est_client_resp_parse.c
 * @brief EST response parsing
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
 * @version 2.6.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL EST_TRACE_LEVEL

//Dependencies
#include "est/est_client.h"
#include "est/est_client_resp_parse.h"
#include "est/est_client_misc.h"
#include "pkcs7/pkcs7_parse.h"
#include "pkcs7/pkcs7_decrypt.h"
#include "pkcs7/pkcs7_sign_verify.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/pem_export.h"
#include "encoding/base64.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "str.h"
#include "debug.h"

//Check crypto library configuration
#if (EST_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Parse "cacerts" response
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientParseGetCaCertsResponse(EstClientContext *context)
{
   error_t error;
   size_t n;
   size_t length;
   const uint8_t *data;
   Asn1Tag tag;
   Pkcs7ContentInfo contentInfo;
   Pkcs7SignedData signedData;

   //Initialize status code
   error = NO_ERROR;

   //The EST client should disable use of Implicit TA database entries
   context->caCertsLen = 0;

   //The EST client must store the extracted EST CA certificate as an Explicit
   //TA database entry for subsequent EST server authentication (refer to
   //RFC 7030, section 4.1.3)
   context->useExplicitTa = TRUE;

   //If successful, the server response must have an HTTP 200 response code
   if(HTTP_STATUS_CODE_2YZ(context->statusCode))
   {
      //The HTTP content-type of "application/pkcs7-mime" must be used
      if(osStrcmp(context->contentType, "application/pkcs7-mime") == 0)
      {
         //The Simple PKI Response is sent with a Content-Transfer-Encoding of
         //"base64"
         error = base64Decode((char_t *) context->buffer, context->bufferLen,
            context->buffer, &context->bufferLen);

         //Check status code
         if(!error)
         {
            //A successful response must be a certs-only CMC Simple PKI
            //Response, as defined in RFC 5272
            error = pkcs7ParseContentInfo(context->buffer, context->bufferLen,
               &n, &contentInfo);
         }

         //Check status code
         if(!error)
         {
            //Parse signed-data content
            error = pkcs7ParseSignedData(contentInfo.content.value,
               contentInfo.content.length, &signedData);
         }

         //Check status code
         if(!error)
         {
            //Check the length of the certificate chain
            if(signedData.certificates.raw.length > 0)
            {
               //Point to the first certificate of the chain
               data = signedData.certificates.raw.value;
               length = signedData.certificates.raw.length;

               //Parse CA certificates
               while(length > 0 && !error)
               {
                  //Parse certificate
                  error = asn1ReadSequence(data, length, &tag);

                  //Check status code
                  if(!error)
                  {
                     //The first pass calculates the length of the PEM certificate
                     error = pemExportCertificate(data, tag.totalLength, NULL, &n);
                  }

                  //Check status code
                  if(!error)
                  {
                     //Sanity check
                     if((context->caCertsLen + n) <= EST_CLIENT_MAX_CA_CERTS_LEN)
                     {
                        //The second pass exports the certificate to PEM format
                        error = pemExportCertificate(data, tag.totalLength,
                           context->caCerts + context->caCertsLen, &n);
                     }
                     else
                     {
                        //Report an error
                        error = ERROR_RESPONSE_TOO_LARGE;
                     }
                  }

                  //Check status code
                  if(!error)
                  {
                     //Update the length of the CA certificates
                     context->caCertsLen += n;

                     //Next DER certificate
                     data += tag.totalLength;
                     length -= tag.totalLength;
                  }
               }
            }
            else
            {
               //Report an error
               error = ERROR_INVALID_SYNTAX;
            }
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_RESPONSE;
      }
   }
   else
   {
      //Any other response code indicates an error and the client must abort
      //the protocol (refer to RFC 7030, section 4.1.3)
      error = ERROR_UNEXPECTED_STATUS;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse "simpleenroll" or "simplereenroll" response
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientParseSimpleEnrollResponse(EstClientContext *context)
{
   error_t error;

   //Check HTTP status code
   if(context->statusCode == 202)
   {
      //If the server responds with an HTTP 202, this indicates that the
      //request has been accepted for processing but that a response is not
      //yet available (refer to RFC 7030, section 4.2.3)
      error = ERROR_UNEXPECTED_STATUS;
   }
   else if(HTTP_STATUS_CODE_2YZ(context->statusCode))
   {
      //If the enrollment is successful, the server response must contain an
      //HTTP 200 response code with a content-type of "application/pkcs7-mime"
      //(refer to RFC 7030, section 4.2.3)
      if(osStrcmp(context->contentType, "application/pkcs7-mime") == 0)
      {
         //A successful response must be a certs-only CMC Simple PKI Response,
         //as defined in RFC 5272, containing only the certificate that was
         //issued
         error = estClientParsePkiResponse(context, context->buffer,
            context->bufferLen);
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_RESPONSE;
      }
   }
   else
   {
      //The server must answer with a suitable 4xx or 5xx HTTP error code when
      //a problem occurs
      error = ERROR_UNEXPECTED_STATUS;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse PKI message
 * @param[in] context Pointer to the EST client context
 * @param[in] data Pointer to the PKI message to parse
 * @param[in] length Length of the PKI message
 * @return Error code
 **/

error_t estClientParsePkiResponse(EstClientContext *context, uint8_t *data,
   size_t length)
{
   error_t error;
   size_t n;
   Pkcs7ContentInfo contentInfo;
   Pkcs7SignedData signedData;

   //The CMC Simple PKI Response is encoded in base64
   error = base64Decode((char_t *) data, length, data, &n);
   //Any error to report?
   if(error)
      return error;

   //The general syntax for content exchanged between entities associates a
   //content type with content (refer to RFC 2315, section 7)
   error = pkcs7ParseContentInfo(data, n, &n, &contentInfo);
   //Any error to report?
   if(error)
      return error;

   //A successful response must be a certs-only CMC Simple PKI Response, as
   //defined in RFC 5272
   if(OID_COMP(contentInfo.contentType.value, contentInfo.contentType.length,
      PKCS7_SIGNED_DATA_OID) != 0)
   {
      return ERROR_INVALID_TYPE;
   }

   //Parse signed-data content
   error = pkcs7ParseSignedData(contentInfo.content.value,
      contentInfo.content.length, &signedData);
   //Any error to report?
   if(error)
      return error;

   //In the degenerate case where there are no signers on the content (refer to
   //RFC 2315, section 9.1)
   if(signedData.contentInfo.content.length != 0 ||
      signedData.signerInfos.numSignerInfos != 0)
   {
      return ERROR_INVALID_SYNTAX;
   }

   //The reply contains only the certificate that was issued (refer to RFC 7030,
   //section 4.2.3)
   if(signedData.certificates.numCertificates != 1)
      return ERROR_INVALID_SYNTAX;

   //Check the length of the issued certificate
   if(signedData.certificates.certificates[0].length > EST_CLIENT_MAX_CERT_LEN)
      return ERROR_RESPONSE_TOO_LARGE;

   //Save the issued certificate
   osMemcpy(context->cert, signedData.certificates.certificates[0].value,
      signedData.certificates.certificates[0].length);

   //Save the length of the issued certificate
   context->certLen = signedData.certificates.certificates[0].length;

   //Sucessful processing
   return NO_ERROR;
}

#endif
