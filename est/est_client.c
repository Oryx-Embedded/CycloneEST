/**
 * @file est_client.c
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
 * @section Description
 *
 * EST is a certificate enrollment protocol using Certificate Management
 * over CMS (CMC) over a secure transport. Refer to RFC 7030 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL EST_TRACE_LEVEL

//Dependencies
#include "est/est_client.h"
#include "est/est_client_operations.h"
#include "est/est_client_misc.h"
#include "pkix/pem_import.h"
#include "pkix/pem_key_import.h"
#include "pkix/pem_export.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (EST_CLIENT_SUPPORT == ENABLED)


/**
 * @brief EST client initialization
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientInit(EstClientContext *context)
{
   error_t error;

   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Initializing EST client...\r\n");

   //Initialize context
   osMemset(context, 0, sizeof(EstClientContext));

   //Attach TCP/IP stack context
   context->netContext = netGetDefaultContext();

   //Initialize HTTP client context
   error = httpClientInit(&context->httpClientContext);
   //Any error to report?
   if(error)
      return error;

   //Initialize EST client state
   context->state = EST_CLIENT_STATE_DISCONNECTED;

   //Default timeout
   context->timeout = EST_CLIENT_DEFAULT_TIMEOUT;

   //The EST server must support the use of the path-prefix of "/.well-known/"
   //and the registered name of "est" (refer to RFC 7030, section 3.2.2)
   osStrcpy(context->pathPrefix, "/.well-known/est/");

   //Clients should support the Basic and Digest authentication mechanism
   //(refer to RFC 7030, section 3.2.3)
   context->allowedAuthModes = HTTP_AUTH_MODE_BASIC |
      HTTP_AUTH_MODE_DIGEST;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Register TLS initialization callback function
 * @param[in] context Pointer to the EST client context
 * @param[in] callback TLS initialization callback function
 * @return Error code
 **/

error_t estClientRegisterTlsInitCallback(EstClientContext *context,
   EstClientTlsInitCallback callback)
{
   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->tlsInitCallback = callback;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register CSR generation callback function
 * @param[in] context Pointer to the EST client context
 * @param[in] callback CSR generation callback function
 * @return Error code
 **/

error_t estClientRegisterCsrGenCallback(EstClientContext *context,
   EstClientCsrGenCallback callback)
{
   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->csrGenCallback = callback;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the pseudo-random number generator to be used
 * @param[in] context Pointer to the EST client context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t estClientSetPrng(EstClientContext *context, const PrngAlgo *prngAlgo,
   void *prngContext)
{
   //Check parameters
   if(context == NULL || prngAlgo == NULL || prngContext == NULL)
      return ERROR_INVALID_PARAMETER;

   //PRNG algorithm that will be used to generate nonces
   context->prngAlgo = prngAlgo;
   //PRNG context
   context->prngContext = prngContext;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set communication timeout
 * @param[in] context Pointer to the EST client context
 * @param[in] timeout Timeout value, in milliseconds
 * @return Error code
 **/

error_t estClientSetTimeout(EstClientContext *context, systime_t timeout)
{
   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the domain name of the EST server
 * @param[in] context Pointer to the EST client context
 * @param[in] host NULL-terminated string containing the host name
 * @return Error code
 **/

error_t estClientSetHost(EstClientContext *context, const char_t *host)
{
   //Check parameters
   if(context == NULL || host == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the host name is acceptable
   if(osStrlen(host) > EST_CLIENT_MAX_HOST_LEN)
      return ERROR_INVALID_LENGTH;

   //Save host name
   osStrcpy(context->serverName, host);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set path prefix
 * @param[in] context Pointer to the EST client context
 * @param[in] pathPrefix NULL-terminated string that contains the path prefix
 * @return Error code
 **/

error_t estClientSetPathPrefix(EstClientContext *context,
   const char_t *pathPrefix)
{
   //Check parameters
   if(context == NULL || pathPrefix == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the path prefix is acceptable
   if(osStrlen(pathPrefix) > EST_CLIENT_MAX_URI_LEN)
      return ERROR_INVALID_LENGTH;

   //Save the path prefix
   osStrcpy(context->pathPrefix, pathPrefix);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set allowed HTTP authentication modes
 * @param[in] context Pointer to the EST client context
 * @param[in] allowedAuthModes Logic OR of allowed HTTP authentication schemes
 * @return Error code
 **/

error_t estClientSetAllowedAuthModes(EstClientContext *context,
   uint_t allowedAuthModes)
{
   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save allowed HTTP authentication modes
   context->allowedAuthModes = allowedAuthModes;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set authentication information
 * @param[in] context Pointer to the EST client context
 * @param[in] username NULL-terminated string containing the user name to be used
 * @param[in] password NULL-terminated string containing the password to be used
 * @return Error code
 **/

error_t estClientSetAuthInfo(EstClientContext *context, const char_t *username,
   const char_t *password)
{
   //The EST client can use an out-of-band distributed username/password to
   //authenticate itself to the EST server
   return httpClientSetAuthInfo(&context->httpClientContext, username,
      password);
}


/**
 * @brief Bind the EST client to a particular network interface
 * @param[in] context Pointer to the EST client context
 * @param[in] interface Network interface to be used
 * @return Error code
 **/

error_t estClientBindToInterface(EstClientContext *context,
   NetInterface *interface)
{
   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Explicitly associate the EST client with the specified interface
   context->interface = interface;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Specify the address of the EST server
 * @param[in] context Pointer to the EST client context
 * @param[in] serverIpAddr IP address of the EST server to connect to
 * @param[in] serverPort UDP port number
 * @return Error code
 **/

error_t estClientConnect(EstClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort)
{
   error_t error;

   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Establish connection with the HTTP server
   while(!error)
   {
      //Check EST client state
      if(context->state == EST_CLIENT_STATE_DISCONNECTED)
      {
         //Save the TCP port number to be used
         context->serverPort = serverPort;

         //HTTPS must be used (refer to RFC 7030, section 3.3)
         if(context->tlsInitCallback != NULL)
         {
            //Register TLS initialization callback
            error = httpClientRegisterTlsInitCallback(&context->httpClientContext,
               estClientInitTlsContext, context);
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_PARAMETER;
         }

         //Check status code
         if(!error)
         {
            //Select HTTP protocol version
            error = httpClientSetVersion(&context->httpClientContext,
               HTTP_VERSION_1_1);
         }

         //Check status code
         if(!error)
         {
            //Set timeout value for blocking operations
            error = httpClientSetTimeout(&context->httpClientContext,
               context->timeout);
         }

         //Check status code
         if(!error)
         {
            //Bind the HTTP client to the relevant network interface
            error = httpClientBindToInterface(&context->httpClientContext,
               context->interface);
         }

         //Check status code
         if(!error)
         {
            //Establish HTTP connection
            context->state = EST_CLIENT_STATE_CONNECTING;
         }
      }
      else if(context->state == EST_CLIENT_STATE_CONNECTING)
      {
         //Establish HTTP connection
         error = httpClientConnect(&context->httpClientContext, serverIpAddr,
            serverPort);

         //Check status code
         if(error == NO_ERROR)
         {
            //The HTTP connection is established
            context->state = EST_CLIENT_STATE_CONNECTED;
         }
      }
      else if(context->state == EST_CLIENT_STATE_CONNECTED)
      {
         //The client is connected to the EST server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to establish connection with the EST server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Clean up side effects
      httpClientClose(&context->httpClientContext);
      //Update EST client state
      context->state = EST_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Load public/private key pair
 * @param[in] context Pointer to the EST client context
 * @param[in] publicKey Public key (PEM format)
 * @param[in] publicKeyLen Length of the public key
 * @param[in] privateKey Private key (PEM format)
 * @param[in] privateKeyLen Length of the private key
 * @param[in] password NULL-terminated string containing the password. This
 *   parameter is required if the private key is encrypted
 * @return Error code
 **/

error_t estClientLoadKeyPair(EstClientContext *context,
   const char_t *publicKey, size_t publicKeyLen, const char_t *privateKey,
   size_t privateKeyLen, const char_t *password)
{
   error_t error;
   X509KeyType type;

   //Check parameters
   if(context == NULL || publicKey == NULL || publicKeyLen == 0 ||
      privateKey == NULL || privateKeyLen == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Release the current key pair, if any
   estClientUnloadKeyPair(context);

   //Extract the type of the public key
   type = pemGetPublicKeyType(publicKey, publicKeyLen);

#if (EST_CLIENT_RSA_SUPPORT == ENABLED)
   //RSA public key?
   if(type == X509_KEY_TYPE_RSA)
   {
      //Save public key type
      context->keyType = X509_KEY_TYPE_RSA;

      //Initialize RSA public and private keys
      rsaInitPublicKey(&context->rsaPublicKey);
      rsaInitPrivateKey(&context->rsaPrivateKey);

      //Decode the PEM file that contains the RSA public key
      error = pemImportRsaPublicKey(&context->rsaPublicKey, publicKey,
         publicKeyLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the RSA private key
         error = pemImportRsaPrivateKey(&context->rsaPrivateKey, privateKey,
            privateKeyLen, password);
      }
   }
   else
#endif
#if (EST_CLIENT_ECDSA_SUPPORT == ENABLED)
   //EC public key?
   if(type == X509_KEY_TYPE_EC)
   {
      //Save public key type
      context->keyType = X509_KEY_TYPE_EC;

      //Initialize EC public and private keys
      ecInitPublicKey(&context->ecPublicKey);
      ecInitPrivateKey(&context->ecPrivateKey);

      //Decode the PEM file that contains the EC public key
      error = pemImportEcPublicKey(&context->ecPublicKey, publicKey,
         publicKeyLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the EC private key
         error = pemImportEcPrivateKey(&context->ecPrivateKey, privateKey,
            privateKeyLen, password);
      }
   }
   else
#endif
   //Invalid public key?
   {
      //The supplied public key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      estClientUnloadKeyPair(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Unload public/private key pair
 * @param[in] context Pointer to the EST client context
 **/

void estClientUnloadKeyPair(EstClientContext *context)
{
   //Make sure the EST client context is valid
   if(context != NULL)
   {
#if (EST_CLIENT_RSA_SUPPORT == ENABLED)
      //RSA key pair?
      if(context->keyType == X509_KEY_TYPE_RSA)
      {
         //Release RSA public and private keys
         rsaFreePublicKey(&context->rsaPublicKey);
         rsaFreePrivateKey(&context->rsaPrivateKey);
      }
      else
#endif
#if (EST_CLIENT_ECDSA_SUPPORT == ENABLED)
      //EC key pair?
      if(context->keyType == X509_KEY_TYPE_EC)
      {
         //Release EC public and private keys
         ecFreePublicKey(&context->ecPublicKey);
         ecFreePrivateKey(&context->ecPrivateKey);
      }
      else
#endif
      //Invalid key pair?
      {
         //Just for sanity
      }
   }
}


/**
 * @brief Load client's certificate
 * @param[in] context Pointer to the EST client context
 * @param[out] input Pointer to the PEM-encoded certificate
 * @param[out] length Length of the PEM-encoded certificate
 * @return Error code
 **/

error_t estClientLoadCert(EstClientContext *context,
   const char_t *input, size_t length)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the EST client context is valid
   if(context != NULL)
   {
      //Valid certificate?
      if(input != NULL && length > 0)
      {
         //The first pass calculates the length of the DER-encoded certificate
         error = pemImportCertificate(input, length, NULL, &n, NULL);

         //Check status code
         if(!error)
         {
            //Check the length of the certificate
            if(n <= EST_CLIENT_MAX_CERT_LEN)
            {
               //The second pass decodes the PEM certificate
               error = pemImportCertificate(input, length, context->cert,
                  &context->certLen, NULL);
            }
            else
            {
               //Report an error
               error = ERROR_INVALID_LENGTH;
            }
         }
      }
      else
      {
         //Clear certificate
         context->certLen = 0;
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Store client's certificate
 * @param[in] context Pointer to the EST client context
 * @param[out] output Pointer to the buffer where to store the PEM-encoded
 *   certificate (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @return Error code
 **/

error_t estClientStoreCert(EstClientContext *context,
   char_t *output, size_t *written)
{
   error_t error;

   //Check parameters
   if(context == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Valid certificate?
   if(context->certLen > 0)
   {
      //Export the certificate to PEM format
      error = pemExportCertificate(context->cert, context->certLen, output,
         written);
   }
   else
   {
      //Report an error
      error = ERROR_NO_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Load implicit TA database
 * @param[in] context Pointer to the EST client context
 * @param[out] input Pointer to the PEM-encoded CA certificates
 * @param[out] length Length of the PEM-encoded CA certificates
 * @return Error code
 **/

error_t estClientLoadCaCerts(EstClientContext *context,
   const char_t *input, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the EST client context is valid
   if(context != NULL)
   {
      //Valid CA certificates?
      if(input != NULL && length > 0)
      {
         //Check the length of the CA certificate
         if(length <= EST_CLIENT_MAX_CA_CERTS_LEN)
         {
            //Copy the CA certificates
            osMemcpy(context->caCerts, input, length);
            context->caCertsLen = length;

            //The client must maintain a distinction between the use of explicit
            //and implicit TA databases during authentication in order to
            //support proper authorization (refer to RFC 7030, section 3.3.1)
            context->useExplicitTa = FALSE;
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_LENGTH;
         }
      }
      else
      {
         //Clear CA certificates
         context->caCertsLen = 0;
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Store CA certificates
 * @param[in] context Pointer to the EST client context
 * @param[out] output Pointer to the buffer where to store the PEM-encoded
 *   CA certificates (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @return Error code
 **/

error_t estClientStoreCaCerts(EstClientContext *context,
   char_t *output, size_t *written)
{
   error_t error;

   //Check parameters
   if(context == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Valid CA certificates?
   if(context->caCertsLen > 0)
   {
      //If the output parameter is NULL, then the function calculates the
      //length of the CA certificates without copying any data
      if(output != NULL)
      {
         //Copy the CA certificates
         osMemcpy(output, context->caCerts, context->caCertsLen);
         //Properly terminate the string with a NULL character
         output[context->caCertsLen] = '\0';
      }

      //Return the length of the PEM string (excluding the terminating NULL)
      *written = context->caCertsLen;
   }
   else
   {
      //Report an error
      error = ERROR_NO_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Get CA certificates
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientGetCaCerts(EstClientContext *context)
{
   error_t error;

   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check EST client state
      if(context->state == EST_CLIENT_STATE_CONNECTED)
      {
         //Update EST client state
         context->state = EST_CLIENT_STATE_GET_CA;
      }
      else if(context->state == EST_CLIENT_STATE_GET_CA)
      {
         //Perform "cacerts" operation
         error = estClientSendCaCerts(context);

         //Check status code
         if(!error)
         {
            //Update EST client state
            context->state = EST_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = EST_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Certificate enrollment
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientEnroll(EstClientContext *context)
{
   error_t error;

   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check EST client state
      if(context->state == EST_CLIENT_STATE_CONNECTED)
      {
         //Update EST client state
         context->state = EST_CLIENT_STATE_GET_CA;
      }
      else if(context->state == EST_CLIENT_STATE_GET_CA)
      {
         //It is recommended that a client obtain the current CA certificates,
         //as described in Section 4.1, before performing certificate request
         //functions (refer to RFC 7030, section 4.2)
         error = estClientSendCaCerts(context);

         //Check status code
         if(!error)
         {
            //Update EST client state
            context->state = EST_CLIENT_STATE_CSR_GEN;
         }
      }
      else if(context->state == EST_CLIENT_STATE_CSR_GEN)
      {
         //Generate PKCS #10 certificate request
         error = estClientGenerateCsr(context);

         //Check status code
         if(!error)
         {
            //Update EST client state
            context->state = EST_CLIENT_STATE_ENROLL;
         }
      }
      else if(context->state == EST_CLIENT_STATE_ENROLL)
      {
         //Perform "simpleenroll" operation
         error = estClientSendSimpleEnroll(context);

         //Check status code
         if(!error)
         {
            //Update EST client state
            context->state = EST_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE || error == ERROR_REQUEST_REJECTED)
   {
      //Revert to default state
      context->state = EST_CLIENT_STATE_CONNECTED;
   }
   else
   {
      //Just for sanity
   }

   //Return status code
   return error;
}


/**
 * @brief Certificate re-enrollment
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientReEnroll(EstClientContext *context)
{
   error_t error;

   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the previously issued certificate is valid
   if(context->certLen == 0)
      return ERROR_BAD_CERTIFICATE;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check EST client state
      if(context->state == EST_CLIENT_STATE_CONNECTED)
      {
         //Update EST client state
         context->state = EST_CLIENT_STATE_GET_CA;
      }
      else if(context->state == EST_CLIENT_STATE_GET_CA)
      {
         //It is recommended that a client obtain the current CA certificates,
         //as described in Section 4.1, before performing certificate request
         //functions (refer to RFC 7030, section 4.2)
         error = estClientSendCaCerts(context);

         //Check status code
         if(!error)
         {
            //Update EST client state
            context->state = EST_CLIENT_STATE_CSR_GEN;
         }
      }
      else if(context->state == EST_CLIENT_STATE_CSR_GEN)
      {
         //Generate PKCS #10 certificate request
         error = estClientGenerateCsr(context);

         //Check status code
         if(!error)
         {
            //Update EST client state
            context->state = EST_CLIENT_STATE_REENROLL;
         }
      }
      else if(context->state == EST_CLIENT_STATE_REENROLL)
      {
         //Perform "simplereenroll" operation
         error = estClientSendSimpleReEnroll(context);

         //Check status code
         if(!error)
         {
            //Update EST client state
            context->state = EST_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE || error == ERROR_REQUEST_REJECTED)
   {
      //Revert to default state
      context->state = EST_CLIENT_STATE_CONNECTED;
   }
   else
   {
      //Just for sanity
   }

   //Return status code
   return error;
}


/**
 * @brief Gracefully disconnect from the EST server
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientDisconnect(EstClientContext *context)
{
   error_t error;

   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Gracefully disconnect from the EST server
   while(!error)
   {
      //Check EST client state
      if(context->state == EST_CLIENT_STATE_CONNECTED)
      {
         //Gracefully shutdown HTTP connection
         context->state = EST_CLIENT_STATE_DISCONNECTING;
      }
      else if(context->state == EST_CLIENT_STATE_DISCONNECTING)
      {
         //Gracefully shutdown HTTP connection
         error = httpClientDisconnect(&context->httpClientContext);

         //Check status code
         if(error == NO_ERROR)
         {
            //Close HTTP connection
            httpClientClose(&context->httpClientContext);
            //Update EST client state
            context->state = EST_CLIENT_STATE_DISCONNECTED;
         }
      }
      else if(context->state == EST_CLIENT_STATE_DISCONNECTED)
      {
         //The client is disconnected from the EST server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to gracefully disconnect from the EST server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Close HTTP connection
      httpClientClose(&context->httpClientContext);
      //Update EST client state
      context->state = EST_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Close the connection with the EST server
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientClose(EstClientContext *context)
{
   //Make sure the EST client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Close HTTP connection
   httpClientClose(&context->httpClientContext);
   //Update EST client state
   context->state = EST_CLIENT_STATE_DISCONNECTED;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release EST client context
 * @param[in] context Pointer to the EST client context
 **/

void estClientDeinit(EstClientContext *context)
{
   //Make sure the EST client context is valid
   if(context != NULL)
   {
      //Release HTTP client context
      httpClientDeinit(&context->httpClientContext);

      //Release public/private key pair
      estClientUnloadKeyPair(context);

      //Clear EST client context
      osMemset(context, 0, sizeof(EstClientContext));
   }
}

#endif
