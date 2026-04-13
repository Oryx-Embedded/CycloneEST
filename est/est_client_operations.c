/**
 * @file est_client_operations.c
 * @brief EST operations
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
#include "est/est_client_operations.h"
#include "est/est_client_req_format.h"
#include "est/est_client_resp_parse.h"
#include "est/est_client_transport.h"
#include "debug.h"

//Check crypto library configuration
#if (EST_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Perform "cacerts" operation
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientSendCaCerts(EstClientContext *context)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == EST_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_INFO("Generating cacerts request...\r\n");

         //Update HTTP request state
         context->requestState = EST_REQ_STATE_FORMAT_HEADER;
      }
      else if(context->requestState == EST_REQ_STATE_FORMAT_HEADER)
      {
         //EST clients request the EST CA TA database information of the CA
         //with an HTTPS GET message using an operation path of "/cacerts"
         //(refer to RFC 7030, section 4.1.2)
         error = estClientFormatRequestHeader(context, "GET", "cacerts");

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending cacerts request...\r\n");

            //Update HTTP request state
            context->requestState = EST_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == EST_REQ_STATE_SEND_HEADER ||
         context->requestState == EST_REQ_STATE_SEND_BODY ||
         context->requestState == EST_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == EST_REQ_STATE_PARSE_HEADER ||
         context->requestState == EST_REQ_STATE_RECEIVE_BODY ||
         context->requestState == EST_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = estClientSendRequest(context);
      }
      else if(context->requestState == EST_REQ_STATE_COMPLETE)
      {
         //Debug message
         TRACE_INFO("Parsing cacerts response...\r\n");

         //Parse the body of the HTTP response
         error = estClientParseGetCaCertsResponse(context);

         //The HTTP transaction is complete
         context->requestState = EST_REQ_STATE_INIT;
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Perform "simpleenroll" operation
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientSendSimpleEnroll(EstClientContext *context)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == EST_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_INFO("Generating simpleenroll request...\r\n");

         //Update HTTP request state
         context->requestState = EST_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == EST_REQ_STATE_FORMAT_BODY)
      {
         //When HTTPS POSTing to "/simpleenroll", the client must include a
         //Simple PKI Request as specified in CMC (refer to RFC 7030,
         //section 4.2.1)
         error = estClientFormatPkiRequest(context, context->buffer,
            &context->bufferLen);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = EST_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == EST_REQ_STATE_FORMAT_HEADER)
      {
         //EST clients request a certificate from the EST server with an HTTPS
         //POST using the operation path value of "/simpleenroll" (refer to
         //RFC 7030, section 4.2)
         error = estClientFormatRequestHeader(context, "POST", "simpleenroll");

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending simpleenroll request...\r\n");

            //Update HTTP request state
            context->requestState = EST_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == EST_REQ_STATE_SEND_HEADER ||
         context->requestState == EST_REQ_STATE_SEND_BODY ||
         context->requestState == EST_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == EST_REQ_STATE_PARSE_HEADER ||
         context->requestState == EST_REQ_STATE_RECEIVE_BODY ||
         context->requestState == EST_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = estClientSendRequest(context);
      }
      else if(context->requestState == EST_REQ_STATE_COMPLETE)
      {
         //Invalid authentication credentials?
         if(context->statusCode == 401)
         {
            //In response to the initial HTTP POST attempt, the server requests
            //WWW-Authenticate from the client
            if(context->selectedAuthMode == HTTP_AUTH_MODE_NONE &&
               context->httpClientContext.authParams.selectedMode != HTTP_AUTH_MODE_NONE)
            {
               //In the subsequent HTTP POST, the username/password is included
               context->requestState = EST_REQ_STATE_FORMAT_HEADER;
            }
            else
            {
               //Report an error
               error = ERROR_AUTHENTICATION_FAILED;
            }
         }
         else
         {
            //Debug message
            TRACE_INFO("Parsing simpleenroll response...\r\n");

            //Parse the body of the HTTP response
            error = estClientParseSimpleEnrollResponse(context);

            //The HTTP transaction is complete
            context->requestState = EST_REQ_STATE_INIT;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Perform "simplereenroll" operation
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientSendSimpleReEnroll(EstClientContext *context)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == EST_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_INFO("Generating simplereenroll request...\r\n");

         //Update HTTP request state
         context->requestState = EST_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == EST_REQ_STATE_FORMAT_BODY)
      {
         //A certificate request employs the same format as the "simpleenroll"
         //request (refer to RFC 7030, section 4.2.2)
         error = estClientFormatPkiRequest(context, context->buffer,
            &context->bufferLen);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = EST_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == EST_REQ_STATE_FORMAT_HEADER)
      {
         //EST clients request a renew/rekey of existing certificates with an
         //HTTP POST using the operation path value of "/simplereenroll" (refer
         //to RFC 7030, section 4.2)
         error = estClientFormatRequestHeader(context, "POST",
            "simplereenroll");

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending simplereenroll request...\r\n");

            //Update HTTP request state
            context->requestState = EST_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == EST_REQ_STATE_SEND_HEADER ||
         context->requestState == EST_REQ_STATE_SEND_BODY ||
         context->requestState == EST_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == EST_REQ_STATE_PARSE_HEADER ||
         context->requestState == EST_REQ_STATE_RECEIVE_BODY ||
         context->requestState == EST_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = estClientSendRequest(context);
      }
      else if(context->requestState == EST_REQ_STATE_COMPLETE)
      {
         //Invalid authentication credentials?
         if(context->statusCode == 401)
         {
            //In response to the initial HTTP POST attempt, the server requests
            //WWW-Authenticate from the client
            if(context->selectedAuthMode == HTTP_AUTH_MODE_NONE &&
               context->httpClientContext.authParams.selectedMode != HTTP_AUTH_MODE_NONE)
            {
               //In the subsequent HTTP POST, the username/password is included
               context->requestState = EST_REQ_STATE_FORMAT_HEADER;
            }
            else
            {
               //Report an error
               error = ERROR_AUTHENTICATION_FAILED;
            }
         }
         else
         {
            //Debug message
            TRACE_INFO("Parsing simplereenroll response...\r\n");

            //Parse the body of the HTTP response
            error = estClientParseSimpleEnrollResponse(context);

            //The HTTP transaction is complete
            context->requestState = EST_REQ_STATE_INIT;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}

#endif
