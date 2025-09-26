/**
 * @file est_client_transport.c
 * @brief HTTP transport mechanism
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
#include "est/est_client_transport.h"
#include "debug.h"

//Check crypto library configuration
#if (EST_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Send HTTP request
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientSendRequest(EstClientContext *context)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Check HTTP request state
   if(context->requestState == EST_REQ_STATE_SEND_HEADER)
   {
      //Send HTTP request header
      error = httpClientWriteHeader(&context->httpClientContext);

      //Check status code
      if(!error)
      {
         //Check whether the HTTP request contains a body
         if(context->bufferLen > 0)
         {
            //Point to the first byte of the body
            context->bufferPos = 0;

            //Send HTTP request body
            context->requestState = EST_REQ_STATE_SEND_BODY;
         }
         else
         {
            //Receive HTTP response header
            context->requestState = EST_REQ_STATE_RECEIVE_HEADER;
         }
      }
   }
   else if(context->requestState == EST_REQ_STATE_SEND_BODY)
   {
      //Send HTTP request body
      if(context->bufferPos < context->bufferLen)
      {
         //Send more data
         error = httpClientWriteBody(&context->httpClientContext,
            context->buffer + context->bufferPos,
            context->bufferLen - context->bufferPos, &n, 0);

         //Check status code
         if(!error)
         {
            //Advance data pointer
            context->bufferPos += n;
         }
      }
      else
      {
         //Update HTTP request state
         context->requestState = EST_REQ_STATE_RECEIVE_HEADER;
      }
   }
   else if(context->requestState == EST_REQ_STATE_RECEIVE_HEADER)
   {
      //Receive HTTP response header
      error = httpClientReadHeader(&context->httpClientContext);

      //Check status code
      if(!error)
      {
         //Update HTTP request state
         context->requestState = EST_REQ_STATE_PARSE_HEADER;
      }
   }
   else if(context->requestState == EST_REQ_STATE_PARSE_HEADER)
   {
      //Parse HTTP response header
      error = estClientParseResponseHeader(context);

      //Check status code
      if(!error)
      {
         //Invalid authentication credentials?
         if(context->statusCode == 401)
         {
            //Rewind to the beginning of the buffer
            context->bufferPos = 0;

            //Update HTTP request state
            context->requestState = EST_REQ_STATE_CLOSE_BODY;
         }
         else
         {
            //Flush the receive buffer
            context->bufferLen = 0;
            context->bufferPos = 0;

            //Update HTTP request state
            context->requestState = EST_REQ_STATE_RECEIVE_BODY;
         }
      }
   }
   else if(context->requestState == EST_REQ_STATE_RECEIVE_BODY)
   {
      //Receive HTTP response body
      if(context->bufferLen < EST_CLIENT_BUFFER_SIZE)
      {
         //Receive more data
         error = httpClientReadBody(&context->httpClientContext,
            context->buffer + context->bufferLen,
            EST_CLIENT_BUFFER_SIZE - context->bufferLen, &n, 0);

         //Check status code
         if(error == NO_ERROR)
         {
            //Advance data pointer
            context->bufferLen += n;
         }
         else if(error == ERROR_END_OF_STREAM)
         {
            //The end of the response body has been reached
            error = NO_ERROR;

            //Update HTTP request state
            context->requestState = EST_REQ_STATE_CLOSE_BODY;
         }
         else
         {
            //Just for sanity
         }
      }
      else
      {
         //Update HTTP request state
         context->requestState = EST_REQ_STATE_CLOSE_BODY;
      }
   }
   else if(context->requestState == EST_REQ_STATE_CLOSE_BODY)
   {
      //Close HTTP response body
      error = httpClientCloseBody(&context->httpClientContext);

      //Check status code
      if(!error)
      {
         //Update HTTP request state
         context->requestState = EST_REQ_STATE_COMPLETE;
      }
   }
   else
   {
      //Invalid state
      error = ERROR_WRONG_STATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Format HTTP request header
 * @param[in] context Pointer to the EST client context
 * @param[in] method NULL-terminating string containing the HTTP method
 * @param[in] operation NULL-terminating string containing the operation path
 * @return Error code
 **/

error_t estClientFormatRequestHeader(EstClientContext *context,
   const char_t *method, const char_t *operation)
{
   error_t error;
   HttpClientContext *httpClientContext;
   char_t uri[EST_CLIENT_MAX_URI_LEN + 1];

   //Point to the HTTP client context
   httpClientContext = &context->httpClientContext;

   //Create a new HTTP request
   error = httpClientCreateRequest(httpClientContext);
   //Any error to report?
   if(error)
      return error;

   //EST uses the HTTP POST and GET methods to perform the desired EST
   //operation
   error = httpClientSetMethod(httpClientContext, method);
   //Any error to report?
   if(error)
      return error;

   //Check the length of the URI absolute path
   if((osStrlen(operation) + osStrlen(context->pathPrefix)) > EST_CLIENT_MAX_URI_LEN)
      return ERROR_INVALID_PATH;

   //The operation path is appended to the path-prefix to form the URI (refer
   //to RFC 7030, section 3.2.2)
   osStrcpy(uri, context->pathPrefix);
   osStrcat(uri, operation);

   //Specify the URI absolute path
   error = httpClientSetUri(httpClientContext, uri);
   //Any error to report?
   if(error)
      return error;

   //A client must send a Host header field in all HTTP/1.1 requests (refer
   //to RFC 7230, section 5.4)
   if(context->serverPort == HTTPS_PORT)
   {
      //A host without any trailing port information implies the default port
      //for the service requested
      error = httpClientAddHeaderField(httpClientContext, "Host",
         context->serverName);
   }
   else
   {
      //Append the port number information to the host
      error = httpClientFormatHeaderField(httpClientContext,
         "Host", "%s:%" PRIu16, context->serverName, context->serverPort);
   }

   //Any error to report?
   if(error)
      return error;

   //Set User-Agent header field
   error = httpClientAddHeaderField(httpClientContext, "User-Agent",
      "Mozilla/5.0");
   //Any error to report?
   if(error)
      return error;

   //Accept any media type
   error = httpClientAddHeaderField(httpClientContext, "Accept", "*/*");
   //Any error to report?
   if(error)
      return error;

   //POST request?
   if(osStrcmp(method, "POST") == 0)
   {
      //The EST server can optionally also request that the EST client submit
      //a username/password using the HTTP Basic or Digest authentication
      //methods (refer to RFC 7030, section 2.2.3)
      error = httpClientSetAllowedAuthModes(httpClientContext,
         context->allowedAuthModes);
      //Any error to report?
      if(error)
         return error;

      //The HTTP content-type of "application/pkcs10" is used here (refer to
      //RFC 7030, section 4.2.1)
      error = httpClientAddHeaderField(httpClientContext, "Content-Type",
         "application/pkcs10");
      //Any error to report?
      if(error)
         return error;

      //The format of the message is as specified in RFC 5967 with a Content-
      //Transfer-Encoding of "base64"
      error = httpClientAddHeaderField(httpClientContext,
         "Content-Transfer-Encoding", "base64");
      //Any error to report?
      if(error)
         return error;

      //Specify the length of the request body
      error = httpClientSetContentLength(httpClientContext, context->bufferLen);
      //Any error to report?
      if(error)
         return error;
   }
   else
   {
      //Disable HTTP authentication mechanism
      error = httpClientSetAllowedAuthModes(httpClientContext,
         HTTP_AUTH_MODE_NONE);
      //Any error to report?
      if(error)
         return error;

      //The HTTP request body is empty
      context->bufferLen = 0;
   }

   //Get current HTTP authentication mode
   context->selectedAuthMode = context->httpClientContext.authParams.selectedMode;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse HTTP response header
 * @param[in] context Pointer to the EST client context
 * @return Error code
 **/

error_t estClientParseResponseHeader(EstClientContext *context)
{
   size_t n;
   char_t *p;
   const char_t *contentType;

   //Get HTTP response status code
   context->statusCode = httpClientGetStatus(&context->httpClientContext);

   //Get the Content-Type header field
   contentType = httpClientGetHeaderField(&context->httpClientContext,
      "Content-Type");

   //Content-Type header field found?
   if(contentType != NULL)
   {
      //Retrieve the header field value
      n = osStrlen(contentType);
      //Limit the length of the string
      n = MIN(n, EST_CLIENT_MAX_CONTENT_TYPE_LEN);

      //Save the media type
      osStrncpy(context->contentType, contentType, n);
      //Properly terminate the string with a NULL character
      context->contentType[n] = '\0';

      //Discard the parameters that may follow the type/subtype
      osStrtok_r(context->contentType, "; \t", &p);
   }
   else
   {
      //The Content-Type header field is not present in the response
      context->contentType[0] = '\0';
   }

   //Successful processing
   return NO_ERROR;
}

#endif
