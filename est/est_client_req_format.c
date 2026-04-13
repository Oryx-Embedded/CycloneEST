/**
 * @file est_client_req_format.c
 * @brief EST request generation
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
#include "est/est_client_req_format.h"
#include "encoding/base64.h"
#include "debug.h"

//Check crypto library configuration
#if (EST_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Format PKI request
 * @param[in] context Pointer to the SCEP client context
 * @param[out] output Buffer where to format the PKI request
 * @param[out] written Length of the resulting PKI request
 * @return Error code
 **/

error_t estClientFormatPkiRequest(EstClientContext *context,
   uint8_t *output, size_t *written)
{
   size_t n;

   //The client must include a Simple PKI Request as specified in CMC (i.e.,
   //a PKCS #10 Certification Request)
   osMemcpy(context->buffer, context->csr, context->csrLen);
   n = context->csrLen;

   //The format of the message is as specified in RFC 5967 with a Content-
   //Transfer-Encoding of "base64"
   base64EncodeMultiline(context->buffer, n, (char_t *) context->buffer, &n,
      64);

   //Total length of the message
   *written = n;

   //Successful processing
   return NO_ERROR;
}

#endif
