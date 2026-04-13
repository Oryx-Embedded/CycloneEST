/**
 * @file est_client_operations.h
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

#ifndef _EST_CLIENT_OPERATIONS_H
#define _EST_CLIENT_OPERATIONS_H

//Dependencies
#include "core/net.h"
#include "est/est_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//EST client related functions
error_t estClientSendCaCerts(EstClientContext *context);
error_t estClientSendSimpleEnroll(EstClientContext *context);
error_t estClientSendSimpleReEnroll(EstClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
