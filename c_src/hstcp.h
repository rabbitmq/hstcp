/* ------------------------------------------------------------------------- */
/*                                                                           */
/*   The contents of this file are subject to the Mozilla Public License     */
/*   Version 1.1 (the "License"); you may not use this file except in        */
/*   compliance with the License. You may obtain a copy of the License at    */
/*   http://www.mozilla.org/MPL/                                             */
/*                                                                           */
/*   Software distributed under the License is distributed on an "AS IS"     */
/*   basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the */
/*   License for the specific language governing rights and limitations      */
/*   under the License.                                                      */
/*                                                                           */
/*   The Original Code is HSTCP.                                               */
/*                                                                           */
/*   The Initial Developers of the Original Code are VMware, Inc.            */
/*   Copyright (c) 2011-2011 VMware, Inc.  All rights reserved.              */
/*                                                                           */
/* ------------------------------------------------------------------------- */

#ifndef __HSTCP_H_
#define __HSTCP_H_

enum _CommandType {
  HSTCP_INVALID_COMMAND = 255,
  HSTCP_LISTEN          = 0,
  HSTCP_CONNECT         = 1,
  HSTCP_CLOSE           = 2,
  HSTCP_ACCEPT          = 3,
  HSTCP_RECV            = 4,
  HSTCP_WRITE           = 5,
  HSTCP_SET_OPTIONS     = 6
};
typedef enum _CommandType CommandType;

enum _ReaderError {
  READER_NO_ERROR      = 0,
  READER_READ_ALL_DATA = 1,
  READER_PACKING_ERROR = 2
};
typedef enum _ReaderError ReaderError;

enum _AsyncCommandType {
  HSTCP_ASYNC_START            = 0,
  HSTCP_ASYNC_EXIT             = 1,
  HSTCP_ASYNC_SOCKET           = 2,
  HSTCP_ASYNC_CLOSE            = 3,
  HSTCP_ASYNC_ACCEPT           = 4,
  HSTCP_ASYNC_RECV             = 5,
  HSTCP_ASYNC_WRITE            = 6,
  HSTCP_ASYNC_INCOMPLETE_WRITE = 7,
  HSTCP_ASYNC_DESTROY_SOCKET   = 8,
  HSTCP_ASYNC_CHECK_WATERMARKS = 9
};
typedef enum _AsyncCommandType AsyncCommandType;

enum _SendType {
  EVENT = 1,
  REPLY = 2
};
typedef enum _SendType SendType;

enum _SocketType {
  LISTEN_SOCKET    = 1,
  CONNECTED_SOCKET = 2
};
typedef enum _SocketType SocketType;

enum _WatermarkLevel {
  UNKNOWN_WATERMARK = 0,
  LOW_WATERMARK     = 1,
  HIGH_WATERMARK    = 2
};
typedef enum _WatermarkLevel WatermarkLevel;

#endif
