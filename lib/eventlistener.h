/*******************************************************************************
* Copyright (C) 2004-2007 Intel Corp. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*  - Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
*  - Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
*  - Neither the name of Intel Corp. nor the names of its
*    contributors may be used to endorse or promote products derived from this
*    software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

/**
 * @author Anas Nashif
 * @author Liang Hou
 */

#ifndef __EVENTLISTENER_H__
#define __EVENTLISTENER_H__

#ifdef __cplusplus
extern "C" {
#endif	

#include "wsman-soap.h"

struct digest;

typedef int (*eventlistener_bauth_callback_t)(char *u, char *passwd);
typedef int (*eventlistener_dauth_callback_t)(char *realm, char *method, struct digest *);
typedef int (*eventlistener_event_processor_t)(WsXmlDocH indoc, void *data);

int eventlistener_init(int port, char *servicepath, int authnotneeded, int debug);

void eventlistener_register_bauth_callback(eventlistener_bauth_callback_t);

void eventlistener_register_dauth_callback(eventlistener_dauth_callback_t);

void eventlistener_register_event_processor(eventlistener_event_processor_t, void *data);

void eventlistener_start(void);

#ifdef __cplusplus
}
#endif

#endif
