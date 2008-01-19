/*
    Copyright (C) 2005  Hans Carlos Hofmann <carlos@hchs.de>

    This file is part of Siproxd.

    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#ifndef		ADDRCACHE_H
#define		ADDRCACHE_H	1


#include <sys/types.h>
#include <netinet/in.h>
#include <osipparser2/osip_parser.h>



/*
 * We caching the address as function of from and to header to
 * find the correct path where to send the sip-responses
 */
int  adr_cache_init(void);

int  store_address (osip_message_t *sipmsg, int direction, int channel, const struct sockaddr_in *source);

int  load_address (osip_message_t *sipmsg, osip_message_t ** initsipmsg, 
                     int *direction, int *channel, struct sockaddr_in *source);

/* not used: int  adr_cache_kill(void);*/


#endif
