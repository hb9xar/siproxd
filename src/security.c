/*
    Copyright (C) 2002  Thomas Ries <tries@gmx.net>

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

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <osip/smsg.h>

#include "siproxd.h"
#include "log.h"


/*
 * do security and integrity checks on the received packet
 * (raw buffer)
 *
 * RETURNS
 *	STS_SUCCESS if ok 
 * 	STS_FAILURE if the packed did not pass the checks
 */
int security_check_raw(char *sip_buffer, int size){

   /* TODO: still way to go here ... */
   return STS_SUCCESS;
}


/*
 * do security and integrity checks on the received packet
 * (parsed buffer)
 *
 * RETURNS
 *	STS_SUCCESS if ok 
 * 	STS_FAILURE if the packed did not pass the checks
 */
int security_check_sip(sip_t *sip){

   /* check for existing SIP URI */
   if (sip->strtline == NULL) {
      ERROR("security check failed: NULL SIP URI");
      return STS_FAILURE;
   }

   /* check for existing TO */
   if (sip->to == NULL) {
      ERROR("security check failed: NULL To Header");
      return STS_FAILURE;
   }

   /* check for existing TO URL */
   if (sip->to->url == NULL) {
      ERROR("security check failed: NULL To->url Header");
      return STS_FAILURE;
   }

    /* check for existing TO URL host*/
   if (sip->to->url->host == NULL) {
      ERROR("security check failed: NULL To->url->host Header");
      return STS_FAILURE;
   }

  /* check for existing FROM */
   if (sip->from == NULL) {
      ERROR("security check failed: NULL From Header");
      return STS_FAILURE;
   }

   /* check for existing FROM URL */
   if (sip->from->url == NULL) {
      ERROR("security check failed: NULL From->url Header");
      return STS_FAILURE;
   }

   /* check for existing FROM URL host*/
   if (sip->from->url->host == NULL) {
      ERROR("security check failed: NULL From->url->host Header");
      return STS_FAILURE;
   }

   /* TODO: still way to go here ... */
   return STS_SUCCESS;
}
