/* -*- Mode: C; c-basic-offset: 3 -*-
    Copyright (C) 2005  Thomas Ries <tries@gmx.net>

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

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>

#include "log.h"

static char const ident[]="$Id$";


/* local functions */
static int _resolve(char *name, int proto, int type,
                    char *dname, int dnamelen, int *port);

#define PROTO_UDP       1
#define PROTO_TCP       2

/*
 * perform a SRV record lookup
 */
int resolve_SRV(char *name, int proto, char *dname, int dnamelen, int *port) {
   return _resolve(name, proto, T_SRV, dname, dnamelen, port);
}

/*
 * perform a NAPTR lookup
 */
int resolve_NAPTR(char *name, char *dname, int dnamelen) {
   int port=0;
   return _resolve(name, 0, T_NAPTR, dname, dnamelen, &port);
}


/*
 * query the DNS for a specific record type
 */
static int _resolve(char *name, int proto, int type,
                    char *dname, int dnamelen, int *port) {
   int sts;

   int class=C_ANY;

   // message buffer
   char msg[PACKETSZ];
   int msglen=PACKETSZ;

   // response header
   HEADER *res_header;

   // expanded name
   char exp_dn[MAXDNAME];
   int exp_dnlen=MAXDNAME;

   int i, j, co;
   char *mptr, *xptr;
   unsigned short *usp,ty;
   unsigned int *uip;

   u_short priority = 0;
   u_short weight = 0;

   char tmpname[PACKETSZ];

   dname[0]='\0';
   *port=0;


   // issue request
   sts=res_query(name, class, type, msg, msglen);
   if (sts<0) {
      ERROR("res_query failed sts=%i\n", sts);
      return 0;
   }

   res_header = (HEADER *)msg;
   DEBUGC(DBCLASS_DNS, "_resolve: name=[%s], type=%i, qdcount=%i, ancount=%i",
         name, type, ntohs(res_header->qdcount), ntohs(res_header->ancount));

   mptr=msg+sizeof(HEADER);

   // loop through query part
   co=ntohs(res_header->qdcount);
   for (i=0; i<co; i++) {
      j=dn_expand(msg,msg+PACKETSZ,mptr,exp_dn,exp_dnlen);
      DEBUGC(DBCLASS_DNS, "_resolve: Q - len=%i, name=[%s]", j, exp_dn);
      if( j < 0 ) {
         break;
      } else {
         mptr += j;
         usp = (unsigned short *)mptr;
         mptr += sizeof( short );
         usp = (unsigned short *)mptr;
         mptr += sizeof( short );
      }
   }

   // loop through answer part
   co=ntohs(res_header->ancount);
   for (i=0; i<co; i++) {
      j=dn_expand(msg,msg+PACKETSZ,mptr,exp_dn,exp_dnlen);
      if( j < 0 ) {
         ERROR("_resolve: dn_expand error");
         break;
      } else {
         mptr += j;
         usp = (unsigned short *)mptr;
         ty = ntohs( *usp );
         mptr += sizeof( short );
         usp = (unsigned short *)mptr;
         mptr += sizeof(short);
         uip = (unsigned int *)mptr;
         mptr += sizeof(int);
         uip = (unsigned int *)mptr;
         j = ntohs( *uip );
         mptr += sizeof(short);
         xptr = mptr;
         mptr += j;
         if( ty == T_NAPTR ) {
            DEBUGC(DBCLASS_DNS, "_resolve: A - type NAPTR");
            usp = (unsigned short *)xptr;
            xptr += sizeof(short);
            usp = (unsigned short *)xptr;
            xptr += sizeof(short);
            j = (int)(*xptr);
            xptr += 1;
            while( j > 0 ) {
               xptr+=1;
               j--;
            }
            j = (int)(*xptr);
            xptr += 1;
            while( j > 0 ) {
               xptr += 1;
               j--;
            }
            j=(int)(*xptr);
            xptr+=1;
            while( j > 0 ) {
               xptr += 1;
               j--;
            }
            j = dn_expand( msg, msg + PACKETSZ, xptr, tmpname, MAXDNAME );
            if( j < 0 ) {
               break;
            } else {
/*
 * there should be some REGEX magic, no?
 */
               if( proto == PROTO_UDP ) {
                  if( strstr(tmpname, "_udp" ) ) {
                     strncpy(dname, tmpname, dnamelen);
                  }
               } else {
                  if( strstr(tmpname, "_tcp" ) ) {
                     strncpy(dname, tmpname, dnamelen);
                  }
               }
               DEBUGC(DBCLASS_DNS, "_resolve: A[%i] - type NAPTR: %s",
                      i, tmpname);
               xptr+=j;
            }
         } else if( ty == T_SRV ) {
            u_short pr;
            u_short we;
            u_short po;
            usp = (unsigned short *)xptr;
            pr = ntohs( *usp );
            xptr += sizeof( short );
            usp = (unsigned short *)xptr;
            we = ntohs( *usp );
            xptr += sizeof( short );
            usp = (unsigned short *)xptr;
            po = ntohs( *usp );
            xptr += sizeof( short );
            j = dn_expand( msg, msg + PACKETSZ, xptr, tmpname, MAXDNAME );
            if( j < 0 ) {
               break;
            } else {
                DEBUGC(DBCLASS_DNS, "_resolve: A[%i] - type SRV pr=%i, we=%i, "
                       "po=%i name=[%s]", i, pr, we, po, tmpname);
               if( !priority || pr < priority ||
                   (pr == priority && we < weight) ) {
                  priority = pr;
                  weight = we;
                  *port = po;
                  strncpy(dname, tmpname, dnamelen-1);
                  xptr+=j;
               }
            }
         } else {
            ERROR("_resolve: unknown type in DNS answer [type=%i]\n", ty);
         } // if ty
      } // if dn_expand
   } // for i

   dname[dnamelen-1]='\0';
   return 0;
}
