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
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <osip/smsg.h>
#include <osip/sdp.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


/* configuration storage */
extern struct siproxd_config configuration;

extern int errno;
extern struct urlmap_s urlmap[];		/* URL mapping table     */
extern struct lcl_if_s local_addresses;
extern int sip_socket;				/* sending SIP datagrams */


/*
 * PROXY_REQUEST
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_request (sip_t *request) {
   int i;
   int sts;
   int type;
   struct in_addr addr;
   contact_t *contact;
   url_t *url;
   int port;
   char *buffer;

#define REQTYP_INCOMMING	1
#define REQTYP_OUTGOING		2

   DEBUGC(DBCLASS_PROXY,"proxy_request");

/* check for VIA loop, if yes, discard the request */
   sts=check_vialoop(request);
   if (sts == STS_TRUE) {
      DEBUGC(DBCLASS_PROXY,"via loop detected, ignoring request");
      return STS_FAILURE;
   }

   type = 0;
   for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) continue;

      /* incomming request ('to' == 'masq') */
      if (compare_url(request->to->url, urlmap[i].masq_url)==STS_SUCCESS) {
         type=REQTYP_INCOMMING;
         DEBUGC(DBCLASS_PROXY,"incomming request from %s@%s from outbound",
	        request->from->url->username,
		request->from->url->host);
	 break;
      }

      /* outgoing request ('from' == 'masq') */
      if (compare_url(request->from->url, urlmap[i].masq_url)==STS_SUCCESS) {
         type=REQTYP_OUTGOING;
         DEBUGC(DBCLASS_PROXY,"outgoing request from %s@%s from inbound",
	        request->from->url->username,
		request->from->url->host);
	 break;
      }
   }


/*
 * ok, we got a request that we are allowed to process.
 */
   switch (type) {
  /*
   * from an external host to the internal masqueraded host
   */
   case REQTYP_INCOMMING:
      /* rewrite request URI to point to the real host */
      /* i still holds the valid index into the URLMAP table */

      /* THIS IS UGLY!!! I dont like it */
      DEBUGC(DBCLASS_PROXY,"rewriting incomming Request URI");
      url=msg_geturi(request);
      free(url->host);url->host=NULL;
{
      char *host;
      char *port;
      /* set the true host */
      if(urlmap[i].true_url->host) {
	 host = (char *)malloc(strlen(urlmap[i].true_url->host)+1);
	 memcpy(host, urlmap[i].true_url->host, strlen(urlmap[i].true_url->host));
	 host[strlen(urlmap[i].true_url->host)]='\0';
	 url_sethost(url, host);
      }

      /* set the true port */
      if(urlmap[i].true_url->port) {
	 port = (char *)malloc(strlen(urlmap[i].true_url->port)+1);
	 memcpy(port, urlmap[i].true_url->port, strlen(urlmap[i].true_url->port));
	 port[strlen(urlmap[i].true_url->port)]='\0';
	 url_setport(url, port);
      }
}

      /* add my Via header line (inbound interface)*/
      sts = proxy_add_myvia(request, 1);
      if (sts == STS_FAILURE) {
         WARN("adding my inbound via failed!");
      }

      /* if this is CANCEL/BYE request, stop RTP proxying */
      if (MSG_IS_BYE(request) || MSG_IS_CANCEL(request)) {
         /* stop the RTP proxying stream */
         rtp_stop_fwd(msg_getcall_id(request));
      }

      break;
   
  /*
   * from the internal masqueraded host to an external host
   */
   case REQTYP_OUTGOING:
      /* if an INVITE, rewrite body */
      if (MSG_IS_INVITE(request)) {
         sts = proxy_rewrite_invitation_body(request);
      }

      /* rewrite Contact header to represent the masqued address */
      msg_getcontact(request,0,&contact);
      if (contact != NULL) {
         for (i=0;i<URLMAP_SIZE;i++){
	    if (urlmap[i].active == 0) continue;
            if (compare_url(contact->url, urlmap[i].true_url)==STS_SUCCESS)
	       break;
         }
         /* found a mapping entry */
         if (i<URLMAP_SIZE) {
            DEBUGC(DBCLASS_PROXY, "rewrote Contact header %s@%s -> %s@%s",
	           contact->url->username, contact->url->host,
		   urlmap[i].masq_url->username, urlmap[i].masq_url->host);
            /* remove old entry */
            list_remove(request->contacts,0);
            contact_free(contact);
            free(contact);
            /* clone the masquerading url */
	    contact_init(&contact);
            url_clone(urlmap[i].masq_url, &contact->url);
            list_add(request->contacts,contact,-1);
         }     
      }

      /* add my Via header line (outbound interface)*/
      sts = proxy_add_myvia(request, 0);
      if (sts == STS_FAILURE) {
         WARN("adding my outbound via failed!");
      }

      /* if this is CANCEL/BYE request, stop RTP proxying */
      if (MSG_IS_BYE(request) || MSG_IS_CANCEL(request)) {
         /* stop the RTP proxying stream */
         rtp_stop_fwd(msg_getcall_id(request));
      }

      break;
   
   default:
      DEBUGC(DBCLASS_PROXY,"request: refuse to proxy - UA not registered?");
      WARN("request from/to unregistered UA (%s@%s)",
	        request->from->url->username,
		request->from->url->host);
/* some clients seem to run amok when passing back a negative response */
//      proxy_gen_response(request, 403 /*forbidden*/);
      return STS_FAILURE;
   }


/* get target address from request URL */
   url=msg_geturi(request);

#ifdef HACK1
/* linphone-0.9.0pre4
   take To address and place it into URI (at least the host part)
   Linphone-0.9.0pre4 puts the proxy host in the request URI
   if OUTBOUND proxy is activated!
   This is only a hack to recreate the proper final request URI.
   This issue has been fixed in 0.9.1pre1
*/
{
   header_t *header_ua;
   msg_getuser_agent(request,0,&header_ua);

   if ( header_ua && header_ua->hvalue &&
        (strcmp(header_ua->hvalue,"oSIP/Linphone-0.8.0")==0) ) {
      /* if an outgoing request, try to fix the SIP URI */
      if (type == REQTYP_OUTGOING) {
         WARN("broken linphone-0.8.0: restoring SIP URI");
	 free (url->host);
	 url->host=malloc(strlen(request->to->url->host));
	 strcpy(url->host,request->to->url->host);

      }
   }
}
#endif

   sts = get_ip_by_host(url->host, &addr);

   sts = msg_2char(request, &buffer);
   if (sts != 0) {
      ERROR("proxy_request: msg_2char failed");
      return STS_FAILURE;
   }

   /* send to destination */
   if (url->port) {
      port=atoi(url->port);
   } else {
      port=configuration.sip_listen_port;
   }

   sipsock_send_udp(&sip_socket, addr, port, buffer, strlen(buffer), 1); 
   free (buffer);
   return STS_SUCCESS;
}


/*
 * PROXY_RESPONSE
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_response (sip_t *response) {
   int i;
   int sts;
   int type;
   struct in_addr addr;
   via_t *via;
   contact_t *contact;
   int port;
   char *buffer;

#define RESTYP_INCOMMING	1
#define RESTYP_OUTGOING		2

   DEBUGC(DBCLASS_PROXY,"proxy_response");


   /* check for VIA loop, if yes, discard the request */
   sts=check_vialoop(response);
   if (sts == STS_TRUE) {
      DEBUGC(DBCLASS_PROXY,"via loop detected, ignoring response");
      return STS_FAILURE;
   }

   /* ALWAYS: remove my Via header line */
   sts = proxy_del_myvia(response);
   if (sts == STS_FAILURE) {
      DEBUGC(DBCLASS_PROXY,"not addressed to my VIA, ignoring response");
      return STS_FAILURE;
   }

   /* figure out if this is an request comming from the outside
    * world to one of our registered clients
    */


   /* Ahhrghh...... an response seems to have NO contact information... 
    * so let's take FROM instead...
    * the TO and FROM headers are EQUAL to the request - that means 
    * they are swapped in their meaning for a response...
    */

   type = 0;
   for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) continue;


      /* incomming response ('from' == 'masq') */
      if (compare_url(response->from->url, urlmap[i].masq_url)==STS_SUCCESS) {
         type=RESTYP_INCOMMING;
         DEBUGC(DBCLASS_PROXY,"incomming response for %s@%s from outbound",
	        response->from->url->username,
		response->from->url->host);
	 break;
      }

      /* outgoing response ('to' == 'masq') */
      if (compare_url(response->to->url, urlmap[i].masq_url)==STS_SUCCESS) {
         type=RESTYP_OUTGOING;
         DEBUGC(DBCLASS_PROXY,"outgoing response for %s@%s from inbound",
	        response->from->url->username,
		response->from->url->host);
	 break;
      }
   }

/*
 * ok, we got a response that we are allowed to process.
 */
   switch (type) {
  /*
   * from an external host to the internal masqueraded host
   */
   case RESTYP_INCOMMING:
      break;
   
  /*
   * from the internal masqueraded host to an external host
   */
   case RESTYP_OUTGOING:
      #define satoi atoi  /* used in MSG_TEST_CODE macro ... */
      /* If an 200 answer to an INVITE request, rewrite body */
      if ((MSG_IS_RESPONSEFOR(response,"INVITE")) &&
          (MSG_TEST_CODE(response, 200))) {
         sts = proxy_rewrite_invitation_body(response);
      }

      /* rewrite Contact header to represent the masqued address */
      msg_getcontact(response,0,&contact);
      if (contact != NULL) {
         for (i=0;i<URLMAP_SIZE;i++){
	    if (urlmap[i].active == 0) continue;
            if (compare_url(contact->url, urlmap[i].true_url)==STS_SUCCESS)
	       break;
         }
         /* found a mapping entry */
         if (i<URLMAP_SIZE) {
            DEBUGC(DBCLASS_PROXY, "rewrote Contact header %s@%s -> %s@%s",
	           contact->url->username, contact->url->host,
		   urlmap[i].masq_url->username, urlmap[i].masq_url->host);
            /* remove old entry */
            list_remove(response->contacts,0);
            contact_free(contact);
            free(contact);
            /* clone the masquerading url */
	    contact_init(&contact);
            url_clone(urlmap[i].masq_url, &contact->url);
            list_add(response->contacts,contact,-1);
         }     
      }

      break;
   
   default:
      DEBUGC(DBCLASS_PROXY,"response: refuse to proxy - UA not registered?");
/* some clients seem to run amok when passing back a negative response */
//      proxy_gen_response(request, 403 /*forbidden*/);
      return STS_FAILURE;
   }

   /* get target address from VIA header */
   via = (via_t *) list_get (response->vias, 0);

   sts = get_ip_by_host(via->host, &addr);

   sts = msg_2char(response, &buffer);
   if (sts != 0) {
      ERROR("proxy_request: msg_2char failed");
      return STS_FAILURE;
   }

   /* send to destination */
   if (via->port) {
      port=atoi(via->port);
   } else {
      port=configuration.sip_listen_port;
   }

   sipsock_send_udp(&sip_socket, addr, port, buffer, strlen(buffer), 1); 
   free (buffer);
   return STS_SUCCESS;
}


/*
 * PROXY_GEN_RESPONSE
 *
 * send an proxy generated response back to the client.
 * Only errors are reported from the proxy itself.
 *  code =  SIP result code to deliver
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_gen_response(sip_t *request, int code) {
   sip_t *response;
   int sts;
   via_t *via;
   char *buffer;
   struct in_addr addr;

   /* create the response template */
   if ((response=msg_make_template_reply(request, code))==NULL) {
      ERROR("proxy_response: error in msg_make_template_reply");
      return STS_FAILURE;
   }

   /* we must check if first via has x.x.x.x address. If not, we must resolve it */
   msg_getvia (response, 0, &via);
   if (via == NULL)
   {
      ERROR("proxy_response: Cannot send response - no via field");
      return STS_FAILURE;
   }


/* name resolution */
   if (inet_aton (via->host,&addr) == 0)
   {
      /* need name resolution */
      DEBUGC(DBCLASS_DNS,"resolving name:%s",via->host);
      sts = get_ip_by_host(via->host, &addr);
   }   

DEBUGC(DBCLASS_PROXY,"response=%p",response);
   sts = msg_2char(response, &buffer);
   if (sts != 0) {
      ERROR("proxy_response: msg_2char failed");
      return STS_FAILURE;
   }

   /* send to destination */
   sipsock_send_udp(&sip_socket, addr, atoi(via->port),
                    buffer, strlen(buffer), 1);

   /* free the resources */
   msg_free(response);
   free(response);
   free (buffer);
   return STS_SUCCESS;
}


/*
 * PROXY_ADD_MYVIA
 *
 * interface == 0 -> outbound interface, else inbound interface
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_add_myvia (sip_t *request, int interface) {
   struct in_addr addr;
   char tmp[URL_STRING_SIZE];
   via_t *via;
   int sts;

   if (interface == 0) {
      sts = get_ip_by_host(configuration.outboundhost, &addr);
   } else {
      sts = get_ip_by_host(configuration.inboundhost, &addr);
   }

   sprintf (tmp, "SIP/2.0/UDP %s:%i", inet_ntoa(addr),
            configuration.sip_listen_port);
   DEBUGC(DBCLASS_BABBLE,"adding VIA:%s",tmp);

   sts = via_init(&via);
   if (sts!=0) return STS_FAILURE; /* allocation failed */
   sts = via_parse(via, tmp);
   if (sts!=0) return STS_FAILURE;
   list_add(request->vias,via,0);

   return STS_SUCCESS;
}


/*
 * PROXY_DEL_MYVIA
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_del_myvia (sip_t *response) {
   via_t *via;
   int sts;

   DEBUGC(DBCLASS_PROXY,"deleting topmost VIA");
   via = list_get (response->vias, 0);
   
   if ( is_via_local(via) == STS_FALSE ) {
      ERROR("I'm trying to delete a VIA but it's not mine! host=%s",via->host);
      return STS_FAILURE;
   }

   sts = list_remove(response->vias, 0);
   via_free (via);
   free(via);
   return STS_SUCCESS;
}


/*
 * PROXY_REWRITE_INVITATION_BODY
 *
 * rewrites the outgoing INVITATION packet
 * 
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_rewrite_invitation_body(sip_t *mymsg){
   body_t *body;
   sdp_t  *sdp;
   struct in_addr outb_addr, lcl_clnt_addr;
   int sts;
   char *oldbody;
   char newbody[BODY_MESSAGE_MAX_SIZE];
   char clen[8]; /* content length: probably never more than 7 digits !*/
   int outb_rtp_port, inb_clnt_port;

   sts = msg_getbody(mymsg, 0, &body);
   if (sts != 0) {
      ERROR("rewrite_invitation_body: no body found in message");
      return STS_FAILURE;
   }

   sts = body_2char(body, &oldbody);

   sts = sdp_init(&sdp);
   sts = sdp_parse (sdp, oldbody);
   if (sts != 0) {
      ERROR("rewrite_invitation_body: unable to sdp_parse body");
      return STS_FAILURE;
   }

{ /* just dump the buffer */
   char *tmp2;
   content_length_2char(mymsg->contentlength, &tmp2);
   DEBUG("Body before rewrite (clen=%s, strlen=%i):\n%s\n----",
         tmp2, strlen(oldbody), oldbody);
   free(tmp2);
}


   /*
    * RTP proxy: get ready and start forwarding
    */
   sts = get_ip_by_host(sdp_c_addr_get(sdp,-1,0), &lcl_clnt_addr);
   sts = get_ip_by_host(configuration.outboundhost, &outb_addr);
   inb_clnt_port = atoi(sdp_m_port_get(sdp,0));
   /* start an RTP proxying stream */
   rtp_start_fwd(msg_getcall_id(mymsg),
                       outb_addr, &outb_rtp_port,
		       lcl_clnt_addr, inb_clnt_port);


/*
 * yup, I know - here are some HARDCODED strings that we
 * search for in the connect information and media description
 * in the SDP part of the INVITE packet
 *
 * TODO: redo the rewriting section below,
 * using the nice sdp_ routines of libosip!
 *
 * Up to now, also only ONE incomming media port per session
 * is supported! I guess, there may be more allowed.
 */
{
   char *data_c=NULL;	/* connection information 'c=' line*/
   char *data_m=NULL;	/* media description 'm=' line*/
   char *data2_c=NULL;	/* end of IP address on 'c=' line */
   char *data2_m=NULL;	/* end of port number on 'm=' line */
   char *ptr=NULL;

   memset(newbody, 0, sizeof(newbody));

   /*
    * find where to patch connection information (IP address)
    */
   data_c = strstr (oldbody, "\nc=");
   if (data_c == NULL) data_c = strstr (oldbody, "\rc=");
   if (data_c == NULL) {
      ERROR("did not find a c= line in the body");
      return STS_FAILURE;
   }
   data_c += 3;
   /* can only rewrite IPV4 addresses by now */
   if (strncmp(data_c,"IN IP4 ",7)!=0) {
      ERROR("c= does not contain an IN IP4 address");
      return STS_FAILURE;
   }
   data_c += 7; /* PTR to start of IP address */
   /* find the end of the IP address -> end of line */
   data2_c = strstr (data_c, "\n");
   if (data2_c == NULL) data2_c = strstr (oldbody, "\r");
   if (data2_c == NULL) {
      ERROR("did not find a CR/LF after c= line");
      return STS_FAILURE;
   }

   /*
    * find where to patch media description (port number)
    */
   data_m = strstr (oldbody, "\nm=");
   if (data_m == NULL) data_m = strstr (oldbody, "\rm=");
   if (data_m == NULL) {
      ERROR("did not find a m= line in the body");
      return STS_FAILURE;
   }
   data_m += 3;
   /* check for audio media */
   if (strncmp(data_m,"audio ",6)!=0) {
      ERROR("m= does not contain audio");
      return STS_FAILURE;
   }
   data_m += 6; /* PTR to start of port number */
   /* find the end of the IP address -> end of line */
   data2_m = strstr (data_m, " RTP/");
   if (data2_m == NULL) {
      ERROR("did not find RTP/ on m= line");
      return STS_FAILURE;
   }

   /* 
    * what is first? c= or m= ?
    * (Im sure this can be made nicer)
    */
   if (data_c < data_m) {
      DEBUGC(DBCLASS_PROXY,"c= before m=");
      /*
       * c= line first, replace IP address, then port
       */
      /* copy up to the to-be-masqueraded address */
      memcpy(newbody, oldbody, data_c-oldbody);
      /* insert proxy outbound address */
      ptr=newbody+(data_c-oldbody);
      sprintf(ptr, "%s", inet_ntoa(outb_addr));
      ptr += strlen(ptr);
      /* copy up to the m= line */
      memcpy (ptr, data2_c, data_m-data2_c);
      ptr += strlen(ptr);
      /* substitute port number */
      sprintf(ptr, "%i", outb_rtp_port);
      ptr += strlen(ptr);
     /* copy the rest */
      memcpy (ptr, data2_m, strlen(data2_m));
   } else {
      DEBUGC(DBCLASS_PROXY,"m= before c=");
      /*
       * m= line first, replace port, then IP address
       */
      /* copy up to the to-be-masqueraded port */
      memcpy(newbody, oldbody, data_m-oldbody);
      ptr=newbody+(data_m-oldbody);
      /* substitute port number */
      sprintf(ptr, "%i", outb_rtp_port);
      ptr += strlen(ptr);
      /* copy up to the c= line */
      memcpy (ptr, data2_m, data_c-data2_m);
      ptr += strlen(ptr);
      /* insert proxy outbound address */
      sprintf(ptr, "%s", inet_ntoa(outb_addr));
      ptr += strlen(ptr);
      /* copy the rest */
      memcpy (ptr, data2_c, strlen(data2_c));
   }




}

   /* remove old body */
   sts = list_remove(mymsg->bodies, 0);
   body_free(body);
   free(body);
   /* free sdp structure */
   sdp_free(sdp);
   free(sdp);

   /* include new body */
   msg_setbody(mymsg, newbody);

   /* free content length resource and include new one*/
   content_length_free(mymsg->contentlength);
   free(mymsg->contentlength);
   mymsg->contentlength=NULL;
   sprintf(clen,"%i",strlen(newbody));
   sts = msg_setcontent_length(mymsg, clen);


{ /* just dump the buffer */
   char *tmp, *tmp2;
   sts = msg_getbody(mymsg, 0, &body);
   sts = body_2char(body, &tmp);
   content_length_2char(mymsg->contentlength, &tmp2);
   DEBUG("Body after rewrite (clen=%s, strlen=%i):\n%s\n----",
         tmp2, strlen(tmp), tmp);
   free(tmp);
   free(tmp2);
}
   free(oldbody);
   return STS_SUCCESS;
}
