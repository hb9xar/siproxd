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

#ifdef DMALLOC
 #include <dmalloc.h>
#endif

/*				function returns STS_* status values     vvv */

/* sock.c */
int sipsock_listen (void);						/*X*/
int sipsock_wait(void);
int sipsock_read(void *buf, size_t bufsize, struct sockaddr_in *from);
int sipsock_send_udp(int *sock, struct in_addr addr, int port,		/*X*/
                     char *buffer, int size, int allowdump);
int sockbind(struct in_addr ipaddr, int localport, int errflg);

/* register.c */
void register_init(void);
int  register_client(osip_message_t *request, int force_lcl_masq);	/*X*/
void register_agemap(void);
int  register_response(osip_message_t *request, int flag);		/*X*/

/* proxy.c */
int proxy_request (osip_message_t *request);				/*X*/
int proxy_response (osip_message_t *response);				/*X*/
int proxy_rewrite_invitation_body(osip_message_t *mymsg);		/*X*/
int proxy_rewrite_request_uri(osip_message_t *mymsg, int idx);		/*X*/

/* utils.c */
int  get_ip_by_host(char *hostname, struct in_addr *addr);		/*X*/
void secure_enviroment (void);
int  get_ip_by_ifname(char *ifname, struct in_addr *retaddr);		/*X*/
char *utils_inet_ntoa(struct in_addr in);
int  utils_inet_aton(const char *cp, struct in_addr *inp);

/* sip_utils.c */
osip_message_t * msg_make_template_reply (osip_message_t * request, int code);
int  check_vialoop (osip_message_t *my_msg);				/*X*/
int  is_via_local (osip_via_t *via);					/*X*/
int  compare_url(osip_uri_t *url1, osip_uri_t *url2);			/*X*/
int  compare_callid(osip_call_id_t *cid1, osip_call_id_t *cid2);	/*X*/
int  is_sipuri_local (osip_message_t *sip);				/*X*/
int  check_rewrite_rq_uri (osip_message_t *sip);			/*X*/
int  sip_gen_response(osip_message_t *request, int code);		/*X*/
#define IF_OUTBOUND 0
#define IF_INBOUND  1
int  sip_add_myvia (osip_message_t *request, int interface);		/*X*/
int  sip_del_myvia (osip_message_t *response);				/*X*/

/* readconf.c */
int read_config(char *name, int search);				/*X*/

/* rtpproxy.c */
int  rtpproxy_init( void );						/*X*/
int  rtp_start_fwd (osip_call_id_t *callid, int media_stream_no,	/*X*/
		    struct in_addr outbound_ipaddr, int *outboundport,
                    struct in_addr lcl_client_ipaddr, int lcl_clientport);
int  rtp_stop_fwd (osip_call_id_t *callid);     			/*X*/
void rtpproxy_kill( void );						/*X*/

/* accessctl.c */
int accesslist_check(struct sockaddr_in from);

/* security.c */
int security_check_raw(char *sip_buffer, int size);			/*X*/
int security_check_sip(osip_message_t *sip);				/*X*/

/* auth.c */
int authenticate_proxy(osip_message_t *request);			/*X*/
int auth_include_authrq(osip_message_t *response);			/*X*/



/*
 * table to hold the client registrations
 */
struct urlmap_s {
   int  active;
   int  expires;
   osip_uri_t *true_url;	// true URL of UA  (inbound URL)
   osip_uri_t *masq_url;	// masqueraded URL (outbound URL)
   osip_uri_t *reg_url;		// registered URL  (masq URL as wished by UA)
   osip_via_t *via;
};
/*
 * the difference between masq_url and reg_url is, 
 * the reg URL *always* holds the url registered by the UA.
 * the masq_url may contain a different URL due to an additional
 * masquerading feature (mask_host, masked_host config options)
 */


/*
 * Array of strings - used withing configuration store
 */
#define CFG_STRARR_SIZE		128
typedef struct {
   int  used;
   char *string[CFG_STRARR_SIZE];
} stringa_t;

/*
 * configuration option table
 */
struct siproxd_config {
   int debuglevel;
   char *inbound_if;
   char *outbound_if;
   int sip_listen_port;
   int daemonize;
   int silence_log;
   int rtp_port_low;
   int rtp_port_high;
   int rtp_timeout;
   int rtp_proxy_enable;
   char *user;
   char *chrootjail;
   char *hosts_allow_reg;
   char *hosts_allow_sip;
   char *hosts_deny_sip;
   char *proxy_auth_realm;
   char *proxy_auth_passwd;
   char *proxy_auth_pwfile;
   stringa_t mask_host;
   stringa_t masked_host;
   char *outbound_proxy_host;
   int  outbound_proxy_port;
};


/*
 * some constant definitions
 */
#define SIP_PORT	5060

#define URLMAP_SIZE	32	/* number of URL mapping table entries	*/
#define RTPPROXY_SIZE	64	/* number of rtp proxy entries		*/

#define BUFFER_SIZE	8196	/* input buffer for read from socket	*/
#define RTP_BUFFER_SIZE	512	/* max size of an RTP frame		*/
#define URL_STRING_SIZE	128	/* max size of an URL/URI string	*/
#define STATUSCODE_SIZE 5	/* size of string representation of status */
#define DNS_CACHE_SIZE  32	/* number of entries in internal DNS cache */
#define DNS_MAX_AGE	60	/* maximum age of an cache entry (sec)	*/
#define IFADR_CACHE_SIZE 32	/* number of entries in internal IFADR cache */
#define IFADR_MAX_AGE	5	/* max. age of the IF address cache (sec) */
#define IFNAME_SIZE	16	/* max string length of a interface name */
#define HOSTNAME_SIZE	64	/* max string length of a hostname	*/
#define USERNAME_SIZE	64	/* max string length of a username (auth) */
#define PASSWORD_SIZE	64	/* max string length of a password (auth) */


#define ACCESSCTL_SIP	1	/* for access control - SIP allowed	*/
#define ACCESSCTL_REG	2	/* --"--              - registr. allowed */

/* symbolic return status */

#define STS_SUCCESS	0	/* SUCCESS				*/
#define STS_TRUE	0	/* TRUE					*/
#define STS_FAILURE	1	/* FAILURE				*/
#define STS_FALSE	1	/* FALSE				*/
#define STS_NEED_AUTH	1001	/* need authentication			*/


/*
 * optional hacks
 */
#define HACK1	/* linphone-0.9.0pre4: broken RQ URI hack */
/* 14-Aug-2002 TR
   Linphone puts in the proxies hostname in the request URI when
   OUTBOUND proxy is activated. But ONLY the hostname. Username and
   Port (!!!) are kept from the SIP address given by the user.
   This issue is fixed in linphone-0.9.1pre1
*/

//#define MOREDEBUG
