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
#include "config.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>

#include <osipparser2/osip_parser.h>
#include "siproxd.h"
#include "log.h"

#include "addrcache.h"


typedef struct 
{
	osip_message_t		*sipmsg;
	int			direction;
	int			channel;
	struct sockaddr_in	source;
	int			lastused;
} addrcache_t ;



/*
 * count the request's
 */
static int tacount;

/*
 * table to remember the sources
 */
static addrcache_t cachetable[SOURCECACHE_SIZE];


/*
 * We caching the address as function of from and to header to
 * find the correct path where to send the sip-responses
 */


/*
 * initialize internal variables
 */
int 	adr_cache_init(void)
{
	tacount = 1 ;
	memset(&cachetable, 0, sizeof(cachetable));
	return STS_SUCCESS;
}



int	my_cseq_match (osip_cseq_t * cseq1, osip_cseq_t * cseq2)
{
	if (cseq1 == NULL || cseq2 == NULL) return -1;
	if (cseq1->number == NULL || cseq2->number == NULL ||
	    cseq1->method == NULL || cseq2->method == NULL) return -1 ;

	if (0 != strcmp (cseq1->number, cseq2->number)) return -1 ;
	if (0 != strcmp (cseq1->method, cseq2->method)) return -1 ;

	return 0;
}


/*
 * We seek for an existing entry
 * if not found, we return a suggest which entry shoud be overwritten
 */
int	seek_for_entry (osip_message_t *sipmsg, addrcache_t **entry_out)
{
	int			i;

	addrcache_t		*entry;
	addrcache_t		*suggest;


	for (suggest=entry=&cachetable[0],i=0;i<SOURCECACHE_SIZE;i++,entry++)
	{
		if (entry->sipmsg)
		{
			if ((0 == osip_call_id_match (sipmsg->call_id, entry->sipmsg->call_id)) &&
			    (0 == osip_from_tag_match (sipmsg->from,entry->sipmsg->from)) &&
			    (0 == my_cseq_match (sipmsg->cseq, sipmsg->cseq)) )
			{
				int level = 0 ;
				int isequal = 1 ;

				osip_via_t 		*via1;
				osip_via_t 		*via2;

				while ( isequal &&
					(level == 0 || entry->direction == DIR_INCOMING) &&
					!osip_list_eol (sipmsg->vias, level) &&
					!osip_list_eol (entry->sipmsg->vias, level) &&
					(via1 = (osip_via_t *) osip_list_get (sipmsg->vias, level)) &&
					(via2 = (osip_via_t *) osip_list_get (entry->sipmsg->vias, level)) &&
					(level < 70))
				{
					/*
					 * This must be, because of legal loop backs in case of
					 * calling one party behind this prox from behind this
					 * proxy :-/
					 */

					osip_generic_param_t	*branch ;
					char			*branch_value = "\0";
					char			*branch_compare = "\0";

					osip_via_param_get_byname (via1, "branch", &branch);
					if (branch && branch->gvalue) branch_value = branch->gvalue ;


 					osip_via_param_get_byname (via2, "branch", &branch);
					if (branch && branch->gvalue) branch_compare = branch->gvalue ;

					if (0 != strcmp(branch_value,branch_compare)) isequal = 0 ;

					level ++ ;
				} ;
				if (isequal &&
					osip_list_eol (sipmsg->vias, level) &&
					(osip_list_eol (entry->sipmsg->vias, level) || 
					 entry->direction == DIR_OUTGOING ) )
				{
					*entry_out = entry ;
					return STS_SUCCESS;
				}
			}
			if (suggest->lastused > entry->lastused)
			{
				suggest = entry ;
			} ;
		}
		else
		{
			suggest = entry ;
			suggest->lastused = 0 ;
		} ;
	} ;

	*entry_out = suggest ;
	return STS_FAILURE ;
}

int	store_address (osip_message_t *sipmsg, int direction, int channel, const struct sockaddr_in *source)
{
	int		sts;
	addrcache_t	*entry;

	sts = seek_for_entry (sipmsg,&entry) ;

	if (entry->sipmsg)
	{
		osip_message_free (entry->sipmsg) ;
		entry->sipmsg = NULL ;
	} ;

	if (osip_message_clone (sipmsg,&(entry->sipmsg)))
	{
		entry->sipmsg = NULL ;
		return STS_FAILURE ;
	} ;

	entry->lastused = tacount ++ ;
	entry->direction = direction ;
	entry->channel = channel ;
        memcpy(&(entry->source), source, sizeof (*source));

	return STS_SUCCESS;
}

int  load_address (osip_message_t *sipmsg, osip_message_t ** initsipmsg,
                     int *direction, int *channel, struct sockaddr_in *source)
{
	int		sts;
	addrcache_t	*entry;

	sts = seek_for_entry (sipmsg,&entry) ;
	if (sts == STS_FAILURE)
	{
		return STS_FAILURE ;
	} ;

	*initsipmsg = entry->sipmsg ;
	*direction = entry->direction ;
	*channel = entry->channel ;
	memcpy(source, &(entry->source), sizeof (*source));

	return STS_SUCCESS;
}

/*
not yet used:
int  adr_cache_kill(void)
{
	int		i;
	addrcache_t	*entry;

	for (entry=&cachetable[0],i=0;i<SOURCECACHE_SIZE;i++,entry++)
	{
		if (entry->sipmsg)
		{
			osip_message_free (entry->sipmsg) ;
			entry->sipmsg = NULL ;
		} ;
	} ;
	return STS_SUCCESS;
}
*/
