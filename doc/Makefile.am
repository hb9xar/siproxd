#
#    Copyright (C) 2002-2005  Thomas Ries <tries@gmx.net>
#
#    This file is part of Siproxd.
#    
#    Siproxd is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#    
#    Siproxd is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#    
#    You should have received a copy of the GNU General Public License
#    along with Siproxd; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
#


EXTRA_DIST = 	siproxd.conf.example \
		siproxd_passwd.cfg \
                FAQ KNOWN_BUGS \
                FLI4L_HOWTO.txt \
                RFC3261_compliance.txt \
                sample_cfg_budgetone.txt \
                sample_cfg_x-lite.txt


install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	$(INSTALL_DATA) $(srcdir)/siproxd.conf.example	$(DESTDIR)$(sysconfdir)/
	$(INSTALL_DATA) $(srcdir)/siproxd_passwd.cfg	$(DESTDIR)$(sysconfdir)/
	chmod 600 $(DESTDIR)$(sysconfdir)/siproxd_passwd.cfg
