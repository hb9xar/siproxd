%define name		siproxd
%define ver		0.2.8
%define release		1
%define serial		1
%define prefix		%{_prefix}
%define sysconfdir	%{_sysconfdir}

Name:		%{name}
Summary:	A SIP masquerading proxy with RTP support
Version: 	%{ver}
Release: 	%{release}
Copyright: 	GPL
Group:		Applications/Communications
Source0: 	%{name}-%{ver}.tar.gz

URL: 		http://siproxd.sourceforge.net/
BuildRoot:	%{_tmppath}/%{name}-%{ver}-root
Docdir: 	%{_docdir}

Requires:	libosip >= 0.8.0
BuildRequires:	libosip >= 0.8.0

Vendor:		Thomas Ries

Packager:       Thomas Ries <tries@gmx.net>

%description
Siprox is an proxy/masquerading daemon for the SIP protocol.
It handles registrations of SIP clients on a private IP network
and performs rewriting of the SIP message bodies to make SIP
connections possible via an masquerading firewall.
It allows SIP clients (like kphone, linphone) to work behind
an IP masquerading firewall or router.


%prep
%setup -q

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{prefix} --sysconfdir=%{sysconfdir}
make

%install
make prefix=$RPM_BUILD_ROOT%{prefix} PIXDESTDIR=$RPM_BUILD_ROOT sysconfdir=$RPM_BUILD_ROOT%{sysconfdir} install


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-, root, root)
%doc COPYING README AUTHORS INSTALL NEWS ChangeLog
%{_bindir}/siproxd

%changelog
* Sat Sep 21 2002 Thomas Ries <tries@gmx.net>
- first RPM support
