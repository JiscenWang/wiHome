# $Id$

%define name whome
%define lib_name libhttpd
%define version 1.0.0
%define release 1mdk

Summary: The wiHome project is a solution for self fun at home.
Name: %{name}
Version: %{version}
Release: %{release}
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prereq: /sbin/ldconfig

%description
The wiHome project is a solution for self fun at home.

%prep
%setup -q

%build
%configure
%make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_prefix}


# Will this overide previous config file?
mkdir -p $RPM_BUILD_ROOT/etc
cp WirelessHome.conf $RPM_BUILD_ROOT/etc

%makeinstall

%post
/sbin/ldconfig
%_post_service JM

%postun
/sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,0755)
%doc AUTHORS COPYING ChangeLog INSTALL NEWS README FAQ doc/html
%config /etc/WirelessHome.conf 
%{_bindir}/*
%{_libdir}/*.a
%{_libdir}/*.la
%{_libdir}/*.so*
%{_includedir}/*

%changelog
* Sun Aug 29 2004 Guillaume Beaudoin <isf@soli.ca>
- Littles fixes and libofx leftover.
- Prefix changed to /usr to match init.d script (define removed).
* Sat Mar 8 2004 Benoit Gr�goire <bock@step.polymtl.ca>
- Created spec file
