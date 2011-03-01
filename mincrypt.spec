%if 0%{?suse_version}
%define         php_confdir %{_sysconfdir}/php5/conf.d
%define         php_extdir      %{_libdir}/php5/extensions
%else
%define         php_confdir %{_sysconfdir}/php.d
%define         php_extdir  %{_libdir}/php/modules
%endif

Name:		mincrypt
Version:	0.0.1
Release:	1%{?dist}%{?extra_release}
Summary:	MinCrypt crypto-algorithm implementation
Source:		http://www.migsoft.net/projects/mincrypt/mincrypt-%{version}.tar.gz

Group:		Development/Libraries
License:	GPL
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root

%if 0%{?suse_version}  
Requires:	php5
%else
Requires:	php
%endif

%description
MinCrypt minimal encryption/decryption system

%prep
%setup -q -n mincrypt-%{version}

%build
%configure
./configure
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}
mkdir -p $RPM_BUILD_ROOT%{_bindir}/bin
mv $RPM_BUILD_ROOT/usr/local/bin/mincrypt $RPM_BUILD_ROOT%{_bindir}/mincrypt

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/mincrypt
%{php_extdir}/mincrypt-php.so
%config(noreplace) %{php_confdir}/mincrypt-php.ini

%changelog

