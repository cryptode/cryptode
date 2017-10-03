%define rvc_confdir %{_sysconfdir}/rvc
%define rvc_datadir %{_datadir}/rvc

%define version 0.9.0
#%define dev_rel dev25
#%define release 1

Name: rvc
Summary: Relaxed VPN Client command line tool
Version: %{version}
Release: %{release}%{?dist}
License: GPLv2+
URL: https://github.com/riboseinc/rvc
Group: System Environment/Daemons

Source0: rvc-0.9.0.tar.gz
Source1: rvd.json

Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service
Requires(postun): /sbin/service

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: json-c-devel openssl-devel
BuildRequires: setup >= 2.5
Requires: json-c openssl

%description
RVC is a secure CLI-based OpenVPN client for Linux/MacOS.

%prep
%setup -q -n %{name}-%{version}

%build
rm -rf %{buildroot}
./configure --prefix=%{buildroot}/usr --sysconfdir=%{buildroot}/etc/rvc
make

%install
make install
rm -rf %{buildroot}/usr/include
rm -rf %{buildroot}/usr/bin/dns_util.sh
rm -rf %{buildroot}/usr/var

%files
%defattr(-,root,root,-)
%config(noreplace) %{rvc_confdir}/rvd.json
%attr(0600, root, root) %{rvc_confdir}/rvd.json
%{_initrddir}/rvd
%{_sbindir}/rvd
%{_bindir}/%{name}

%clean
rm -rf %{buildroot}

%pre

%post
/sbin/chkconfig --add rvd

mkdir -p %{rvc_confdir}/vpn.d
mkdir -p %{_localstatedir}/log/rvd

%preun
if [ "$1" -eq 0 ]; then
    /sbin/service rvd stop >/dev/null 2>&1
    /sbin/chkconfig --del rvd
fi

%postun
if [ "$1" -ge 1 ]; then
    /sbin/service rvd condrestart >/dev/null 2>&1 || :
fi

rm -rf %{_localstatedir}/log/rvd

%changelog
* Sun Oct 01 2017 Jin JinRu <jin.jinru840430@gmail.com> - 0.9.0
- Added first version of rvc
