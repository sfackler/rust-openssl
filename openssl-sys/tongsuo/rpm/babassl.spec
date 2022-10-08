%define base_release 1

%define babassl_prefix /opt/babassl

%global _privatelibs libcrypto[.]so.*
%global _privatelibs %{_privatelibs}|libssl[.]so.*
%global __provides_exclude ^(%{_privatelibs})$
%global __requires_exclude ^(%{_privatelibs})$

%global DOMAIN github.com
%global ORG BabaSSL
%global PROJECT BabaSSL
%global IMPORTNAME %{DOMAIN}/%{ORG}/%{PROJECT}

Name:           babassl
Version:        8.3.0
Release:        %{base_release}%{?dist}
Summary:        A Brisk and Better Assured Cryptographic Toolkit
Group:          System Environment/Libraries
License:        Apache-2.0
ExclusiveArch:	x86_64 aarch64
Url:            https://%{IMPORTNAME}
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-root
BuildRequires:  coreutils, perl
BuildRequires:  perl-Test-Harness, perl-core

%description
BabaSSL is a modern cryptographic and secure protocol library developed by the
 amazing people in Alibaba Digital Economy.

%prep
%setup -q -n BabaSSL-%{version}

%build
sslarch=%{_os}-%{_target_cpu}

%ifarch %ix86
sslarch=linux-x86
%endif
%ifarch x86_64
sslarch=linux-x86_64
%endif
%ifarch aarch64
sslarch=linux-aarch64
%endif

./Configure \
    --prefix=%{babassl_prefix} -Wl,-rpath,%{babassl_prefix}/lib \
    ${sslarch} enable-shared no-hw no-hw-padlock no-static-engine \
    enable-dynamic-engine enable-tls1_3 enable-ssl3 enable-ssl3-method \
    enable-weak-ssl-ciphers enable-evp-cipher-api-compat enable-status \
    enable-crypto-mdebug-count enable-dynamic-ciphers enable-optimize-chacha \
    enable-rsa-multi-prime-key-compat enable-session-lookup \
    enable-session-reused-type enable-global-session-cache enable-verify-sni \
    enable-skip-scsv enable-ntls enable-sm2 --strict-warnings --release -fPIC \
    %{optflags} -Wa,--noexecstack -DPURIFY -Wno-unused-result

make %{?_smp_mflags}

%check
make test

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

make install DESTDIR=$RPM_BUILD_ROOT

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{babassl_prefix}
%exclude %{babassl_prefix}/bin/c_rehash
%exclude %{babassl_prefix}/ssl/misc/tsget*
%exclude %{babassl_prefix}/ssl/misc/*.pl

%changelog

