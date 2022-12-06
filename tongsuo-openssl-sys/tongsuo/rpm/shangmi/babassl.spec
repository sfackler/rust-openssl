%define linux_release 1

%define babassl_prefix /usr
%define soversion 1.1
%define openssl_version 1.1.1h
%define epoch 1
%define package_suffix shangmi

# Arches on which we need to prevent arch conflicts on opensslconf.h, must
# also be handled in opensslconf-new.h.
%define multilib_arches %{ix86} ia64 %{mips} ppc ppc64 s390 s390x sparcv9 sparc64 x86_64

%global DOMAIN github.com
%global ORG BabaSSL
%global PROJECT BabaSSL
%global IMPORTNAME %{DOMAIN}/%{ORG}/%{PROJECT}

Name:           babassl
Version:        8.3.0
Release:        %{linux_release}.%{?package_suffix}%{?dist}
Summary:        A Brisk and Better Assured Cryptographic Toolkit
Group:          System Environment/Libraries
License:        Apache-2.0
Url:            https://github.com/BabaSSL/BabaSSL.git
Source0:        %{name}-%{version}.tar.gz
Source2:        Makefile.certificate
Source6:        make-dummy-cert
Source7:        renew-dummy-cert
Source9:        opensslconf-new.h
Source10:       opensslconf-new-warning.h

# ShangMi OS Patches
Patch10001:     10001-apps-only-display-BabaSSL-version-in-the-openssl-ve.patch
Patch10002:     10002-sync-babassl-version-number-up-with-openssl-1.1.1g-.patch

BuildRoot:      %{_tmppath}/%{name}-%{version}-root
BuildRequires:  coreutils, perl
BuildRequires:  perl-Test-Harness, perl-core

Provides:       openssl = %{openssl_version}
Provides:       openssl-libs = %{epoch}:%{openssl_version}-%{linux_release}
Provides:       openssl-libs%{?_isa} = %{epoch}:%{openssl_version}
Provides:       openssl-devel = %{openssl_version}
Provides:       openssl-perl = %{openssl_version}
Provides:       openssl-static = %{openssl_version}

Conflicts:      openssl
Conflicts:      openssl-libs
Conflicts:      openssl-devel
Conflicts:      openssl-perl
Conflicts:      openssl-static

%description
BabaSSL is a modern cryptographic and secure protocol library developed by the
 amazing people in Alibaba Digital Economy.

%prep
%setup -q -n BabaSSL-%{version}

%patch10001 -p1
%patch10002 -p1

%build
# Figure out which flags we want to use.
# default
sslarch=%{_os}-%{_target_cpu}
%ifarch %ix86
sslarch=linux-elf
if ! echo %{_target} | grep -q i686 ; then
        sslflags="no-asm 386"
fi
%endif
%ifarch x86_64
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch sparcv9
sslarch=linux-sparcv9
sslflags=no-asm
%endif
%ifarch sparc64
sslarch=linux64-sparcv9
sslflags=no-asm
%endif
%ifarch alpha alphaev56 alphaev6 alphaev67
sslarch=linux-alpha-gcc
%endif
%ifarch s390 sh3eb sh4eb
sslarch="linux-generic32 -DB_ENDIAN"
%endif
%ifarch s390x
sslarch="linux64-s390x"
%endif
%ifarch %{arm}
sslarch=linux-armv4
%endif
%ifarch aarch64
sslarch=linux-aarch64
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch sh3 sh4
sslarch=linux-generic32
%endif
%ifarch ppc64 ppc64p7
sslarch=linux-ppc64
%endif
%ifarch ppc64le
sslarch="linux-ppc64le"
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch mips mipsel
sslarch="linux-mips32 -mips32r2"
%endif
%ifarch mips64 mips64el
sslarch="linux64-mips64 -mips64r2"
%endif
%ifarch mips64el
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch riscv64
sslarch=linux-generic64
%endif

# Add -Wa,--noexecstack here so that libcrypto's assembler modules will be
# marked as not requiring an executable stack.
# Also add -DPURIFY to make using valgrind with openssl easier as we do not
# want to depend on the uninitialized memory as a source of entropy anyway.
RPM_OPT_FLAGS="$RPM_OPT_FLAGS -Wa,--noexecstack -Wa,--generate-missing-build-notes=yes -DPURIFY $RPM_LD_FLAGS"

# delete install_html_doc in the Makefile
sed -i "s/install_docs\: install_man_docs install_html_docs/install_docs\: install_man_docs/" Configurations/unix-Makefile.tmpl

# Configure the linux-aarch64
sed -i '/linux-aarch64/a\        multilib         => "64",' Configurations/10-main.conf

./Configure \
    --prefix=%{babassl_prefix} --openssldir=%{_sysconfdir}/pki/tls ${sslflags} \
    -Wl,-rpath,%{babassl_prefix}/lib \
    --system-ciphers-file=%{_sysconfdir}/crypto-policies/back-ends/openssl.config \
    ${sslarch} enable-shared no-hw no-hw-padlock no-static-engine \
    enable-dynamic-engine enable-tls1_3 enable-ssl3 enable-ssl3-method \
    enable-weak-ssl-ciphers enable-evp-cipher-api-compat enable-status \
    enable-crypto-mdebug-count enable-dynamic-ciphers enable-optimize-chacha \
    enable-md2 enable-rc5 \
    enable-rsa-multi-prime-key-compat enable-session-lookup \
    enable-session-reused-type enable-global-session-cache enable-verify-sni \
    enable-skip-scsv enable-ntls enable-sm2 $RPM_OPT_FLAGS --release -fPIC

make %{?_smp_mflags}

# Add generation of HMAC checksum of the final stripped library
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    ln -sf .libcrypto.so.%{version}.hmac $RPM_BUILD_ROOT%{_libdir}/.libcrypto.so.%{soversion}.hmac \
    ln -sf .libssl.so.%{version}.hmac $RPM_BUILD_ROOT%{_libdir}/.libssl.so.%{soversion}.hmac \
%{nil}

%install
make install DESTDIR=$RPM_BUILD_ROOT
rename so.%{soversion} so.%{openssl_version} $RPM_BUILD_ROOT%{_libdir}/*.so.%{soversion}
for lib in $RPM_BUILD_ROOT%{_libdir}/*.so.%{openssl_version} ; do
        chmod 755 ${lib}
        ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{openssl_version}`
        ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{openssl_version}`.%{soversion}
done

# Install a makefile for generating keys and self-signed certs, and a script
# for generating them on the fly.
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/certs
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/openssl
install -m644 %{SOURCE2} $RPM_BUILD_ROOT/usr/share/doc/openssl/Makefile.certificate
install -m755 %{SOURCE6} $RPM_BUILD_ROOT%{_bindir}/make-dummy-cert
install -m755 %{SOURCE7} $RPM_BUILD_ROOT%{_bindir}/renew-dummy-cert

# Move runable perl scripts to bindir
mv $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/misc/*.pl $RPM_BUILD_ROOT%{_bindir}
mv $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/misc/tsget $RPM_BUILD_ROOT%{_bindir}

# Rename man pages so that they don't conflict with other system man pages.
pushd $RPM_BUILD_ROOT%{_mandir}
ln -s -f config.5 man5/openssl.cnf.5
for manpage in man*/* ; do
        if [ -L ${manpage} ]; then
                TARGET=`ls -l ${manpage} | awk '{ print $NF }'`
                ln -snf ${TARGET}ssl ${manpage}ssl
                rm -f ${manpage}
        else
                mv ${manpage} ${manpage}ssl
        fi
done
for conflict in passwd rand ; do
        rename ${conflict} ssl${conflict} man*/${conflict}*
# Fix dangling symlinks
        manpage=man1/openssl-${conflict}.*
        if [ -L ${manpage} ] ; then
                ln -snf ssl${conflict}.1ssl ${manpage}
        fi
done
popd

mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA
mkdir -m700 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/private
mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/certs
mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/crl
mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/newcerts

# Ensure the config file timestamps are identical across builds to avoid
# mulitlib conflicts and unnecessary renames on upgrade
touch -r %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf
touch -r %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/ct_log_list.cnf

rm -f $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf.dist
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/ct_log_list.cnf.dist

# Determine which arch opensslconf.h is going to try to #include.
basearch=%{_arch}
%ifarch %{ix86}
basearch=i386
%endif
%ifarch sparcv9
basearch=sparc
%endif
%ifarch sparc64
basearch=sparc64
%endif

%ifarch %{multilib_arches}
# Do an opensslconf.h switcheroo to avoid file conflicts on systems where you
# can have both a 32- and 64-bit version of the library, and they each need
# their own correct-but-different versions of opensslconf.h to be usable.
install -m644 %{SOURCE10} \
        $RPM_BUILD_ROOT/%{_prefix}/include/openssl/opensslconf-${basearch}.h
cat $RPM_BUILD_ROOT/%{_prefix}/include/openssl/opensslconf.h >> \
        $RPM_BUILD_ROOT/%{_prefix}/include/openssl/opensslconf-${basearch}.h
install -m644 %{SOURCE9} \
        $RPM_BUILD_ROOT/%{_prefix}/include/openssl/opensslconf.h
%endif
LD_LIBRARY_PATH=`pwd`${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}
export LD_LIBRARY_PATH

%check
# Verify that what was compiled actually works.

LD_LIBRARY_PATH=`pwd`${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}
export LD_LIBRARY_PATH
ln -s .libcrypto.so.%{soversion}.hmac .libcrypto.so.hmac
ln -s .libssl.so.%{soversion}.hmac .libssl.so.hmac
OPENSSL_ENABLE_MD5_VERIFY=
export OPENSSL_ENABLE_MD5_VERIFY
OPENSSL_SYSTEM_CIPHERS_OVERRIDE=xyz_nonexistent_file
export OPENSSL_SYSTEM_CIPHERS_OVERRIDE

make test

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{!?_licensedir:%global license %%doc}
%license LICENSE
%doc FAQ NEWS
%doc README.FIPS
%{_bindir}/openssl
%{_mandir}/man1*/*
%exclude %{_mandir}/man1*/*.pl*
%exclude %{_mandir}/man1*/c_rehash*
%exclude %{_mandir}/man1*/tsget*
%{_mandir}/man5*/*
%{_mandir}/man7*/*
%{_bindir}/make-dummy-cert
%{_bindir}/renew-dummy-cert
%{_pkgdocdir}/../openssl/Makefile.certificate
%{babassl_prefix}/lib64/engines-1.1

# libs
%dir %{_sysconfdir}/pki/tls
%dir %{_sysconfdir}/pki/tls/certs
%dir %{_sysconfdir}/pki/tls/misc
%dir %{_sysconfdir}/pki/tls/private
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.cnf
%config(noreplace) %{_sysconfdir}/pki/tls/ct_log_list.cnf
%{_libdir}/libcrypto.so.*
%{_libdir}/libssl.so.*
%{_libdir}/.libcrypto.so.*.hmac
%{_libdir}/.libssl.so.*.hmac

# devel
%doc CHANGES
%{babassl_prefix}/include/openssl
%{_libdir}/*.so
%{_mandir}/man3*/*
%{_libdir}/pkgconfig/*.pc

# static
%{_libdir}/*.a
%exclude %{babassl_prefix}/bin/c_rehash

# perl
%{_bindir}/*.pl
%{_bindir}/tsget
%dir %{_sysconfdir}/pki/CA
%dir %{_sysconfdir}/pki/CA/private
%dir %{_sysconfdir}/pki/CA/certs
%dir %{_sysconfdir}/pki/CA/crl
%dir %{_sysconfdir}/pki/CA/newcerts

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
* Fri Nov 5 2021 Yilin Li <YiLin.Li@linux.alibaba.com> - 8.3.0-1
- Init package
