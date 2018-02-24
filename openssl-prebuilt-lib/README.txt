OpenSSL static library guide for VS2017

# Read NOTES.WIN and NOTES.PERL

# https://github.com/openssl/openssl/issues/1061
# Add 'crypt32.lib' to linker command
# Otherwise we get
# 1>libcrypto.lib(e_capi.obj) : error LNK2001: unresolved external symbol __imp_CertOpenStore
# 1>libcrypto.lib(e_capi.obj) : error LNK2001: unresolved external symbol __imp_CertCloseStore
# 1>libcrypto.lib(e_capi.obj) : error LNK2001: unresolved external symbol __imp_CertEnumCertificatesInStore
# 1>libcrypto.lib(e_capi.obj) : error LNK2001: unresolved external symbol __imp_CertFindCertificateInStore
# 1>libcrypto.lib(e_capi.obj) : error LNK2001: unresolved external symbol __imp_CertDuplicateCertificateContext
# 1>libcrypto.lib(e_capi.obj) : error LNK2001: unresolved external symbol __imp_CertFreeCertificateContext
# 1>libcrypto.lib(e_capi.obj) : error LNK2001: unresolved external symbol __imp_CertGetCertificateContextProperty

# use Visual Studio native tools command prompt
# use activeperl, install NASM assembler
ppm install dmake

# Win32 x86
set PATH=D:\NASM-32;%PATH%
# configure with no zlib
perl Configure VC-WIN32 no-shared --release --prefix=C:\Users\home\Downloads\openssl-1.1.0g\x86-build --openssldir=C:\Users\home\Downloads\openssl-1.1.0g\x86-install
nmake
nmake test
# to rebuild
nmake distclean

# x64
set PATH=D:\NASM-64;%PATH%
perl Configure VC-WIN64A no-shared --release --prefix=C:\Users\home\Downloads\openssl-1.1.0g\x64-build --openssldir=C:\Users\home\Downloads\openssl-1.1.0g\x64-install
# others are the same as x86
