import_options!{
// The following values are directly from recent OpenSSL
SSL_OP_MICROSOFT_SESS_ID_BUG                   0x00000001
SSL_OP_NETSCAPE_CHALLENGE_BUG                  0x00000002
SSL_OP_LEGACY_SERVER_CONNECT                   0x00000004
SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG        0x00000008
SSL_OP_TLSEXT_PADDING                          0x00000010
SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER              0x00000020
SSL_OP_SAFARI_ECDHE_ECDSA_BUG                  0x00000040
SSL_OP_SSLEAY_080_CLIENT_DH_BUG                0x00000080
SSL_OP_TLS_D5_BUG                              0x00000100
SSL_OP_TLS_BLOCK_PADDING_BUG                   0x00000200
// unused:                                     0x00000400
SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS             0x00000800
SSL_OP_NO_QUERY_MTU                            0x00001000
SSL_OP_COOKIE_EXCHANGE                         0x00002000
SSL_OP_NO_TICKET                               0x00004000
SSL_OP_CISCO_ANYCONNECT                        0x00008000
SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION  0x00010000
SSL_OP_NO_COMPRESSION                          0x00020000
SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION       0x00040000
SSL_OP_SINGLE_ECDH_USE                         0x00080000
SSL_OP_SINGLE_DH_USE                           0x00100000
// unused:                                     0x00200000
SSL_OP_CIPHER_SERVER_PREFERENCE                0x00400000
SSL_OP_TLS_ROLLBACK_BUG                        0x00800000
SSL_OP_NO_SSLv2                                0x01000000
SSL_OP_NO_SSLv3                                0x02000000
SSL_OP_NO_DTLSv1                               0x04000000
SSL_OP_NO_TLSv1                                0x04000000
SSL_OP_NO_DTLSv1_2                             0x08000000
SSL_OP_NO_TLSv1_2                              0x08000000
SSL_OP_NO_TLSv1_1                              0x10000000
SSL_OP_NETSCAPE_CA_DN_BUG                      0x20000000
SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG         0x40000000
SSL_OP_CRYPTOPRO_TLSEXT_BUG                    0x80000000

// The following values were in 32-bit range in old OpenSSL
SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG             0x100000000
SSL_OP_MSIE_SSLV2_RSA_PADDING                  0x200000000
SSL_OP_PKCS1_CHECK_1                           0x400000000
SSL_OP_PKCS1_CHECK_2                           0x800000000

// The following values were redefined to 0 for security reasons
SSL_OP_EPHEMERAL_RSA                           0x0
}
