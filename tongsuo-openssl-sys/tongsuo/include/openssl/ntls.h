/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

#ifndef HEADER_NTLS_H
#define HEADER_NTLS_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_NTLS
#  ifdef  __cplusplus
extern "C" {
#  endif

/* NTLS version */
#  define NTLS1_1_VERSION       0x0101
#  define NTLS1_1_VERSION_MAJOR 0x01
#  define NTLS1_1_VERSION_MINOR 0x01
#  define NTLS_VERSION          NTLS1_1_VERSION
#  define NTLS_VERSION_MAJOR    NTLS1_1_VERSION_MAJOR
#  define NTLS_VERSOIN_MINOR    NTLS1_1_VERSION_MINOR
/*
 * This tag is used to replace SSLv3 when use NTLS.
 * SSLv3 is not used default, so it always be the min protocal version in test,
 * but when add NTLS, the NTLS becomes the min version, and NTLS is commonly use,
 * then will cause some problems, so add this tag
 */
#  define MIN_VERSION_WITH_NTLS 0x0100

/* Compatible with GM/T 0024-2014 cipher suites name */
#  define NTLS_TXT_SM2DHE_WITH_SM4_SM3          "ECDHE-SM2-WITH-SM4-SM3"
#  define NTLS_TXT_SM2_WITH_SM4_SM3             "ECC-SM2-WITH-SM4-SM3"

/* GB/T 38636-2020 TLCP, cipher suites */
#  define NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3        "ECDHE-SM2-SM4-CBC-SM3"
#  define NTLS_TXT_ECDHE_SM2_SM4_GCM_SM3        "ECDHE-SM2-SM4-GCM-SM3"
#  define NTLS_TXT_ECC_SM2_SM4_CBC_SM3          "ECC-SM2-SM4-CBC-SM3"
#  define NTLS_TXT_ECC_SM2_SM4_GCM_SM3          "ECC-SM2-SM4-GCM-SM3"
#  define NTLS_TXT_IBSDH_SM9_SM4_CBC_SM3        "IBSDH-SM9-SM4-CBC-SM3"
#  define NTLS_TXT_IBSDH_SM9_SM4_GCM_SM3        "IBSDH-SM9-SM4-GCM-SM3"
#  define NTLS_TXT_IBC_SM9_SM4_CBC_SM3          "IBC-SM9-SM4-CBC-SM3"
#  define NTLS_TXT_IBC_SM9_SM4_GCM_SM3          "IBC-SM9-SM4-GCM-SM3"
#  define NTLS_TXT_RSA_SM4_CBC_SM3              "RSA-SM4-CBC-SM3"
#  define NTLS_TXT_RSA_SM4_GCM_SM3              "RSA-SM4-GCM-SM3"
#  define NTLS_TXT_RSA_SM4_CBC_SHA256           "RSA-SM4-CBC-SHA256"
#  define NTLS_TXT_RSA_SM4_GCM_SHA256           "RSA-SM4-GCM-SHA256"

#  define NTLS_GB_ECDHE_SM2_SM4_CBC_SM3         "ECDHE_SM4_CBC_SM3"
#  define NTLS_GB_ECDHE_SM2_SM4_GCM_SM3         "ECDHE_SM4_GCM_SM3"
#  define NTLS_GB_ECC_SM2_SM4_CBC_SM3           "ECC_SM4_CBC_SM3"
#  define NTLS_GB_ECC_SM2_SM4_GCM_SM3           "ECC_SM4_GCM_SM3"
#  define NTLS_GB_IBSDH_SM9_SM4_CBC_SM3         "IBSDH_SM4_CBC_SM3"
#  define NTLS_GB_IBSDH_SM9_SM4_GCM_SM3         "IBSDH_SM4_GCM_SM3"
#  define NTLS_GB_IBC_SM9_SM4_CBC_SM3           "IBC_SM4_CBC_SM3"
#  define NTLS_GB_IBC_SM9_SM4_GCM_SM3           "IBC_SM4_GCM_SM3"
#  define NTLS_GB_RSA_SM4_CBC_SM3               "RSA_SM4_CBC_SM3"
#  define NTLS_GB_RSA_SM4_GCM_SM3               "RSA_SM4_GCM_SM3"
#  define NTLS_GB_RSA_SM4_CBC_SHA256            "RSA_SM4_CBC_SHA256"
#  define NTLS_GB_RSA_SM4_GCM_SHA256            "RSA_SM4_GCM_SHA256"

#  define NTLS_CK_ECDHE_SM2_SM4_CBC_SM3         0x0300E011
#  define NTLS_CK_ECDHE_SM2_SM4_GCM_SM3         0x0300E051
#  define NTLS_CK_ECC_SM2_SM4_CBC_SM3           0x0300E013
#  define NTLS_CK_ECC_SM2_SM4_GCM_SM3           0x0300E053
#  define NTLS_CK_IBSDH_SM9_SM4_CBC_SM3         0x0300E015
#  define NTLS_CK_IBSDH_SM9_SM4_GCM_SM3         0x0300E055
#  define NTLS_CK_IBC_SM9_SM4_CBC_SM3           0x0300E017
#  define NTLS_CK_IBC_SM9_SM4_GCM_SM3           0x0300E057
#  define NTLS_CK_RSA_SM4_CBC_SM3               0x0300E019
#  define NTLS_CK_RSA_SM4_GCM_SM3               0x0300E059
#  define NTLS_CK_RSA_SM4_CBC_SHA256            0x0300E01C
#  define NTLS_CK_RSA_SM4_GCM_SHA256            0x0300E05a


#  define NTLS_AD_UNSUPPORTED_SITE2SITE         200
#  define NTLS_AD_NO_AREA                       201
#  define NTLS_AD_UNSUPPORTED_AREATYPE          202
#  define NTLS_AD_BAD_IBCPARAM                  203
#  define NTLS_AD_UNSUPPORTED_IBCPARAM          204
#  define NTLS_AD_IDENTITY_NEED                 205

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
