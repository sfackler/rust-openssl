/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

#include <openssl/ocsp.h>
#include "ssl_local_ntls.h"
#include "internal/cryptlib.h"
#include "statem_local_ntls.h"

#ifndef OPENSSL_NO_NTLS
EXT_RETURN tls_construct_ctos_server_name_ntls(SSL *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    if (s->ext.hostname == NULL)
        return EXT_RETURN_NOT_SENT;

    /* Add TLS extension servername to the Client Hello message */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_server_name)
               /* Sub-packet for server_name extension */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* Sub-packet for servername list (always 1 hostname)*/
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, TLSEXT_NAMETYPE_host_name)
            || !WPACKET_sub_memcpy_u16(pkt, s->ext.hostname,
                                       strlen(s->ext.hostname))
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_SERVER_NAME_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

/* Push a Max Fragment Len extension into ClientHello */
EXT_RETURN tls_construct_ctos_maxfragmentlen_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    if (s->ext.max_fragment_len_mode == TLSEXT_max_fragment_length_DISABLED)
        return EXT_RETURN_NOT_SENT;

    /* Add Max Fragment Length extension if client enabled it. */
    /*-
     * 4 bytes for this extension type and extension length
     * 1 byte for the Max Fragment Length code value.
     */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_max_fragment_length)
            /* Sub-packet for Max Fragment Length extension (1 byte) */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, s->ext.max_fragment_len_mode)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_CTOS_MAXFRAGMENTLEN_NTLS, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

# ifndef OPENSSL_NO_EC
EXT_RETURN tls_construct_ctos_ec_pt_formats_ntls(SSL *s, WPACKET *pkt,
                                            unsigned int context, X509 *x,
                                            size_t chainidx)
{
    /* No ec_point_formats */
    return EXT_RETURN_NOT_SENT;
}

EXT_RETURN tls_construct_ctos_supported_groups_ntls(SSL *s, WPACKET *pkt,
                                               unsigned int context, X509 *x,
                                               size_t chainidx)
{
    /* No supported_groups */
    return EXT_RETURN_NOT_SENT;
}
# endif

EXT_RETURN tls_construct_ctos_session_ticket_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    size_t ticklen;

    if (!tls_use_ticket(s))
        return EXT_RETURN_NOT_SENT;

    if (!s->new_session && s->session != NULL
            && s->session->ext.tick != NULL
            && s->session->ssl_version != TLS1_3_VERSION) {
        ticklen = s->session->ext.ticklen;
    } else if (s->session && s->ext.session_ticket != NULL
               && s->ext.session_ticket->data != NULL) {
        ticklen = s->ext.session_ticket->length;
        s->session->ext.tick = OPENSSL_malloc(ticklen);
        if (s->session->ext.tick == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CTOS_SESSION_TICKET_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        memcpy(s->session->ext.tick,
               s->ext.session_ticket->data, ticklen);
        s->session->ext.ticklen = ticklen;
    } else {
        ticklen = 0;
    }

    if (ticklen == 0 && s->ext.session_ticket != NULL &&
            s->ext.session_ticket->data == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_session_ticket)
            || !WPACKET_sub_memcpy_u16(pkt, s->session->ext.tick, ticklen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_CTOS_SESSION_TICKET_NTLS, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_ctos_sig_algs_ntls(SSL *s, WPACKET *pkt,
                                       unsigned int context, X509 *x,
                                       size_t chainidx)
{
    /* No signature_algorithms */
    return EXT_RETURN_NOT_SENT;
}

# ifndef OPENSSL_NO_OCSP
EXT_RETURN tls_construct_ctos_status_request_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    int i;

    /* This extension isn't defined for client Certificates */
    if (x != NULL)
        return EXT_RETURN_NOT_SENT;

    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_status_request)
               /* Sub-packet for status request extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, TLSEXT_STATUSTYPE_ocsp)
               /* Sub-packet for the ids */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST_NTLS, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    for (i = 0; i < sk_OCSP_RESPID_num(s->ext.ocsp.ids); i++) {
        unsigned char *idbytes;
        OCSP_RESPID *id = sk_OCSP_RESPID_value(s->ext.ocsp.ids, i);
        int idlen = i2d_OCSP_RESPID(id, NULL);

        if (idlen <= 0
                   /* Sub-packet for an individual id */
                || !WPACKET_sub_allocate_bytes_u16(pkt, idlen, &idbytes)
                || i2d_OCSP_RESPID(id, &idbytes) != idlen) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }
    if (!WPACKET_close(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST_NTLS, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    if (s->ext.ocsp.exts) {
        unsigned char *extbytes;
        int extlen = i2d_X509_EXTENSIONS(s->ext.ocsp.exts, NULL);

        if (extlen < 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        if (!WPACKET_allocate_bytes(pkt, extlen, &extbytes)
                || i2d_X509_EXTENSIONS(s->ext.ocsp.exts, &extbytes)
                   != extlen) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
       }
    }
    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST_NTLS, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
# endif

# ifndef OPENSSL_NO_NEXTPROTONEG
EXT_RETURN tls_construct_ctos_npn_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ctx->ext.npn_select_cb == NULL || !SSL_IS_FIRST_HANDSHAKE(s))
        return EXT_RETURN_NOT_SENT;

    /*
     * The client advertises an empty extension to indicate its support
     * for Next Protocol Negotiation
     */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_next_proto_neg)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_NPN_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
# endif

EXT_RETURN tls_construct_ctos_alpn_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx)
{
    s->s3->alpn_sent = 0;

    if (s->ext.alpn == NULL || !SSL_IS_FIRST_HANDSHAKE(s))
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt,
                TLSEXT_TYPE_application_layer_protocol_negotiation)
               /* Sub-packet ALPN extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u16(pkt, s->ext.alpn, s->ext.alpn_len)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_ALPN_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    s->s3->alpn_sent = 1;

    return EXT_RETURN_SENT;
}


# ifndef OPENSSL_NO_SRTP
EXT_RETURN tls_construct_ctos_use_srtp_ntls(SSL *s, WPACKET *pkt,
                                       unsigned int context, X509 *x,
                                       size_t chainidx)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt = SSL_get_srtp_profiles(s);
    int i, end;

    if (clnt == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_use_srtp)
               /* Sub-packet for SRTP extension */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* Sub-packet for the protection profile list */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_USE_SRTP_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    end = sk_SRTP_PROTECTION_PROFILE_num(clnt);
    for (i = 0; i < end; i++) {
        const SRTP_PROTECTION_PROFILE *prof =
            sk_SRTP_PROTECTION_PROFILE_value(clnt, i);

        if (prof == NULL || !WPACKET_put_bytes_u16(pkt, prof->id)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CTOS_USE_SRTP_NTLS, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }
    if (!WPACKET_close(pkt)
               /* Add an empty use_mki value */
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_USE_SRTP_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
# endif

EXT_RETURN tls_construct_ctos_etm_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    /* No encrypt-then-MAC */
    return EXT_RETURN_NOT_SENT;
}

# ifndef OPENSSL_NO_CT
EXT_RETURN tls_construct_ctos_sct_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ct_validation_callback == NULL)
        return EXT_RETURN_NOT_SENT;

    /* Not defined for client Certificates */
    if (x != NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_signed_certificate_timestamp)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_SCT_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
# endif

EXT_RETURN tls_construct_ctos_ems_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    /* No extended_master_secret */
    return EXT_RETURN_NOT_SENT;
}

EXT_RETURN tls_construct_ctos_supported_versions_ntls(SSL *s, WPACKET *pkt,
                                                 unsigned int context, X509 *x,
                                                 size_t chainidx)
{
    /* No supported_versions */
    return EXT_RETURN_NOT_SENT;
}

/*
 * Construct a psk_kex_modes extension.
 */
EXT_RETURN tls_construct_ctos_psk_kex_modes_ntls(SSL *s, WPACKET *pkt,
                                            unsigned int context, X509 *x,
                                            size_t chainidx)
{
# ifndef OPENSSL_NO_TLS1_3
    int nodhe = s->options & SSL_OP_ALLOW_NO_DHE_KEX;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_psk_kex_modes)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u8(pkt)
            || !WPACKET_put_bytes_u8(pkt, TLSEXT_KEX_MODE_KE_DHE)
            || (nodhe && !WPACKET_put_bytes_u8(pkt, TLSEXT_KEX_MODE_KE))
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_CTOS_PSK_KEX_MODES_NTLS, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    s->ext.psk_kex_mode = TLSEXT_KEX_MODE_FLAG_KE_DHE;
    if (nodhe)
        s->ext.psk_kex_mode |= TLSEXT_KEX_MODE_FLAG_KE;
# endif

    return EXT_RETURN_SENT;
}

# ifndef OPENSSL_NO_TLS1_3
static int add_key_share(SSL *s, WPACKET *pkt, unsigned int curve_id)
{
    unsigned char *encoded_point = NULL;
    EVP_PKEY *key_share_key = NULL;
    size_t encodedlen;

    if (s->s3->tmp.pkey != NULL) {
        if (!ossl_assert(s->hello_retry_request == SSL_HRR_PENDING)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_ADD_KEY_SHARE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        /*
         * Could happen if we got an HRR that wasn't requesting a new key_share
         */
        key_share_key = s->s3->tmp.pkey;
    } else {
        key_share_key = ssl_generate_pkey_group(s, curve_id);
        if (key_share_key == NULL) {
            /* SSLfatal_ntls() already called */
            return 0;
        }
    }

    /* Encode the public key. */
    encodedlen = EVP_PKEY_get1_tls_encodedpoint(key_share_key,
                                                &encoded_point);
    if (encodedlen == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_ADD_KEY_SHARE, ERR_R_EC_LIB);
        goto err;
    }

    /* Create KeyShareEntry */
    if (!WPACKET_put_bytes_u16(pkt, curve_id)
            || !WPACKET_sub_memcpy_u16(pkt, encoded_point, encodedlen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_ADD_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * TODO(TLS1.3): When changing to send more than one key_share we're
     * going to need to be able to save more than one EVP_PKEY. For now
     * we reuse the existing tmp.pkey
     */
    s->s3->tmp.pkey = key_share_key;
    s->s3->group_id = curve_id;
    OPENSSL_free(encoded_point);

    return 1;
 err:
    if (s->s3->tmp.pkey == NULL)
        EVP_PKEY_free(key_share_key);
    OPENSSL_free(encoded_point);
    return 0;
}
# endif

EXT_RETURN tls_construct_ctos_key_share_ntls(SSL *s, WPACKET *pkt,
                                        unsigned int context, X509 *x,
                                        size_t chainidx)
{
# ifndef OPENSSL_NO_TLS1_3
    size_t i, num_groups = 0;
    const uint16_t *pgroups = NULL;
    uint16_t curve_id = 0;

    /* key_share extension */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_key_share)
               /* Extension data sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* KeyShare list sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    tls1_get_supported_groups(s, &pgroups, &num_groups);

    /*
     * TODO(TLS1.3): Make the number of key_shares sent configurable. For
     * now, just send one
     */
    if (s->s3->group_id != 0) {
        curve_id = s->s3->group_id;
    } else {
        for (i = 0; i < num_groups; i++) {

            if (!tls_curve_allowed(s, pgroups[i], SSL_SECOP_CURVE_SUPPORTED))
                continue;

            curve_id = pgroups[i];
            break;
        }
    }

    if (curve_id == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE_NTLS,
                 SSL_R_NO_SUITABLE_KEY_SHARE);
        return EXT_RETURN_FAIL;
    }

    if (!add_key_share(s, pkt, curve_id)) {
        /* SSLfatal_ntls() already called */
        return EXT_RETURN_FAIL;
    }

    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    return EXT_RETURN_SENT;
# else
    return EXT_RETURN_NOT_SENT;
# endif
}

EXT_RETURN tls_construct_ctos_cookie_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                     X509 *x, size_t chainidx)
{
    EXT_RETURN ret = EXT_RETURN_FAIL;

    /* Should only be set if we've had an HRR */
    if (s->ext.tls13_cookie_len == 0)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_cookie)
               /* Extension data sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u16(pkt, s->ext.tls13_cookie,
                                       s->ext.tls13_cookie_len)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_COOKIE_NTLS,
                 ERR_R_INTERNAL_ERROR);
        goto end;
    }

    ret = EXT_RETURN_SENT;
 end:
    OPENSSL_free(s->ext.tls13_cookie);
    s->ext.tls13_cookie = NULL;
    s->ext.tls13_cookie_len = 0;

    return ret;
}

EXT_RETURN tls_construct_ctos_early_data_ntls(SSL *s, WPACKET *pkt,
                                         unsigned int context, X509 *x,
                                         size_t chainidx)
{
    const unsigned char *id = NULL;
    size_t idlen = 0;
    SSL_SESSION *psksess = NULL;
    SSL_SESSION *edsess = NULL;
    const EVP_MD *handmd = NULL;

    if (s->hello_retry_request == SSL_HRR_PENDING)
        handmd = ssl_handshake_md(s);

    if (s->psk_use_session_cb != NULL
            && (!s->psk_use_session_cb(s, handmd, &id, &idlen, &psksess)
                || (psksess != NULL
                    && psksess->ssl_version != TLS1_3_VERSION))) {
        SSL_SESSION_free(psksess);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_EARLY_DATA_NTLS,
                 SSL_R_BAD_PSK);
        return EXT_RETURN_FAIL;
    }

    SSL_SESSION_free(s->psksession);
    s->psksession = psksess;
    if (psksess != NULL) {
        OPENSSL_free(s->psksession_id);
        s->psksession_id = OPENSSL_memdup(id, idlen);
        if (s->psksession_id == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CTOS_EARLY_DATA_NTLS, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        s->psksession_id_len = idlen;
    }

    if (s->early_data_state != SSL_EARLY_DATA_CONNECTING
            || (s->session->ext.max_early_data == 0
                && (psksess == NULL || psksess->ext.max_early_data == 0))) {
        s->max_early_data = 0;
        return EXT_RETURN_NOT_SENT;
    }
    edsess = s->session->ext.max_early_data != 0 ? s->session : psksess;
    s->max_early_data = edsess->ext.max_early_data;

    if (edsess->ext.hostname != NULL) {
        if (s->ext.hostname == NULL
                || (s->ext.hostname != NULL
                    && strcmp(s->ext.hostname, edsess->ext.hostname) != 0)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CTOS_EARLY_DATA_NTLS,
                     SSL_R_INCONSISTENT_EARLY_DATA_SNI);
            return EXT_RETURN_FAIL;
        }
    }

    if ((s->ext.alpn == NULL && edsess->ext.alpn_selected != NULL)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_EARLY_DATA_NTLS,
                 SSL_R_INCONSISTENT_EARLY_DATA_ALPN);
        return EXT_RETURN_FAIL;
    }

    /*
     * Verify that we are offering an ALPN protocol consistent with the early
     * data.
     */
    if (edsess->ext.alpn_selected != NULL) {
        PACKET prots, alpnpkt;
        int found = 0;

        if (!PACKET_buf_init(&prots, s->ext.alpn, s->ext.alpn_len)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CTOS_EARLY_DATA_NTLS, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        while (PACKET_get_length_prefixed_1(&prots, &alpnpkt)) {
            if (PACKET_equal(&alpnpkt, edsess->ext.alpn_selected,
                             edsess->ext.alpn_selected_len)) {
                found = 1;
                break;
            }
        }
        if (!found) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CTOS_EARLY_DATA_NTLS,
                     SSL_R_INCONSISTENT_EARLY_DATA_ALPN);
            return EXT_RETURN_FAIL;
        }
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_early_data)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_EARLY_DATA_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /*
     * We set this to rejected here. Later, if the server acknowledges the
     * extension, we set it to accepted.
     */
    s->ext.early_data = SSL_EARLY_DATA_REJECTED;
    s->ext.early_data_ok = 1;

    return EXT_RETURN_SENT;
}

# define F5_WORKAROUND_MIN_MSG_LEN   0xff
# define F5_WORKAROUND_MAX_MSG_LEN   0x200

/*
 * PSK pre binder overhead =
 *  2 bytes for TLSEXT_TYPE_psk
 *  2 bytes for extension length
 *  2 bytes for identities list length
 *  2 bytes for identity length
 *  4 bytes for obfuscated_ticket_age
 *  2 bytes for binder list length
 *  1 byte for binder length
 * The above excludes the number of bytes for the identity itself and the
 * subsequent binder bytes
 */
# define PSK_PRE_BINDER_OVERHEAD (2 + 2 + 2 + 2 + 4 + 2 + 1)

EXT_RETURN tls_construct_ctos_padding_ntls(SSL *s, WPACKET *pkt,
                                      unsigned int context, X509 *x,
                                      size_t chainidx)
{
    unsigned char *padbytes;
    size_t hlen;

    if ((s->options & SSL_OP_TLSEXT_PADDING) == 0)
        return EXT_RETURN_NOT_SENT;

    /*
     * Add padding to workaround bugs in F5 terminators. See RFC7685.
     * This code calculates the length of all extensions added so far but
     * excludes the PSK extension (because that MUST be written last). Therefore
     * this extension MUST always appear second to last.
     */
    if (!WPACKET_get_total_written(pkt, &hlen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_PADDING_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /*
     * If we're going to send a PSK then that will be written out after this
     * extension, so we need to calculate how long it is going to be.
     */
    if (s->session->ssl_version == TLS1_3_VERSION
            && s->session->ext.ticklen != 0
            && s->session->cipher != NULL) {
        const EVP_MD *md = ssl_md(s->session->cipher->algorithm2);

        if (md != NULL) {
            /*
             * Add the fixed PSK overhead, the identity length and the binder
             * length.
             */
            hlen +=  PSK_PRE_BINDER_OVERHEAD + s->session->ext.ticklen
                     + EVP_MD_size(md);
        }
    }

    if (hlen > F5_WORKAROUND_MIN_MSG_LEN && hlen < F5_WORKAROUND_MAX_MSG_LEN) {
        /* Calculate the amount of padding we need to add */
        hlen = F5_WORKAROUND_MAX_MSG_LEN - hlen;

        /*
         * Take off the size of extension header itself (2 bytes for type and
         * 2 bytes for length bytes), but ensure that the extension is at least
         * 1 byte long so as not to have an empty extension last (WebSphere 7.x,
         * 8.x are intolerant of that condition)
         */
        if (hlen > 4)
            hlen -= 4;
        else
            hlen = 1;

        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_padding)
                || !WPACKET_sub_allocate_bytes_u16(pkt, hlen, &padbytes)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_PADDING_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        memset(padbytes, 0, hlen);
    }

    return EXT_RETURN_SENT;
}

/*
 * Construct the pre_shared_key extension
 */
EXT_RETURN tls_construct_ctos_psk_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
# ifndef OPENSSL_NO_TLS1_3
    uint32_t now, agesec, agems = 0;
    size_t reshashsize = 0, pskhashsize = 0, binderoffset, msglen;
    unsigned char *resbinder = NULL, *pskbinder = NULL, *msgstart = NULL;
    const EVP_MD *handmd = NULL, *mdres = NULL, *mdpsk = NULL;
    int dores = 0;

    s->ext.tick_identity = 0;

    /*
     * Note: At this stage of the code we only support adding a single
     * resumption PSK. If we add support for multiple PSKs then the length
     * calculations in the padding extension will need to be adjusted.
     */

    /*
     * If this is an incompatible or new session then we have nothing to resume
     * so don't add this extension.
     */
    if (s->session->ssl_version != TLS1_3_VERSION
            || (s->session->ext.ticklen == 0 && s->psksession == NULL))
        return EXT_RETURN_NOT_SENT;

    if (s->hello_retry_request == SSL_HRR_PENDING)
        handmd = ssl_handshake_md(s);

    if (s->session->ext.ticklen != 0) {
        /* Get the digest associated with the ciphersuite in the session */
        if (s->session->cipher == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_PSK_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        mdres = ssl_md(s->session->cipher->algorithm2);
        if (mdres == NULL) {
            /*
             * Don't recognize this cipher so we can't use the session.
             * Ignore it
             */
            goto dopsksess;
        }

        if (s->hello_retry_request == SSL_HRR_PENDING && mdres != handmd) {
            /*
             * Selected ciphersuite hash does not match the hash for the session
             * so we can't use it.
             */
            goto dopsksess;
        }

        /*
         * Technically the C standard just says time() returns a time_t and says
         * nothing about the encoding of that type. In practice most
         * implementations follow POSIX which holds it as an integral type in
         * seconds since epoch. We've already made the assumption that we can do
         * this in multiple places in the code, so portability shouldn't be an
         * issue.
         */
        now = (uint32_t)time(NULL);
        agesec = now - (uint32_t)s->session->time;
        /*
         * We calculate the age in seconds but the server may work in ms. Due to
         * rounding errors we could overestimate the age by up to 1s. It is
         * better to underestimate it. Otherwise, if the RTT is very short, when
         * the server calculates the age reported by the client it could be
         * bigger than the age calculated on the server - which should never
         * happen.
         */
        if (agesec > 0)
            agesec--;

        if (s->session->ext.tick_lifetime_hint < agesec) {
            /* Ticket is too old. Ignore it. */
            goto dopsksess;
        }

        /*
         * Calculate age in ms. We're just doing it to nearest second. Should be
         * good enough.
         */
        agems = agesec * (uint32_t)1000;

        if (agesec != 0 && agems / (uint32_t)1000 != agesec) {
            /*
             * Overflow. Shouldn't happen unless this is a *really* old session.
             * If so we just ignore it.
             */
            goto dopsksess;
        }

        /*
         * Obfuscate the age. Overflow here is fine, this addition is supposed
         * to be mod 2^32.
         */
        agems += s->session->ext.tick_age_add;

        reshashsize = EVP_MD_size(mdres);
        s->ext.tick_identity++;
        dores = 1;
    }

 dopsksess:
    if (!dores && s->psksession == NULL)
        return EXT_RETURN_NOT_SENT;

    if (s->psksession != NULL) {
        mdpsk = ssl_md(s->psksession->cipher->algorithm2);
        if (mdpsk == NULL) {
            /*
             * Don't recognize this cipher so we can't use the session.
             * If this happens it's an application bug.
             */
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_PSK_NTLS,
                     SSL_R_BAD_PSK);
            return EXT_RETURN_FAIL;
        }

        if (s->hello_retry_request == SSL_HRR_PENDING && mdpsk != handmd) {
            /*
             * Selected ciphersuite hash does not match the hash for the PSK
             * session. This is an application bug.
             */
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_PSK_NTLS,
                     SSL_R_BAD_PSK);
            return EXT_RETURN_FAIL;
        }

        pskhashsize = EVP_MD_size(mdpsk);
    }

    /* Create the extension, but skip over the binder for now */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_psk)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_PSK_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    if (dores) {
        if (!WPACKET_sub_memcpy_u16(pkt, s->session->ext.tick,
                                           s->session->ext.ticklen)
                || !WPACKET_put_bytes_u32(pkt, agems)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_PSK_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }

    if (s->psksession != NULL) {
        if (!WPACKET_sub_memcpy_u16(pkt, s->psksession_id,
                                    s->psksession_id_len)
                || !WPACKET_put_bytes_u32(pkt, 0)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_PSK_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        s->ext.tick_identity++;
    }

    if (!WPACKET_close(pkt)
            || !WPACKET_get_total_written(pkt, &binderoffset)
            || !WPACKET_start_sub_packet_u16(pkt)
            || (dores
                && !WPACKET_sub_allocate_bytes_u8(pkt, reshashsize, &resbinder))
            || (s->psksession != NULL
                && !WPACKET_sub_allocate_bytes_u8(pkt, pskhashsize, &pskbinder))
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)
            || !WPACKET_get_total_written(pkt, &msglen)
               /*
                * We need to fill in all the sub-packet lengths now so we can
                * calculate the HMAC of the message up to the binders
                */
            || !WPACKET_fill_lengths(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CTOS_PSK_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    msgstart = WPACKET_get_curr(pkt) - msglen;

    if (dores
            && tls_psk_do_binder_ntls(s, mdres, msgstart, binderoffset, NULL,
                                 resbinder, s->session, 1, 0) != 1) {
        /* SSLfatal_ntls() already called */
        return EXT_RETURN_FAIL;
    }

    if (s->psksession != NULL
            && tls_psk_do_binder_ntls(s, mdpsk, msgstart, binderoffset, NULL,
                                 pskbinder, s->psksession, 1, 1) != 1) {
        /* SSLfatal_ntls() already called */
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
# else
    return EXT_RETURN_NOT_SENT;
# endif
}

EXT_RETURN tls_construct_ctos_post_handshake_auth_ntls(SSL *s, WPACKET *pkt,
                                                  unsigned int context,
                                                  X509 *x, size_t chainidx)
{
# ifndef OPENSSL_NO_TLS1_3
    if (!s->pha_enabled)
        return EXT_RETURN_NOT_SENT;

    /* construct extension - 0 length, no contents */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_post_handshake_auth)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_CTOS_POST_HANDSHAKE_AUTH_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    s->post_handshake_auth = SSL_PHA_EXT_SENT;

    return EXT_RETURN_SENT;
# else
    return EXT_RETURN_NOT_SENT;
# endif
}

/* Parse the server's max fragment len extension packet */
int tls_parse_stoc_maxfragmentlen_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    unsigned int value;

    if (PACKET_remaining(pkt) != 1 || !PACKET_get_1(pkt, &value)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_MAXFRAGMENTLEN_NTLS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* |value| should contains a valid max-fragment-length code. */
    if (!IS_MAX_FRAGMENT_LENGTH_EXT_VALID(value)) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_F_TLS_PARSE_STOC_MAXFRAGMENTLEN_NTLS,
                 SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /* Must be the same value as client-configured one who was sent to server */
    /*-
     * RFC 6066: if a client receives a maximum fragment length negotiation
     * response that differs from the length it requested, ...
     * It must abort with SSL_AD_ILLEGAL_PARAMETER alert
     */
    if (value != s->ext.max_fragment_len_mode) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_F_TLS_PARSE_STOC_MAXFRAGMENTLEN_NTLS,
                 SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /*
     * Maximum Fragment Length Negotiation succeeded.
     * The negotiated Maximum Fragment Length is binding now.
     */
    s->session->ext.max_fragment_len_mode = value;

    return 1;
}

int tls_parse_stoc_server_name_ntls(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    if (s->ext.hostname == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_SERVER_NAME_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (PACKET_remaining(pkt) > 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_SERVER_NAME_NTLS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!s->hit) {
        if (s->session->ext.hostname != NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_SERVER_NAME_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->session->ext.hostname = OPENSSL_strdup(s->ext.hostname);
        if (s->session->ext.hostname == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_SERVER_NAME_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

# ifndef OPENSSL_NO_EC
int tls_parse_stoc_ec_pt_formats_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx)
{
    /* Ignore ec_point_formats */
    return 1;
}
# endif

int tls_parse_stoc_session_ticket_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ext.session_ticket_cb != NULL &&
        !s->ext.session_ticket_cb(s, PACKET_data(pkt),
                              PACKET_remaining(pkt),
                              s->ext.session_ticket_cb_arg)) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                 SSL_F_TLS_PARSE_STOC_SESSION_TICKET_NTLS, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tls_use_ticket(s)) {
        SSLfatal_ntls(s, SSL_AD_UNSUPPORTED_EXTENSION,
                 SSL_F_TLS_PARSE_STOC_SESSION_TICKET_NTLS, SSL_R_BAD_EXTENSION);
        return 0;
    }
    if (PACKET_remaining(pkt) > 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_STOC_SESSION_TICKET_NTLS, SSL_R_BAD_EXTENSION);
        return 0;
    }

    s->ext.ticket_expected = 1;

    return 1;
}

# ifndef OPENSSL_NO_OCSP
int tls_parse_stoc_status_request_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        /* We ignore this if the server sends a CertificateRequest */
        /* TODO(TLS1.3): Add support for this */
        return 1;
    }

    /*
     * MUST only be sent if we've requested a status
     * request message. In TLS <= 1.2 it must also be empty.
     */
    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp) {
        SSLfatal_ntls(s, SSL_AD_UNSUPPORTED_EXTENSION,
                 SSL_F_TLS_PARSE_STOC_STATUS_REQUEST_NTLS, SSL_R_BAD_EXTENSION);
        return 0;
    }
    if (PACKET_remaining(pkt) > 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_STOC_STATUS_REQUEST_NTLS, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* Set flag to expect CertificateStatus message */
    s->ext.status_expected = 1;

    return 1;
}
# endif


# ifndef OPENSSL_NO_CT
int tls_parse_stoc_sct_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        /* We ignore this if the server sends it in a CertificateRequest */
        /* TODO(TLS1.3): Add support for this */
        return 1;
    }

    /*
     * Only take it if we asked for it - i.e if there is no CT validation
     * callback set, then a custom extension MAY be processing it, so we
     * need to let control continue to flow to that.
     */
    if (s->ct_validation_callback != NULL) {
        size_t size = PACKET_remaining(pkt);

        /* Simply copy it off for later processing */
        OPENSSL_free(s->ext.scts);
        s->ext.scts = NULL;

        s->ext.scts_len = (uint16_t)size;
        if (size > 0) {
            s->ext.scts = OPENSSL_malloc(size);
            if (s->ext.scts == NULL
                    || !PACKET_copy_bytes(pkt, s->ext.scts, size)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_SCT_NTLS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    } else {
        ENDPOINT role = (context & SSL_EXT_TLS1_2_SERVER_HELLO) != 0
                        ? ENDPOINT_CLIENT : ENDPOINT_BOTH;

        /*
         * If we didn't ask for it then there must be a custom extension,
         * otherwise this is unsolicited.
         */
        if (custom_ext_find_ntls(&s->cert->custext, role,
                            TLSEXT_TYPE_signed_certificate_timestamp,
                            NULL) == NULL) {
            SSLfatal_ntls(s, TLS1_AD_UNSUPPORTED_EXTENSION, SSL_F_TLS_PARSE_STOC_SCT_NTLS,
                     SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (!custom_ext_parse_ntls(s, context,
                             TLSEXT_TYPE_signed_certificate_timestamp,
                             PACKET_data(pkt), PACKET_remaining(pkt),
                             x, chainidx)) {
            /* SSLfatal_ntls already called */
            return 0;
        }
    }

    return 1;
}
# endif


# ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * ssl_next_proto_validate validates a Next Protocol Negotiation block. No
 * elements of zero length are allowed and the set of elements must exactly
 * fill the length of the block. Returns 1 on success or 0 on failure.
 */
static int ssl_next_proto_validate(SSL *s, PACKET *pkt)
{
    PACKET tmp_protocol;

    while (PACKET_remaining(pkt)) {
        if (!PACKET_get_length_prefixed_1(pkt, &tmp_protocol)
            || PACKET_remaining(&tmp_protocol) == 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_SSL_NEXT_PROTO_VALIDATE,
                     SSL_R_BAD_EXTENSION);
            return 0;
        }
    }

    return 1;
}

int tls_parse_stoc_npn_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    unsigned char *selected;
    unsigned char selected_len;
    PACKET tmppkt;

    /* Check if we are in a renegotiation. If so ignore this extension */
    if (!SSL_IS_FIRST_HANDSHAKE(s))
        return 1;

    /* We must have requested it. */
    if (s->ctx->ext.npn_select_cb == NULL) {
        SSLfatal_ntls(s, SSL_AD_UNSUPPORTED_EXTENSION, SSL_F_TLS_PARSE_STOC_NPN_NTLS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* The data must be valid */
    tmppkt = *pkt;
    if (!ssl_next_proto_validate(s, &tmppkt)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }
    if (s->ctx->ext.npn_select_cb(s, &selected, &selected_len,
                                  PACKET_data(pkt),
                                  PACKET_remaining(pkt),
                                  s->ctx->ext.npn_select_cb_arg) !=
             SSL_TLSEXT_ERR_OK) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_TLS_PARSE_STOC_NPN_NTLS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * Could be non-NULL if server has sent multiple NPN extensions in
     * a single Serverhello
     */
    OPENSSL_free(s->ext.npn);
    s->ext.npn = OPENSSL_malloc(selected_len);
    if (s->ext.npn == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_NPN_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(s->ext.npn, selected, selected_len);
    s->ext.npn_len = selected_len;
    s->s3->npn_seen = 1;

    return 1;
}
# endif

int tls_parse_stoc_alpn_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                        size_t chainidx)
{
    size_t len;

    /* We must have requested it. */
    if (!s->s3->alpn_sent) {
        SSLfatal_ntls(s, SSL_AD_UNSUPPORTED_EXTENSION, SSL_F_TLS_PARSE_STOC_ALPN_NTLS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }
    /*-
     * The extension data consists of:
     *   uint16 list_length
     *   uint8 proto_length;
     *   uint8 proto[proto_length];
     */
    if (!PACKET_get_net_2_len(pkt, &len)
        || PACKET_remaining(pkt) != len || !PACKET_get_1_len(pkt, &len)
        || PACKET_remaining(pkt) != len) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_ALPN_NTLS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }
    OPENSSL_free(s->s3->alpn_selected);
    s->s3->alpn_selected = OPENSSL_malloc(len);
    if (s->s3->alpn_selected == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_ALPN_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!PACKET_copy_bytes(pkt, s->s3->alpn_selected, len)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_ALPN_NTLS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }
    s->s3->alpn_selected_len = len;

    if (s->session->ext.alpn_selected == NULL
            || s->session->ext.alpn_selected_len != len
            || memcmp(s->session->ext.alpn_selected, s->s3->alpn_selected, len)
               != 0) {
        /* ALPN not consistent with the old session so cannot use early_data */
        s->ext.early_data_ok = 0;
    }
    if (!s->hit) {
        /*
         * This is a new session and so alpn_selected should have been
         * initialised to NULL. We should update it with the selected ALPN.
         */
        if (!ossl_assert(s->session->ext.alpn_selected == NULL)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_ALPN_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->session->ext.alpn_selected =
            OPENSSL_memdup(s->s3->alpn_selected, s->s3->alpn_selected_len);
        if (s->session->ext.alpn_selected == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_ALPN_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->session->ext.alpn_selected_len = s->s3->alpn_selected_len;
    }

    return 1;
}

# ifndef OPENSSL_NO_SRTP
int tls_parse_stoc_use_srtp_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx)
{
    unsigned int id, ct, mki;
    int i;
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt;
    SRTP_PROTECTION_PROFILE *prof;

    if (!PACKET_get_net_2(pkt, &ct) || ct != 2
            || !PACKET_get_net_2(pkt, &id)
            || !PACKET_get_1(pkt, &mki)
            || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_USE_SRTP_NTLS,
                 SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        return 0;
    }

    if (mki != 0) {
        /* Must be no MKI, since we never offer one */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_STOC_USE_SRTP_NTLS,
                 SSL_R_BAD_SRTP_MKI_VALUE);
        return 0;
    }

    /* Throw an error if the server gave us an unsolicited extension */
    clnt = SSL_get_srtp_profiles(s);
    if (clnt == NULL) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_USE_SRTP_NTLS,
                 SSL_R_NO_SRTP_PROFILES);
        return 0;
    }

    /*
     * Check to see if the server gave us something we support (and
     * presumably offered)
     */
    for (i = 0; i < sk_SRTP_PROTECTION_PROFILE_num(clnt); i++) {
        prof = sk_SRTP_PROTECTION_PROFILE_value(clnt, i);

        if (prof->id == id) {
            s->srtp_profile = prof;
            return 1;
        }
    }

    SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_USE_SRTP_NTLS,
             SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
    return 0;
}
# endif

int tls_parse_stoc_etm_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /* Ignore encrypt-then-MAC */
    return 1;
}

int tls_parse_stoc_ems_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /* Ignore extended_master_secret */
    return 1;
}

int tls_parse_stoc_supported_versions_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                      X509 *x, size_t chainidx)
{
    /* Ignore supported_versions */
    return 1;
}

int tls_parse_stoc_key_share_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                             size_t chainidx)
{
# ifndef OPENSSL_NO_TLS1_3
    unsigned int group_id;
    PACKET encoded_pt;
    EVP_PKEY *ckey = s->s3->tmp.pkey, *skey = NULL;

    /* Sanity check */
    if (ckey == NULL || s->s3->peer_tmp != NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_KEY_SHARE_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_net_2(pkt, &group_id)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_KEY_SHARE_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if ((context & SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST) != 0) {
        const uint16_t *pgroups = NULL;
        size_t i, num_groups;

        if (PACKET_remaining(pkt) != 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_KEY_SHARE_NTLS,
                     SSL_R_LENGTH_MISMATCH);
            return 0;
        }

        /*
         * It is an error if the HelloRetryRequest wants a key_share that we
         * already sent in the first ClientHello
         */
        if (group_id == s->s3->group_id) {
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_PARSE_STOC_KEY_SHARE_NTLS, SSL_R_BAD_KEY_SHARE);
            return 0;
        }

        /* Validate the selected group is one we support */
        tls1_get_supported_groups(s, &pgroups, &num_groups);
        for (i = 0; i < num_groups; i++) {
            if (group_id == pgroups[i])
                break;
        }
        if (i >= num_groups
                || !tls_curve_allowed(s, group_id, SSL_SECOP_CURVE_SUPPORTED)) {
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_PARSE_STOC_KEY_SHARE_NTLS, SSL_R_BAD_KEY_SHARE);
            return 0;
        }

        s->s3->group_id = group_id;
        EVP_PKEY_free(s->s3->tmp.pkey);
        s->s3->tmp.pkey = NULL;
        return 1;
    }

    if (group_id != s->s3->group_id) {
        /*
         * This isn't for the group that we sent in the original
         * key_share!
         */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_STOC_KEY_SHARE_NTLS,
                 SSL_R_BAD_KEY_SHARE);
        return 0;
    }

    if (!PACKET_as_length_prefixed_2(pkt, &encoded_pt)
            || PACKET_remaining(&encoded_pt) == 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_KEY_SHARE_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    skey = EVP_PKEY_new();
    if (skey == NULL || EVP_PKEY_copy_parameters(skey, ckey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_KEY_SHARE_NTLS,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!EVP_PKEY_set1_tls_encodedpoint(skey, PACKET_data(&encoded_pt),
                                        PACKET_remaining(&encoded_pt))) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_STOC_KEY_SHARE_NTLS,
                 SSL_R_BAD_ECPOINT);
        EVP_PKEY_free(skey);
        return 0;
    }

    if (ssl_derive(s, ckey, skey, 1) == 0) {
        /* SSLfatal_ntls() already called */
        EVP_PKEY_free(skey);
        return 0;
    }
    s->s3->peer_tmp = skey;
# endif

    return 1;
}

int tls_parse_stoc_cookie_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    PACKET cookie;

    if (!PACKET_as_length_prefixed_2(pkt, &cookie)
            || !PACKET_memdup(&cookie, &s->ext.tls13_cookie,
                              &s->ext.tls13_cookie_len)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_COOKIE_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    return 1;
}

int tls_parse_stoc_early_data_ntls(SSL *s, PACKET *pkt, unsigned int context,
                              X509 *x, size_t chainidx)
{
    if (context == SSL_EXT_TLS1_3_NEW_SESSION_TICKET) {
        unsigned long max_early_data;

        if (!PACKET_get_net_4(pkt, &max_early_data)
                || PACKET_remaining(pkt) != 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_EARLY_DATA_NTLS,
                     SSL_R_INVALID_MAX_EARLY_DATA);
            return 0;
        }

        s->session->ext.max_early_data = max_early_data;

        return 1;
    }

    if (PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_EARLY_DATA_NTLS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!s->ext.early_data_ok
            || !s->hit) {
        /*
         * If we get here then we didn't send early data, or we didn't resume
         * using the first identity, or the SNI/ALPN is not consistent so the
         * server should not be accepting it.
         */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_STOC_EARLY_DATA_NTLS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    s->ext.early_data = SSL_EARLY_DATA_ACCEPTED;

    return 1;
}

int tls_parse_stoc_psk_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
# ifndef OPENSSL_NO_TLS1_3
    unsigned int identity;

    if (!PACKET_get_net_2(pkt, &identity) || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_STOC_PSK_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (identity >= (unsigned int)s->ext.tick_identity) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_STOC_PSK_NTLS,
                 SSL_R_BAD_PSK_IDENTITY);
        return 0;
    }

    /*
     * Session resumption tickets are always sent before PSK tickets. If the
     * ticket index is 0 then it must be for a session resumption ticket if we
     * sent two tickets, or if we didn't send a PSK ticket.
     */
    if (identity == 0 && (s->psksession == NULL || s->ext.tick_identity == 2)) {
        s->hit = 1;
        SSL_SESSION_free(s->psksession);
        s->psksession = NULL;
        return 1;
    }

    if (s->psksession == NULL) {
        /* Should never happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_STOC_PSK_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If we used the external PSK for sending early_data then s->early_secret
     * is already set up, so don't overwrite it. Otherwise we copy the
     * early_secret across that we generated earlier.
     */
    if ((s->early_data_state != SSL_EARLY_DATA_WRITE_RETRY
                && s->early_data_state != SSL_EARLY_DATA_FINISHED_WRITING)
            || s->session->ext.max_early_data > 0
            || s->psksession->ext.max_early_data == 0)
        memcpy(s->early_secret, s->psksession->early_secret, EVP_MAX_MD_SIZE);

    SSL_SESSION_free(s->session);
    s->session = s->psksession;
    s->psksession = NULL;
    s->hit = 1;
    /* Early data is only allowed if we used the first ticket */
    if (identity != 0)
        s->ext.early_data_ok = 0;
# endif

    return 1;
}

#endif
