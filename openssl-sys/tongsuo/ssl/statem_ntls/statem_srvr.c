/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

#include <stdio.h>
#include "ssl_local_ntls.h"
#include "statem_local_ntls.h"
#include "internal/constant_time.h"
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/md5.h>

#ifndef OPENSSL_NO_NTLS

# define TICKET_NONCE_SIZE       8

static int tls_construct_encrypted_extensions(SSL *s, WPACKET *pkt);

/*
 * ossl_statem_server_read_transition_ntls() encapsulates the logic for the allowed
 * handshake state transitions when the server is reading messages from the
 * client. The message type that the client has sent is provided in |mt|. The
 * current state is in |s->statem.hand_state|.
 *
 * Return values are 1 for success (transition allowed) and  0 on error
 * (transition not allowed)
 */
int ossl_statem_server_read_transition_ntls(SSL *s, int mt)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        break;

    case TLS_ST_BEFORE:
    case TLS_ST_OK:
        if (mt == SSL3_MT_CLIENT_HELLO) {
            st->hand_state = TLS_ST_SR_CLNT_HELLO;
            return 1;
        }
        break;

    case TLS_ST_SW_SRVR_DONE:
        /*
         * If we get a CKE message after a ServerDone then either
         * 1) We didn't request a Certificate
         * OR
         * 2) If we did request one then
         *      a) We allow no Certificate to be returned
         *      AND
         *      b) We are running SSL3 (in TLS1.0+ the client must return a 0
         *         list if we requested a certificate)
         */
        if (mt == SSL3_MT_CLIENT_KEY_EXCHANGE) {
            if (s->s3->tmp.cert_request) {
                if (s->version == SSL3_VERSION) {
                    if ((s->verify_mode & SSL_VERIFY_PEER)
                        && (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
                        /*
                         * This isn't an unexpected message as such - we're just
                         * not going to accept it because we require a client
                         * cert.
                         */
                        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                                 SSL_F_OSSL_STATEM_SERVER_READ_TRANSITION_NTLS,
                                 SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
                        return 0;
                    }
                    st->hand_state = TLS_ST_SR_KEY_EXCH;
                    return 1;
                }
            } else {
                st->hand_state = TLS_ST_SR_KEY_EXCH;
                return 1;
            }
        } else if (s->s3->tmp.cert_request) {
            if (mt == SSL3_MT_CERTIFICATE) {
                st->hand_state = TLS_ST_SR_CERT;
                return 1;
            }
        }
        break;

    case TLS_ST_SR_CERT:
        if (mt == SSL3_MT_CLIENT_KEY_EXCHANGE) {
            st->hand_state = TLS_ST_SR_KEY_EXCH;
            return 1;
        }
        break;

    case TLS_ST_SR_KEY_EXCH:
        /*
         * We should only process a CertificateVerify message if we have
         * received a Certificate from the client. If so then |s->session->peer|
         * will be non NULL. In some instances a CertificateVerify message is
         * not required even if the peer has sent a Certificate (e.g. such as in
         * the case of static DH). In that case |st->no_cert_verify| should be
         * set.
         */
        if (s->session->peer == NULL || st->no_cert_verify) {
            if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
                /*
                 * For the ECDH ciphersuites when the client sends its ECDH
                 * pub key in a certificate, the CertificateVerify message is
                 * not sent. Also for GOST ciphersuites when the client uses
                 * its key from the certificate for key exchange.
                 */
                st->hand_state = TLS_ST_SR_CHANGE;
                return 1;
            }
        } else {
            if (mt == SSL3_MT_CERTIFICATE_VERIFY) {
                st->hand_state = TLS_ST_SR_CERT_VRFY;
                return 1;
            }
        }
        break;

    case TLS_ST_SR_CERT_VRFY:
        if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_SR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_SR_CHANGE:
# ifndef OPENSSL_NO_NEXTPROTONEG
        if (s->s3->npn_seen) {
            if (mt == SSL3_MT_NEXT_PROTO) {
                st->hand_state = TLS_ST_SR_NEXT_PROTO;
                return 1;
            }
        } else {
# endif
            if (mt == SSL3_MT_FINISHED) {
                st->hand_state = TLS_ST_SR_FINISHED;
                return 1;
            }
# ifndef OPENSSL_NO_NEXTPROTONEG
        }
# endif
        break;

# ifndef OPENSSL_NO_NEXTPROTONEG
    case TLS_ST_SR_NEXT_PROTO:
        if (mt == SSL3_MT_FINISHED) {
            st->hand_state = TLS_ST_SR_FINISHED;
            return 1;
        }
        break;
# endif

    case TLS_ST_SW_FINISHED:
        if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_SR_CHANGE;
            return 1;
        }
        break;
    }

    /* No valid transition found */
    SSLfatal_ntls(s, SSL3_AD_UNEXPECTED_MESSAGE,
             SSL_F_OSSL_STATEM_SERVER_READ_TRANSITION_NTLS,
             SSL_R_UNEXPECTED_MESSAGE);
    return 0;
}

/*
 * Should we send a ServerKeyExchange message?
 *
 * Valid return values are:
 *   1: Yes
 *   0: No
 */
static int send_server_key_exchange(SSL *s)
{
    return 1;
}

/*
 * Should we send a CertificateRequest message?
 *
 * Valid return values are:
 *   1: Yes
 *   0: No
 */
int send_certificate_request_ntls(SSL *s)
{
    if (
           /* don't request cert unless asked for it: */
           s->verify_mode & SSL_VERIFY_PEER
           /*
            * if SSL_VERIFY_CLIENT_ONCE is set, don't request cert
            * a second time:
            */
           && (s->certreqs_sent < 1 ||
               !(s->verify_mode & SSL_VERIFY_CLIENT_ONCE))
           /*
            * never request cert in anonymous ciphersuites (see
            * section "Certificate request" in SSL 3 drafts and in
            * RFC 2246):
            */
           && (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)
               /*
                * ... except when the application insists on
                * verification (against the specs, but statem_clnt.c accepts
                * this for SSL 3)
                */
               || (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))
           /* don't request certificate for SRP auth */
           && !(s->s3->tmp.new_cipher->algorithm_auth & SSL_aSRP)
           /*
            * With normal PSK Certificates and Certificate Requests
            * are omitted
            */
           && !(s->s3->tmp.new_cipher->algorithm_auth & SSL_aPSK)) {
        return 1;
    }

    return 0;
}

/*
 * ossl_statem_server_write_transition_ntls() works out what handshake state to move
 * to next when the server is writing messages to be sent to the client.
 */
WRITE_TRAN ossl_statem_server_write_transition_ntls(SSL *s)
{
    OSSL_STATEM *st = &s->statem;

    /*
     * Note that before the ClientHello we don't know what version we are going
     * to negotiate yet, so we don't take this branch until later
     */

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_OSSL_STATEM_SERVER_WRITE_TRANSITION_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return WRITE_TRAN_ERROR;

    case TLS_ST_OK:
        if (st->request_state == TLS_ST_SW_HELLO_REQ) {
            /* We must be trying to renegotiate */
            st->hand_state = TLS_ST_SW_HELLO_REQ;
            st->request_state = TLS_ST_BEFORE;
            return WRITE_TRAN_CONTINUE;
        }
        /* Must be an incoming ClientHello */
        if (!tls_setup_handshake_ntls(s)) {
            /* SSLfatal_ntls() already called */
            return WRITE_TRAN_ERROR;
        }
        /* Fall through */

    case TLS_ST_BEFORE:
        /* Just go straight to trying to read from the client */
        return WRITE_TRAN_FINISHED;

    case TLS_ST_SW_HELLO_REQ:
        st->hand_state = TLS_ST_OK;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_SR_CLNT_HELLO:
        if (s->renegotiate == 0 && !SSL_IS_FIRST_HANDSHAKE(s)) {
            /* We must have rejected the renegotiation */
            st->hand_state = TLS_ST_OK;
            return WRITE_TRAN_CONTINUE;
        } else {
            st->hand_state = TLS_ST_SW_SRVR_HELLO;
        }
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_SW_SRVR_HELLO:
        if (s->hit) {
            if (s->ext.ticket_expected)
                st->hand_state = TLS_ST_SW_SESSION_TICKET;
            else
                st->hand_state = TLS_ST_SW_CHANGE;
        } else {
            /* Check if it is anon DH or anon ECDH, */
            /* normal PSK or SRP */
            if (!(s->s3->tmp.new_cipher->algorithm_auth &
                  (SSL_aNULL | SSL_aSRP | SSL_aPSK))) {
                st->hand_state = TLS_ST_SW_CERT;
            } else if (send_server_key_exchange(s)) {
                st->hand_state = TLS_ST_SW_KEY_EXCH;
            } else if (send_certificate_request_ntls(s)) {
                st->hand_state = TLS_ST_SW_CERT_REQ;
            } else {
                st->hand_state = TLS_ST_SW_SRVR_DONE;
            }
        }
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_SW_CERT:
        if (s->ext.status_expected) {
            st->hand_state = TLS_ST_SW_CERT_STATUS;
            return WRITE_TRAN_CONTINUE;
        }
        /* Fall through */

    case TLS_ST_SW_CERT_STATUS:
        if (send_server_key_exchange(s)) {
            st->hand_state = TLS_ST_SW_KEY_EXCH;
            return WRITE_TRAN_CONTINUE;
        }
        /* Fall through */

    case TLS_ST_SW_KEY_EXCH:
        if (send_certificate_request_ntls(s)) {
            st->hand_state = TLS_ST_SW_CERT_REQ;
            return WRITE_TRAN_CONTINUE;
        }
        /* Fall through */

    case TLS_ST_SW_CERT_REQ:
        st->hand_state = TLS_ST_SW_SRVR_DONE;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_SW_SRVR_DONE:
        return WRITE_TRAN_FINISHED;

    case TLS_ST_SR_FINISHED:
        if (s->hit) {
            st->hand_state = TLS_ST_OK;
            return WRITE_TRAN_CONTINUE;
        } else if (s->ext.ticket_expected) {
            st->hand_state = TLS_ST_SW_SESSION_TICKET;
        } else {
            st->hand_state = TLS_ST_SW_CHANGE;
        }
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_SW_SESSION_TICKET:
        st->hand_state = TLS_ST_SW_CHANGE;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_SW_CHANGE:
        st->hand_state = TLS_ST_SW_FINISHED;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_SW_FINISHED:
        if (s->hit) {
            return WRITE_TRAN_FINISHED;
        }
        st->hand_state = TLS_ST_OK;
        return WRITE_TRAN_CONTINUE;
    }
}

/*
 * Perform any pre work that needs to be done prior to sending a message from
 * the server to the client.
 */
WORK_STATE ossl_statem_server_pre_work_ntls(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* No pre work to be done */
        break;

    case TLS_ST_SW_HELLO_REQ:
        s->shutdown = 0;
        break;

    case TLS_ST_SW_SRVR_HELLO:
        break;

    case TLS_ST_SW_SRVR_DONE:
        return WORK_FINISHED_CONTINUE;

    case TLS_ST_SW_SESSION_TICKET:
        break;

    case TLS_ST_SW_CHANGE:
        s->session->cipher = s->s3->tmp.new_cipher;
        if (!s->method->ssl3_enc->setup_key_block(s)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }
        return WORK_FINISHED_CONTINUE;

    case TLS_ST_EARLY_DATA:
        if (s->early_data_state != SSL_EARLY_DATA_ACCEPTING
                && (s->s3->flags & TLS1_FLAGS_STATELESS) == 0)
            return WORK_FINISHED_CONTINUE;
        /* Fall through */

    case TLS_ST_OK:
        /* Calls SSLfatal_ntls() as required */
        return tls_finish_handshake_ntls(s, wst, 1, 1);
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Perform any work that needs to be done after sending a message from the
 * server to the client.
 */
WORK_STATE ossl_statem_server_post_work_ntls(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    s->init_num = 0;

    switch (st->hand_state) {
    default:
        /* No post work to be done */
        break;

    case TLS_ST_SW_HELLO_REQ:
        if (statem_flush_ntls(s) != 1)
            return WORK_MORE_A;
        if (!ssl3_init_finished_mac(s)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }
        break;

    case TLS_ST_SW_SRVR_HELLO:
            break;
        /* Fall through */

    case TLS_ST_SW_CHANGE:
        if (s->hello_retry_request == SSL_HRR_PENDING) {
            if (!statem_flush_ntls(s))
                return WORK_MORE_A;
            break;
        }

        if (!s->method->ssl3_enc->change_cipher_state(s,
                                                      SSL3_CHANGE_CIPHER_SERVER_WRITE))
        {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }

        break;

    case TLS_ST_SW_SRVR_DONE:
        if (statem_flush_ntls(s) != 1)
            return WORK_MORE_A;
        break;

    case TLS_ST_SW_FINISHED:
        if (statem_flush_ntls(s) != 1)
            return WORK_MORE_A;
        break;

    case TLS_ST_SW_CERT_REQ:
        if (s->post_handshake_auth == SSL_PHA_REQUEST_PENDING) {
            if (statem_flush_ntls(s) != 1)
                return WORK_MORE_A;
        }
        break;

    case TLS_ST_SW_KEY_UPDATE:
        if (statem_flush_ntls(s) != 1)
            return WORK_MORE_A;
        if (!tls13_update_key(s, 1)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }
        break;

    case TLS_ST_SW_SESSION_TICKET:
        clear_sys_error();
        break;
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Get the message construction function and message type for sending from the
 * server
 *
 * Valid return values are:
 *   1: Success
 *   0: Error
 */
int ossl_statem_server_construct_message_ntls(SSL *s, WPACKET *pkt,
                                         confunc_f *confunc, int *mt)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_OSSL_STATEM_SERVER_CONSTRUCT_MESSAGE_NTLS,
                 SSL_R_BAD_HANDSHAKE_STATE);
        return 0;

    case TLS_ST_SW_CHANGE:
        *confunc = tls_construct_change_cipher_spec_ntls;
        *mt = SSL3_MT_CHANGE_CIPHER_SPEC;
        break;

    case TLS_ST_SW_HELLO_REQ:
        /* No construction function needed */
        *confunc = NULL;
        *mt = SSL3_MT_HELLO_REQUEST;
        break;

    case TLS_ST_SW_SRVR_HELLO:
        *confunc = tls_construct_server_hello_ntls;
        *mt = SSL3_MT_SERVER_HELLO;
        break;

    case TLS_ST_SW_CERT:
        *confunc = tls_construct_server_certificate_ntls;
        *mt = SSL3_MT_CERTIFICATE;
        break;


    case TLS_ST_SW_KEY_EXCH:
        *confunc = ntls_construct_server_key_exchange_ntls;
        *mt = SSL3_MT_SERVER_KEY_EXCHANGE;
        break;

    case TLS_ST_SW_CERT_REQ:
        *confunc = tls_construct_certificate_request_ntls;
        *mt = SSL3_MT_CERTIFICATE_REQUEST;
        break;

    case TLS_ST_SW_SRVR_DONE:
        *confunc = tls_construct_server_done_ntls;
        *mt = SSL3_MT_SERVER_DONE;
        break;

    case TLS_ST_SW_SESSION_TICKET:
        *confunc = tls_construct_new_session_ticket_ntls;
        *mt = SSL3_MT_NEWSESSION_TICKET;
        break;

    case TLS_ST_SW_CERT_STATUS:
        *confunc = tls_construct_cert_status_ntls;
        *mt = SSL3_MT_CERTIFICATE_STATUS;
        break;

    case TLS_ST_SW_FINISHED:
        *confunc = tls_construct_finished_ntls;
        *mt = SSL3_MT_FINISHED;
        break;

    case TLS_ST_EARLY_DATA:
        *confunc = NULL;
        *mt = SSL3_MT_DUMMY;
        break;

    case TLS_ST_SW_ENCRYPTED_EXTENSIONS:
        *confunc = tls_construct_encrypted_extensions;
        *mt = SSL3_MT_ENCRYPTED_EXTENSIONS;
        break;

    case TLS_ST_SW_KEY_UPDATE:
        *confunc = tls_construct_key_update_ntls;
        *mt = SSL3_MT_KEY_UPDATE;
        break;
    }

    return 1;
}

/*
 * Maximum size (excluding the Handshake header) of a ClientHello message,
 * calculated as follows:
 *
 *  2 + #  client_version
 *  32 + #  only valid length for random
 *  1 + #  length of session_id
 *  32 + #  maximum size for session_id
 *  2 + #  length of cipher suites
 *  2^16-2 + #  maximum length of cipher suites array
 *  1 + #  length of compression_methods
 *  2^8-1 + #  maximum length of compression methods
 *  2 + #  length of extensions
 *  2^16-1 #  maximum length of extensions
 */
# define CLIENT_HELLO_MAX_LENGTH         131396

# define CLIENT_KEY_EXCH_MAX_LENGTH      2048
# define NEXT_PROTO_MAX_LENGTH           514

/*
 * Returns the maximum allowed length for the current message that we are
 * reading. Excludes the message header.
 */
size_t ossl_statem_server_max_message_size_ntls(SSL *s)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        return 0;

    case TLS_ST_SR_CLNT_HELLO:
        return CLIENT_HELLO_MAX_LENGTH;

    case TLS_ST_SR_END_OF_EARLY_DATA:
        return END_OF_EARLY_DATA_MAX_LENGTH;

    case TLS_ST_SR_CERT:
        return s->max_cert_list;

    case TLS_ST_SR_KEY_EXCH:
        return CLIENT_KEY_EXCH_MAX_LENGTH;

    case TLS_ST_SR_CERT_VRFY:
        return SSL3_RT_MAX_PLAIN_LENGTH;

# ifndef OPENSSL_NO_NEXTPROTONEG
    case TLS_ST_SR_NEXT_PROTO:
        return NEXT_PROTO_MAX_LENGTH;
# endif

    case TLS_ST_SR_CHANGE:
        return CCS_MAX_LENGTH;

    case TLS_ST_SR_FINISHED:
        return FINISHED_MAX_LENGTH;

    case TLS_ST_SR_KEY_UPDATE:
        return KEY_UPDATE_MAX_LENGTH;
    }
}

/*
 * Process a message that the server has received from the client.
 */
MSG_PROCESS_RETURN ossl_statem_server_process_message_ntls(SSL *s, PACKET *pkt)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_OSSL_STATEM_SERVER_PROCESS_MESSAGE_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;

    case TLS_ST_SR_CLNT_HELLO:
        return tls_process_client_hello_ntls(s, pkt);

    case TLS_ST_SR_END_OF_EARLY_DATA:
        return tls_process_end_of_early_data_ntls(s, pkt);

    case TLS_ST_SR_CERT:
        return tls_process_client_certificate_ntls(s, pkt);

    case TLS_ST_SR_KEY_EXCH:
        return ntls_process_client_key_exchange_ntls(s, pkt);

    case TLS_ST_SR_CERT_VRFY:
        return ntls_process_cert_verify_ntls(s, pkt);

# ifndef OPENSSL_NO_NEXTPROTONEG
    case TLS_ST_SR_NEXT_PROTO:
        return tls_process_next_proto_ntls(s, pkt);
# endif

    case TLS_ST_SR_CHANGE:
        return tls_process_change_cipher_spec_ntls(s, pkt);

    case TLS_ST_SR_FINISHED:
        return tls_process_finished_ntls(s, pkt);

    case TLS_ST_SR_KEY_UPDATE:
        return tls_process_key_update_ntls(s, pkt);

    }
}

/*
 * Perform any further processing required following the receipt of a message
 * from the client
 */
WORK_STATE ossl_statem_server_post_process_message_ntls(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_OSSL_STATEM_SERVER_POST_PROCESS_MESSAGE_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return WORK_ERROR;

    case TLS_ST_SR_CLNT_HELLO:
        return tls_post_process_client_hello_ntls(s, wst);

    case TLS_ST_SR_KEY_EXCH:
        return tls_post_process_client_key_exchange_ntls(s, wst);
    }
}

# ifndef OPENSSL_NO_EC
/*-
 * ssl_check_for_safari attempts to fingerprint Safari using OS X
 * SecureTransport using the TLS extension block in |hello|.
 * Safari, since 10.6, sends exactly these extensions, in this order:
 *   SNI,
 *   elliptic_curves
 *   ec_point_formats
 *   signature_algorithms (for TLSv1.2 only)
 *
 * We wish to fingerprint Safari because they broke ECDHE-ECDSA support in 10.8,
 * but they advertise support. So enabling ECDHE-ECDSA ciphers breaks them.
 * Sadly we cannot differentiate 10.6, 10.7 and 10.8.4 (which work), from
 * 10.8..10.8.3 (which don't work).
 */
static void ssl_check_for_safari(SSL *s, const CLIENTHELLO_MSG *hello)
{
    static const unsigned char kSafariExtensionsBlock[] = {
        0x00, 0x0a,             /* elliptic_curves extension */
        0x00, 0x08,             /* 8 bytes */
        0x00, 0x06,             /* 6 bytes of curve ids */
        0x00, 0x17,             /* P-256 */
        0x00, 0x18,             /* P-384 */
        0x00, 0x19,             /* P-521 */

        0x00, 0x0b,             /* ec_point_formats */
        0x00, 0x02,             /* 2 bytes */
        0x01,                   /* 1 point format */
        0x00,                   /* uncompressed */
        /* The following is only present in TLS 1.2 */
        0x00, 0x0d,             /* signature_algorithms */
        0x00, 0x0c,             /* 12 bytes */
        0x00, 0x0a,             /* 10 bytes */
        0x05, 0x01,             /* SHA-384/RSA */
        0x04, 0x01,             /* SHA-256/RSA */
        0x02, 0x01,             /* SHA-1/RSA */
        0x04, 0x03,             /* SHA-256/ECDSA */
        0x02, 0x03,             /* SHA-1/ECDSA */
    };
    /* Length of the common prefix (first two extensions). */
    static const size_t kSafariCommonExtensionsLength = 18;
    unsigned int type;
    PACKET sni, tmppkt;
    size_t ext_len;

    tmppkt = hello->extensions;

    if (!PACKET_forward(&tmppkt, 2)
        || !PACKET_get_net_2(&tmppkt, &type)
        || !PACKET_get_length_prefixed_2(&tmppkt, &sni)) {
        return;
    }

    if (type != TLSEXT_TYPE_server_name)
        return;

    ext_len = TLS1_get_client_version(s) >= TLS1_2_VERSION ?
        sizeof(kSafariExtensionsBlock) : kSafariCommonExtensionsLength;

    s->s3->is_probably_safari = PACKET_equal(&tmppkt, kSafariExtensionsBlock,
                                             ext_len);
}
# endif                          /* !OPENSSL_NO_EC */

MSG_PROCESS_RETURN tls_process_client_hello_ntls(SSL *s, PACKET *pkt)
{
    PACKET session_id, compression, extensions, cookie;
    static const unsigned char null_compression = 0;
    CLIENTHELLO_MSG *clienthello = NULL;

    /* Check if this is actually an unexpected renegotiation ClientHello */
    if (s->renegotiate == 0 && !SSL_IS_FIRST_HANDSHAKE(s)) {
        if ((s->options & SSL_OP_NO_RENEGOTIATION) != 0
                || (!s->s3->send_connection_binding
                    && (s->options
                        & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION) == 0)) {
            ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_NO_RENEGOTIATION);
            return MSG_PROCESS_FINISHED_READING;
        }
        s->renegotiate = 1;
        s->new_session = 1;
    }

    clienthello = OPENSSL_zalloc(sizeof(*clienthello));
    if (clienthello == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * First, parse the raw ClientHello data into the CLIENTHELLO_MSG structure.
     */
    clienthello->isv2 = RECORD_LAYER_is_sslv2_record(&s->rlayer);
    PACKET_null_init(&cookie);

    if (clienthello->isv2) {
        unsigned int mt;

        if (!SSL_IS_FIRST_HANDSHAKE(s)
                || s->hello_retry_request != SSL_HRR_NONE) {
            SSLfatal_ntls(s, SSL_AD_UNEXPECTED_MESSAGE,
                     SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS, SSL_R_UNEXPECTED_MESSAGE);
            goto err;
        }

        /*-
         * An SSLv3/TLSv1 backwards-compatible CLIENT-HELLO in an SSLv2
         * header is sent directly on the wire, not wrapped as a TLS
         * record. Our record layer just processes the message length and passes
         * the rest right through. Its format is:
         * Byte  Content
         * 0-1   msg_length - decoded by the record layer
         * 2     msg_type - s->init_msg points here
         * 3-4   version
         * 5-6   cipher_spec_length
         * 7-8   session_id_length
         * 9-10  challenge_length
         * ...   ...
         */

        if (!PACKET_get_1(pkt, &mt)
            || mt != SSL2_MT_CLIENT_HELLO) {
            /*
             * Should never happen. We should have tested this in the record
             * layer in order to have determined that this is a SSLv2 record
             * in the first place
             */
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (!PACKET_get_net_2(pkt, &clienthello->legacy_version)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                 SSL_R_LENGTH_TOO_SHORT);
        goto err;
    }

    /* Parse the message and load client random. */
    if (clienthello->isv2) {
        /*
         * Handle an SSLv2 backwards compatible ClientHello
         * Note, this is only for SSLv3+ using the backward compatible format.
         * Real SSLv2 is not supported, and is rejected below.
         */
        unsigned int ciphersuite_len, session_id_len, challenge_len;
        PACKET challenge;

        if (!PACKET_get_net_2(pkt, &ciphersuite_len)
            || !PACKET_get_net_2(pkt, &session_id_len)
            || !PACKET_get_net_2(pkt, &challenge_len)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                     SSL_R_RECORD_LENGTH_MISMATCH);
            goto err;
        }

        if (session_id_len > SSL_MAX_SSL_SESSION_ID_LENGTH) {
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS, SSL_R_LENGTH_MISMATCH);
            goto err;
        }

        if (!PACKET_get_sub_packet(pkt, &clienthello->ciphersuites,
                                   ciphersuite_len)
            || !PACKET_copy_bytes(pkt, clienthello->session_id, session_id_len)
            || !PACKET_get_sub_packet(pkt, &challenge, challenge_len)
            /* No extensions. */
            || PACKET_remaining(pkt) != 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                     SSL_R_RECORD_LENGTH_MISMATCH);
            goto err;
        }
        clienthello->session_id_len = session_id_len;

        /* Load the client random and compression list. We use SSL3_RANDOM_SIZE
         * here rather than sizeof(clienthello->random) because that is the limit
         * for SSLv3 and it is fixed. It won't change even if
         * sizeof(clienthello->random) does.
         */
        challenge_len = challenge_len > SSL3_RANDOM_SIZE
                        ? SSL3_RANDOM_SIZE : challenge_len;
        memset(clienthello->random, 0, SSL3_RANDOM_SIZE);
        if (!PACKET_copy_bytes(&challenge,
                               clienthello->random + SSL3_RANDOM_SIZE -
                               challenge_len, challenge_len)
            /* Advertise only null compression. */
            || !PACKET_buf_init(&compression, &null_compression, 1)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

        PACKET_null_init(&clienthello->extensions);
    } else {
        /* Regular ClientHello. */
        if (!PACKET_copy_bytes(pkt, clienthello->random, SSL3_RANDOM_SIZE)
            || !PACKET_get_length_prefixed_1(pkt, &session_id)
            || !PACKET_copy_all(&session_id, clienthello->session_id,
                    SSL_MAX_SSL_SESSION_ID_LENGTH,
                    &clienthello->session_id_len)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                     SSL_R_LENGTH_MISMATCH);
            goto err;
        }

        if (!PACKET_get_length_prefixed_2(pkt, &clienthello->ciphersuites)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                     SSL_R_LENGTH_MISMATCH);
            goto err;
        }

        if (!PACKET_get_length_prefixed_1(pkt, &compression)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                     SSL_R_LENGTH_MISMATCH);
            goto err;
        }

        /* Could be empty. */
        if (PACKET_remaining(pkt) == 0) {
            PACKET_null_init(&clienthello->extensions);
        } else {
            if (!PACKET_get_length_prefixed_2(pkt, &clienthello->extensions)
                    || PACKET_remaining(pkt) != 0) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                         SSL_R_LENGTH_MISMATCH);
                goto err;
            }
        }
    }

    if (!PACKET_copy_all(&compression, clienthello->compressions,
                         MAX_COMPRESSIONS_SIZE,
                         &clienthello->compressions_len)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Preserve the raw extensions PACKET for later use */
    extensions = clienthello->extensions;
    if (!tls_collect_extensions_ntls(s, &extensions, SSL_EXT_CLIENT_HELLO,
                                &clienthello->pre_proc_exts,
                                &clienthello->pre_proc_exts_len, 1)) {
        /* SSLfatal_ntls already been called */
        goto err;
    }
    s->clienthello = clienthello;

    return MSG_PROCESS_CONTINUE_PROCESSING;

 err:
    if (clienthello != NULL)
        OPENSSL_free(clienthello->pre_proc_exts);
    OPENSSL_free(clienthello);

    return MSG_PROCESS_ERROR;
}

static int tls_early_post_process_client_hello(SSL *s)
{
    unsigned int j;
    int i, al = SSL_AD_INTERNAL_ERROR;
    int protverr;
    size_t loop;
    unsigned long id;

    const SSL_CIPHER *c;
    STACK_OF(SSL_CIPHER) *ciphers = NULL;
    STACK_OF(SSL_CIPHER) *scsvs = NULL;
    CLIENTHELLO_MSG *clienthello = s->clienthello;
    DOWNGRADE dgrd = DOWNGRADE_NONE;

    /* Finished parsing the ClientHello, now we can start processing it */
    /* Give the ClientHello callback a crack at things */
    if (s->ctx->client_hello_cb != NULL) {
        /* A failure in the ClientHello callback terminates the connection. */
        switch (s->ctx->client_hello_cb(s, &al, s->ctx->client_hello_cb_arg)) {
        case SSL_CLIENT_HELLO_SUCCESS:
            break;
        case SSL_CLIENT_HELLO_RETRY:
            s->rwstate = SSL_CLIENT_HELLO_CB;
            return -1;
        case SSL_CLIENT_HELLO_ERROR:
        default:
            SSLfatal_ntls(s, al,
                     SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                     SSL_R_CALLBACK_FAILED);
            goto err;
        }
    }

    /* Set up the client_random */
    memcpy(s->s3->client_random, clienthello->random, SSL3_RANDOM_SIZE);

    /* Choose the version */

    if (clienthello->isv2) {
        if (clienthello->legacy_version == NTLS_VERSION) {
            /* do nothing */
        } else if (clienthello->legacy_version == SSL2_VERSION
                || (clienthello->legacy_version & 0xff00)
                   != (SSL3_VERSION_MAJOR << 8)) {
            /*
             * This is real SSLv2 or something completely unknown. We don't
             * support it.
             */
            SSLfatal_ntls(s, SSL_AD_PROTOCOL_VERSION,
                     SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                     SSL_R_UNKNOWN_PROTOCOL);
            goto err;
        }
        /* SSLv3/TLS */
        s->client_version = clienthello->legacy_version;
    }
    /*
     * Do SSL/TLS version negotiation if applicable. Version negotiation comes later.
     */
    protverr = ssl_choose_server_version_ntls(s, clienthello, &dgrd);

    if (protverr) {
        if (SSL_IS_FIRST_HANDSHAKE(s)) {
            /* like ssl3_get_record, send alert using remote version number */
            s->version = s->client_version = clienthello->legacy_version;
        }
        SSLfatal_ntls(s, SSL_AD_PROTOCOL_VERSION,
                 SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO, protverr);
        goto err;
    }

    s->hit = 0;

    if (!ssl_cache_cipherlist(s, &clienthello->ciphersuites,
                              clienthello->isv2) ||
        !bytes_to_cipher_list(s, &clienthello->ciphersuites, &ciphers, &scsvs,
                              clienthello->isv2, 1)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    s->s3->send_connection_binding = 0;
    /* Check what signalling cipher-suite values were received. */
    if (scsvs != NULL) {
        for(i = 0; i < sk_SSL_CIPHER_num(scsvs); i++) {
            c = sk_SSL_CIPHER_value(scsvs, i);
            if (SSL_CIPHER_get_id(c) == SSL3_CK_SCSV) {
                if (s->renegotiate) {
                    /* SCSV is fatal if renegotiating */
                    SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                             SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                             SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING);
                    goto err;
                }
                s->s3->send_connection_binding = 1;
            } else if (SSL_CIPHER_get_id(c) == SSL3_CK_FALLBACK_SCSV &&
                       !ssl_check_version_downgrade_ntls(s)) {
                /*
                 * This SCSV indicates that the client previously tried
                 * a higher version.  We should fail if the current version
                 * is an unexpected downgrade, as that indicates that the first
                 * connection may have been tampered with in order to trigger
                 * an insecure downgrade.
                 */
                SSLfatal_ntls(s, SSL_AD_INAPPROPRIATE_FALLBACK,
                         SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                         SSL_R_INAPPROPRIATE_FALLBACK);
                goto err;
            }
        }
    }

    /*
     * We don't allow resumption in a backwards compatible ClientHello.
     * TODO(openssl-team): in TLS1.1+, session_id MUST be empty.
     *
     * Versions before 0.9.7 always allow clients to resume sessions in
     * renegotiation. 0.9.7 and later allow this by default, but optionally
     * ignore resumption requests with flag
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION (it's a new flag rather
     * than a change to default behavior so that applications relying on
     * this for security won't even compile against older library versions).
     * 1.0.1 and later also have a function SSL_renegotiate_abbreviated() to
     * request renegotiation but not a new session (s->new_session remains
     * unset): for servers, this essentially just means that the
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION setting will be
     * ignored.
     */
    if (clienthello->isv2 ||
        (s->new_session &&
         (s->options & SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION))) {
        if (!ssl_get_new_session(s, 1)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else {
        i = ssl_get_prev_session(s, clienthello);
        if (i == 1) {
            /* previous session */
            s->hit = 1;
        } else if (i == -1) {
            /* SSLfatal_ntls() already called */
            goto err;
        } else {
            /* i == 0 */
            if (!ssl_get_new_session(s, 1)) {
                /* SSLfatal_ntls() already called */
                goto err;
            }
        }
    }



    /*
     * If it is a hit, check that the cipher is in the list. In TLSv1.3 we check
     * ciphersuite compatibility with the session as part of resumption.
     */
    if (s->hit) {
        j = 0;
        id = s->session->cipher->id;

# ifdef CIPHER_DEBUG
        fprintf(stderr, "client sent %d ciphers\n", sk_SSL_CIPHER_num(ciphers));
# endif
        for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
            c = sk_SSL_CIPHER_value(ciphers, i);
# ifdef CIPHER_DEBUG
            fprintf(stderr, "client [%2d of %2d]:%s\n",
                    i, sk_SSL_CIPHER_num(ciphers), SSL_CIPHER_get_name(c));
# endif
            if (c->id == id) {
                j = 1;
                break;
            }
        }
        if (j == 0) {
            /*
             * we need to have the cipher in the cipher list if we are asked
             * to reuse it
             */
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                     SSL_R_REQUIRED_CIPHER_MISSING);
            goto err;
        }
    }

    for (loop = 0; loop < clienthello->compressions_len; loop++) {
        if (clienthello->compressions[loop] == 0)
            break;
    }

    if (loop >= clienthello->compressions_len) {
        /* no compress */
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                 SSL_R_NO_COMPRESSION_SPECIFIED);
        goto err;
    }

# ifndef OPENSSL_NO_EC
    if (s->options & SSL_OP_SAFARI_ECDHE_ECDSA_BUG)
        ssl_check_for_safari(s, clienthello);
# endif                          /* !OPENSSL_NO_EC */

    /* TLS extensions */
    if (!tls_parse_all_extensions_ntls(s, SSL_EXT_CLIENT_HELLO,
                                  clienthello->pre_proc_exts, NULL, 0, 1)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    /*
     * Check if we want to use external pre-shared secret for this handshake
     * for not reused session only. We need to generate server_random before
     * calling tls_session_secret_cb in order to allow SessionTicket
     * processing to use it in key derivation.
     */
    {
        unsigned char *pos;
        pos = s->s3->server_random;
        if (ssl_fill_hello_random(s, 1, pos, SSL3_RANDOM_SIZE, dgrd) <= 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (!s->hit
            && s->version >= TLS1_VERSION
            && s->ext.session_secret_cb) {
        const SSL_CIPHER *pref_cipher = NULL;
        /*
         * s->session->master_key_length is a size_t, but this is an int for
         * backwards compat reasons
         */
        int master_key_length;

        master_key_length = sizeof(s->session->master_key);
        if (s->ext.session_secret_cb(s, s->session->master_key,
                                     &master_key_length, ciphers,
                                     &pref_cipher,
                                     s->ext.session_secret_cb_arg)
                && master_key_length > 0) {
            s->session->master_key_length = master_key_length;
            s->hit = 1;
            s->peer_ciphers = ciphers;
            s->session->verify_result = X509_V_OK;

            ciphers = NULL;

            /* check if some cipher was preferred by call back */
            if (pref_cipher == NULL)
                pref_cipher = ssl3_choose_cipher(s, s->peer_ciphers,
                                                 SSL_get_ciphers(s));
            if (pref_cipher == NULL) {
                SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                         SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                         SSL_R_NO_SHARED_CIPHER);
                goto err;
            }

            s->session->cipher = pref_cipher;
            sk_SSL_CIPHER_free(s->cipher_list);
            s->cipher_list = sk_SSL_CIPHER_dup(s->peer_ciphers);
            sk_SSL_CIPHER_free(s->cipher_list_by_id);
            s->cipher_list_by_id = sk_SSL_CIPHER_dup(s->peer_ciphers);
        }
    }

    /*
     * Worst case, we will use the NULL compression, but if we have other
     * options, we will now look for them.  We have complen-1 compression
     * algorithms from the client, starting at q.
     */
    s->s3->tmp.new_compression = NULL;

    /*
     * If compression is disabled we'd better not try to resume a session
     * using compression.
     */
    if (s->session->compress_meth != 0) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                 SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                 SSL_R_INCONSISTENT_COMPRESSION);
        goto err;
    }


    /*
     * Given s->peer_ciphers and SSL_get_ciphers, we must pick a cipher
     */

    if (!s->hit) {
        sk_SSL_CIPHER_free(s->peer_ciphers);
        s->peer_ciphers = ciphers;
        if (ciphers == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ciphers = NULL;
    }

    if (!s->hit) {
        s->session->compress_meth = 0;
    }

    sk_SSL_CIPHER_free(ciphers);
    sk_SSL_CIPHER_free(scsvs);
    OPENSSL_free(clienthello->pre_proc_exts);
    OPENSSL_free(s->clienthello);
    s->clienthello = NULL;
    return 1;
 err:
    sk_SSL_CIPHER_free(ciphers);
    sk_SSL_CIPHER_free(scsvs);
    OPENSSL_free(clienthello->pre_proc_exts);
    OPENSSL_free(s->clienthello);
    s->clienthello = NULL;

    return 0;
}

/*
 * Call the status request callback if needed. Upon success, returns 1.
 * Upon failure, returns 0.
 */
static int tls_handle_status_request(SSL *s)
{
    s->ext.status_expected = 0;

    /*
     * If status request then ask callback what to do. Note: this must be
     * called after servername callbacks in case the certificate has changed,
     * and must be called after the cipher has been chosen because this may
     * influence which certificate is sent
     */
    if (s->ext.status_type != TLSEXT_STATUSTYPE_nothing && s->ctx != NULL
            && s->ctx->ext.status_cb != NULL) {
        int ret;

        /* If no certificate can't return certificate status */
        if (s->s3->tmp.cert != NULL) {
            /*
             * Set current certificate to one we will use so SSL_get_certificate
             * et al can pick it up.
             */
            s->cert->key = s->s3->tmp.cert;
            ret = s->ctx->ext.status_cb(s, s->ctx->ext.status_arg);
            switch (ret) {
                /* We don't want to send a status request response */
            case SSL_TLSEXT_ERR_NOACK:
                s->ext.status_expected = 0;
                break;
                /* status request response should be sent */
            case SSL_TLSEXT_ERR_OK:
                if (s->ext.ocsp.resp)
                    s->ext.status_expected = 1;
                break;
                /* something bad happened */
            case SSL_TLSEXT_ERR_ALERT_FATAL:
            default:
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_HANDLE_STATUS_REQUEST,
                         SSL_R_CLIENTHELLO_TLSEXT);
                return 0;
            }
        }
    }

    return 1;
}

/*
 * Call the alpn_select callback if needed. Upon success, returns 1.
 * Upon failure, returns 0.
 */
int tls_handle_alpn_ntls(SSL *s)
{
    const unsigned char *selected = NULL;
    unsigned char selected_len = 0;

    if (s->ctx->ext.alpn_select_cb != NULL && s->s3->alpn_proposed != NULL) {
        int r = s->ctx->ext.alpn_select_cb(s, &selected, &selected_len,
                                           s->s3->alpn_proposed,
                                           (unsigned int)s->s3->alpn_proposed_len,
                                           s->ctx->ext.alpn_select_cb_arg);

        if (r == SSL_TLSEXT_ERR_OK) {
            OPENSSL_free(s->s3->alpn_selected);
            s->s3->alpn_selected = OPENSSL_memdup(selected, selected_len);
            if (s->s3->alpn_selected == NULL) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_HANDLE_ALPN_NTLS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            s->s3->alpn_selected_len = selected_len;
# ifndef OPENSSL_NO_NEXTPROTONEG
            /* ALPN takes precedence over NPN. */
            s->s3->npn_seen = 0;
# endif

            /* Check ALPN is consistent with session */
            if (s->session->ext.alpn_selected == NULL
                        || selected_len != s->session->ext.alpn_selected_len
                        || memcmp(selected, s->session->ext.alpn_selected,
                                  selected_len) != 0) {
                /* Not consistent so can't be used for early_data */
                s->ext.early_data_ok = 0;

                if (!s->hit) {
                    /*
                     * This is a new session and so alpn_selected should have
                     * been initialised to NULL. We should update it with the
                     * selected ALPN.
                     */
                    if (!ossl_assert(s->session->ext.alpn_selected == NULL)) {
                        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                                 SSL_F_TLS_HANDLE_ALPN_NTLS,
                                 ERR_R_INTERNAL_ERROR);
                        return 0;
                    }
                    s->session->ext.alpn_selected = OPENSSL_memdup(selected,
                                                                   selected_len);
                    if (s->session->ext.alpn_selected == NULL) {
                        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                                 SSL_F_TLS_HANDLE_ALPN_NTLS,
                                 ERR_R_INTERNAL_ERROR);
                        return 0;
                    }
                    s->session->ext.alpn_selected_len = selected_len;
                }
            }

            return 1;
        } else if (r != SSL_TLSEXT_ERR_NOACK) {
            SSLfatal_ntls(s, SSL_AD_NO_APPLICATION_PROTOCOL, SSL_F_TLS_HANDLE_ALPN_NTLS,
                     SSL_R_NO_APPLICATION_PROTOCOL);
            return 0;
        }
        /*
         * If r == SSL_TLSEXT_ERR_NOACK then behave as if no callback was
         * present.
         */
    }

    /* Check ALPN is consistent with session */
    if (s->session->ext.alpn_selected != NULL) {
        /* Not consistent so can't be used for early_data */
        s->ext.early_data_ok = 0;
    }

    return 1;
}

WORK_STATE tls_post_process_client_hello_ntls(SSL *s, WORK_STATE wst)
{
    const SSL_CIPHER *cipher;

    if (wst == WORK_MORE_A) {
        int rv = tls_early_post_process_client_hello(s);
        if (rv == 0) {
            /* SSLfatal_ntls() was already called */
            goto err;
        }
        if (rv < 0)
            return WORK_MORE_A;
        wst = WORK_MORE_B;
    }
    if (wst == WORK_MORE_B) {
        if (!s->hit) {
            /* Let cert callback update server certificates if required */
            if (!s->hit && s->cert->cert_cb != NULL) {
                int rv = s->cert->cert_cb(s, s->cert->cert_cb_arg);
                if (rv == 0) {
                    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                             SSL_F_TLS_POST_PROCESS_CLIENT_HELLO_NTLS,
                             SSL_R_CERT_CB_ERROR);
                    goto err;
                }
                if (rv < 0) {
                    s->rwstate = SSL_X509_LOOKUP;
                    return WORK_MORE_B;
                }
                s->rwstate = SSL_NOTHING;
            }

            cipher =
                ssl3_choose_cipher(s, s->peer_ciphers, SSL_get_ciphers(s));

            if (cipher == NULL) {
                SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                            SSL_F_TLS_POST_PROCESS_CLIENT_HELLO_NTLS,
                            SSL_R_NO_SHARED_CIPHER);
                goto err;
            }
            s->s3->tmp.new_cipher = cipher;

            if (!s->hit) {
                if (!tls_choose_sigalg_ntls(s, 1)) {
                    /* SSLfatal_ntls already called */
                    goto err;
                }
                /* check whether we should disable session resumption */
                if (s->not_resumable_session_cb != NULL)
                    s->session->not_resumable =
                        s->not_resumable_session_cb(s,
                            ((s->s3->tmp.new_cipher->algorithm_mkey
                              & (SSL_kDHE | SSL_kECDHE)) != 0));
                if (s->session->not_resumable)
                    /* do not send a session ticket */
                    s->ext.ticket_expected = 0;
            }
        } else {
            /* Session-id reuse */
            s->s3->tmp.new_cipher = s->session->cipher;
        }

        if (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kSM2DHE)
            s->verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
                             | SSL_VERIFY_CLIENT_ONCE;

        /*-
         * we now have the following setup.
         * client_random
         * cipher_list          - our preferred list of ciphers
         * ciphers              - the clients preferred list of ciphers
         * compression          - basically ignored right now
         * ssl version is set   - sslv3
         * s->session           - The ssl session has been setup.
         * s->hit               - session reuse flag
         * s->s3->tmp.new_cipher- the new cipher to use.
         */

        /*
         * Call status_request callback if needed. Has to be done after the
         * certificate callbacks etc above.
         */
        if (!tls_handle_status_request(s)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
        /*
         * Call alpn_select callback if needed.  Has to be done after SNI and
         * cipher negotiation (HTTP/2 restricts permitted ciphers). In TLSv1.3
         * we already did this because cipher negotiation happens earlier, and
         * we must handle ALPN before we decide whether to accept early_data.
         */
        if (!tls_handle_alpn_ntls(s)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }

        wst = WORK_MORE_C;
    }

    return WORK_FINISHED_STOP;
 err:
    return WORK_ERROR;
}

int tls_construct_server_hello_ntls(SSL *s, WPACKET *pkt)
{
    int compm;
    size_t sl, len;
    int version;
    unsigned char *session_id;
    int usetls13 = s->hello_retry_request == SSL_HRR_PENDING;

    version = usetls13 ? TLS1_2_VERSION : s->version;
    if (!WPACKET_put_bytes_u16(pkt, version)
               /*
                * Random stuff. Filling of the server_random takes place in
                * tls_process_client_hello_ntls()
                */
            || !WPACKET_memcpy(pkt,
                               s->hello_retry_request == SSL_HRR_PENDING
                                   ? hrrrandom_ntls : s->s3->server_random,
                               SSL3_RANDOM_SIZE)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_SERVER_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*-
     * There are several cases for the session ID to send
     * back in the server hello:
     * - For session reuse from the session cache,
     *   we send back the old session ID.
     * - If stateless session reuse (using a session ticket)
     *   is successful, we send back the client's "session ID"
     *   (which doesn't actually identify the session).
     * - If it is a new session, we send back the new
     *   session ID.
     * - However, if we want the new session to be single-use,
     *   we send back a 0-length session ID.
     * - In TLSv1.3 we echo back the session id sent to us by the client
     *   regardless
     * s->hit is non-zero in either case of session reuse,
     * so the following won't overwrite an ID that we're supposed
     * to send back.
     */
    if (s->session->not_resumable ||
        (!(s->ctx->session_cache_mode & SSL_SESS_CACHE_SERVER)
         && !s->hit))
        s->session->session_id_length = 0;

    if (usetls13) {
        sl = s->tmp_session_id_len;
        session_id = s->tmp_session_id;
    } else {
        sl = s->session->session_id_length;
        session_id = s->session->session_id;
    }

    if (sl > sizeof(s->session->session_id)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_SERVER_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* set up the compression method */
    compm = 0;

    if (!WPACKET_sub_memcpy_u8(pkt, session_id, sl)
            || !s->method->put_cipher_by_char(s->s3->tmp.new_cipher, pkt, &len)
            || !WPACKET_put_bytes_u8(pkt, compm)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_SERVER_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tls_construct_extensions_ntls(s, pkt,
                                   s->hello_retry_request == SSL_HRR_PENDING
                                   ? SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST
                                   : SSL_EXT_TLS1_2_SERVER_HELLO,
                                   NULL, 0)) {
        /* SSLfatal() already called */
        return 0;
    }

    if (s->hello_retry_request == SSL_HRR_PENDING) {
        /* Ditch the session. We'll create a new one next time around */
        SSL_SESSION_free(s->session);
        s->session = NULL;
        s->hit = 0;

        /*
         * Re-initialise the Transcript Hash. We're going to prepopulate it with
         * a synthetic message_hash in place of ClientHello1.
         */
        if (!create_synthetic_message_hash_ntls(s, NULL, 0, NULL, 0)) {
            /* SSLfatal_ntls() already called */
            return 0;
        }
    } else if (!(s->verify_mode & SSL_VERIFY_PEER)
                && !ssl3_digest_cached_records(s, 0)) {
        /* SSLfatal_ntls() already called */;
        return 0;
    }

    return 1;
}

int tls_construct_server_done_ntls(SSL *s, WPACKET *pkt)
{
    if (!s->s3->tmp.cert_request) {
        if (!ssl3_digest_cached_records(s, 0)) {
            /* SSLfatal_ntls() already called */
            return 0;
        }
    }
    return 1;
}

int tls_construct_server_key_exchange_ntls(SSL *s, WPACKET *pkt)
{
# ifndef OPENSSL_NO_DH
    EVP_PKEY *pkdh = NULL;
# endif
# ifndef OPENSSL_NO_EC
    unsigned char *encodedPoint = NULL;
    size_t encodedlen = 0;
    int curve_id = 0;
# endif
    const SIGALG_LOOKUP *lu = s->s3->tmp.sigalg;
    int i;
    unsigned long type;
    const BIGNUM *r[4];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    size_t paramlen, paramoffset;

    if (!WPACKET_get_total_written(pkt, &paramoffset)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (md_ctx == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    type = s->s3->tmp.new_cipher->algorithm_mkey;

    r[0] = r[1] = r[2] = r[3] = NULL;
# ifndef OPENSSL_NO_DH
    if (type & (SSL_kDHE | SSL_kDHEPSK)) {
        CERT *cert = s->cert;

        EVP_PKEY *pkdhp = NULL;
        DH *dh;

        if (s->cert->dh_tmp_auto) {
            DH *dhp = ssl_get_auto_dh(s);
            pkdh = EVP_PKEY_new();
            if (pkdh == NULL || dhp == NULL) {
                DH_free(dhp);
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                         ERR_R_INTERNAL_ERROR);
                goto err;
            }
            EVP_PKEY_assign_DH(pkdh, dhp);
            pkdhp = pkdh;
        } else {
            pkdhp = cert->dh_tmp;
        }
        if ((pkdhp == NULL) && (s->cert->dh_tmp_cb != NULL)) {
            DH *dhp = s->cert->dh_tmp_cb(s, 0, 1024);
            pkdh = ssl_dh_to_pkey(dhp);
            if (pkdh == NULL) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                         ERR_R_INTERNAL_ERROR);
                goto err;
            }
            pkdhp = pkdh;
        }
        if (pkdhp == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     SSL_R_MISSING_TMP_DH_KEY);
            goto err;
        }
        if (!ssl_security(s, SSL_SECOP_TMP_DH,
                          EVP_PKEY_security_bits(pkdhp), 0, pkdhp)) {
            SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     SSL_R_DH_KEY_TOO_SMALL);
            goto err;
        }
        if (s->s3->tmp.pkey != NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

        s->s3->tmp.pkey = ssl_generate_pkey(pkdhp);
        if (s->s3->tmp.pkey == NULL) {
            /* SSLfatal_ntls() already called */
            goto err;
        }

        dh = EVP_PKEY_get0_DH(s->s3->tmp.pkey);
        if (dh == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

        EVP_PKEY_free(pkdh);
        pkdh = NULL;

        DH_get0_pqg(dh, &r[0], NULL, &r[1]);
        DH_get0_key(dh, &r[2], NULL);
    } else
# endif
# ifndef OPENSSL_NO_EC
    if (type & (SSL_kECDHE | SSL_kECDHEPSK)) {

        if (s->s3->tmp.pkey != NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

        /* Get NID of appropriate shared curve */
        curve_id = tls1_shared_group(s, -2);
        if (curve_id == 0) {
            SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     SSL_R_UNSUPPORTED_ELLIPTIC_CURVE);
            goto err;
        }
        s->s3->tmp.pkey = ssl_generate_pkey_group(s, curve_id);
        /* Generate a new key for this curve */
        if (s->s3->tmp.pkey == NULL) {
            /* SSLfatal_ntls() already called */
            goto err;
        }

        /* Encode the public key. */
        encodedlen = EVP_PKEY_get1_tls_encodedpoint(s->s3->tmp.pkey,
                                                    &encodedPoint);
        if (encodedlen == 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS, ERR_R_EC_LIB);
            goto err;
        }

        /*
         * We'll generate the serverKeyExchange message explicitly so we
         * can set these to NULLs
         */
        r[0] = NULL;
        r[1] = NULL;
        r[2] = NULL;
        r[3] = NULL;
    } else
# endif                          /* !OPENSSL_NO_EC */
    {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                 SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
        goto err;
    }

    if (((s->s3->tmp.new_cipher->algorithm_auth & (SSL_aNULL | SSL_aSRP)) != 0)
        || ((s->s3->tmp.new_cipher->algorithm_mkey & SSL_PSK)) != 0) {
        lu = NULL;
    } else if (lu == NULL) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    for (i = 0; i < 4 && r[i] != NULL; i++) {
        unsigned char *binval;
        int res;

        res = WPACKET_start_sub_packet_u16(pkt);

        if (!res) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

# ifndef OPENSSL_NO_DH
        /*-
         * for interoperability with some versions of the Microsoft TLS
         * stack, we need to zero pad the DHE pub key to the same length
         * as the prime
         */
        if ((i == 2) && (type & (SSL_kDHE | SSL_kDHEPSK))) {
            size_t len = BN_num_bytes(r[0]) - BN_num_bytes(r[2]);

            if (len > 0) {
                if (!WPACKET_allocate_bytes(pkt, len, &binval)) {
                    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                             SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                             ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                memset(binval, 0, len);
            }
        }
# endif
        if (!WPACKET_allocate_bytes(pkt, BN_num_bytes(r[i]), &binval)
                || !WPACKET_close(pkt)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

        BN_bn2bin(r[i], binval);
    }

# ifndef OPENSSL_NO_EC
    if (type & (SSL_kECDHE | SSL_kECDHEPSK)) {
        /*
         * We only support named (not generic) curves. In this situation, the
         * ServerKeyExchange message has: [1 byte CurveType], [2 byte CurveName]
         * [1 byte length of encoded point], followed by the actual encoded
         * point itself
         */
        if (!WPACKET_put_bytes_u8(pkt, NAMED_CURVE_TYPE)
                || !WPACKET_put_bytes_u8(pkt, 0)
                || !WPACKET_put_bytes_u8(pkt, curve_id)
                || !WPACKET_sub_memcpy_u8(pkt, encodedPoint, encodedlen)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
        OPENSSL_free(encodedPoint);
        encodedPoint = NULL;
    }
# endif

    /* not anonymous */
    if (lu != NULL) {
        EVP_PKEY *pkey;
        const EVP_MD *md;
        unsigned char *sigbytes1, *sigbytes2, *tbs;
        size_t siglen, tbslen;
        int rv;

        pkey = s->s3->tmp.cert->privatekey;

        if (pkey == NULL || !tls1_lookup_md(lu, &md)) {
            /* Should never happen */
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* Get length of the parameters we have written above */
        if (!WPACKET_get_length(pkt, &paramlen)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* send signature algorithm */
        if (SSL_USE_SIGALGS(s) && !WPACKET_put_bytes_u16(pkt, lu->sigalg)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /*
         * Create the signature. We don't know the actual length of the sig
         * until after we've created it, so we reserve enough bytes for it
         * up front, and then properly allocate them in the WPACKET
         * afterwards.
         */
        siglen = EVP_PKEY_size(pkey);

        if (!WPACKET_sub_reserve_bytes_u16(pkt, siglen, &sigbytes1)
            || EVP_DigestSignInit(md_ctx, &pctx, md, NULL, pkey) <= 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (lu->sig == EVP_PKEY_RSA_PSS) {
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                         ERR_R_EVP_LIB);
                goto err;
            }
        }
        tbslen = construct_key_exchange_tbs_ntls(s, &tbs,
                                            s->init_buf->data + paramoffset,
                                            paramlen);
        if (tbslen == 0) {
            /* SSLfatal_ntls() already called */
            goto err;
        }

        /* signature params and callback */
        rv = EVP_DigestSign(md_ctx, sigbytes1, &siglen, tbs, tbslen);
        OPENSSL_free(tbs);
        if (rv <= 0 || !WPACKET_sub_allocate_bytes_u16(pkt, siglen, &sigbytes2)
            || sigbytes1 != sigbytes2) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    EVP_MD_CTX_free(md_ctx);
    return 1;
 err:
# ifndef OPENSSL_NO_DH
    EVP_PKEY_free(pkdh);
# endif
# ifndef OPENSSL_NO_EC
    OPENSSL_free(encodedPoint);
# endif
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

int tls_construct_certificate_request_ntls(SSL *s, WPACKET *pkt)
{
    /* get the list of acceptable cert types */
    if (!WPACKET_start_sub_packet_u8(pkt)
        || !ssl3_get_req_cert_type(s, pkt) || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_CERTIFICATE_REQUEST_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (SSL_USE_SIGALGS(s)) {
        const uint16_t *psigs;
        size_t nl = tls12_get_psigalgs(s, 1, &psigs);

        if (!WPACKET_start_sub_packet_u16(pkt)
                || !WPACKET_set_flags(pkt, WPACKET_FLAGS_NON_ZERO_LENGTH)
                || !tls12_copy_sigalgs(s, pkt, psigs, nl)
                || !WPACKET_close(pkt)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_CERTIFICATE_REQUEST_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!construct_ca_names_ntls(s, get_ca_names_ntls(s), pkt)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }

    s->certreqs_sent++;
    s->s3->tmp.cert_request = 1;
    return 1;
}

static int tls_process_cke_psk_preamble(SSL *s, PACKET *pkt)
{
    /* Should never happen */
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_PSK_PREAMBLE,
             ERR_R_INTERNAL_ERROR);
    return 0;

}

static int tls_process_cke_rsa(SSL *s, PACKET *pkt)
{
# ifndef OPENSSL_NO_RSA
    unsigned char rand_premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];
    int decrypt_len;
    unsigned char decrypt_good, version_good;
    size_t j, padding_len;
    PACKET enc_premaster;
    RSA *rsa = NULL;
    unsigned char *rsa_decrypt = NULL;
    int ret = 0;

    rsa = EVP_PKEY_get0_RSA(s->cert->pkeys[SSL_PKEY_RSA].privatekey);
    if (rsa == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_RSA,
                 SSL_R_MISSING_RSA_CERTIFICATE);
        return 0;
    }

    /* SSLv3  omit the length bytes. */
    if (s->version == SSL3_VERSION) {
        enc_premaster = *pkt;
    } else {
        if (!PACKET_get_length_prefixed_2(pkt, &enc_premaster)
            || PACKET_remaining(pkt) != 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CKE_RSA,
                     SSL_R_LENGTH_MISMATCH);
            return 0;
        }
    }

    /*
     * We want to be sure that the plaintext buffer size makes it safe to
     * iterate over the entire size of a premaster secret
     * (SSL_MAX_MASTER_KEY_LENGTH). Reject overly short RSA keys because
     * their ciphertext cannot accommodate a premaster secret anyway.
     */
    if (RSA_size(rsa) < SSL_MAX_MASTER_KEY_LENGTH) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_RSA,
                 RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    rsa_decrypt = OPENSSL_malloc(RSA_size(rsa));
    if (rsa_decrypt == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_RSA,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /*
     * We must not leak whether a decryption failure occurs because of
     * Bleichenbacher's attack on PKCS # 1 v1.5 RSA padding (see RFC 2246,
     * section 7.4.7.1). The code follows that advice of the TLS RFC and
     * generates a random premaster secret for the case that the decrypt
     * fails. See https://tools.ietf.org/html/rfc5246# section-7.4.7.1
     */

    if (RAND_priv_bytes(rand_premaster_secret,
                      sizeof(rand_premaster_secret)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_RSA,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * Decrypt with no padding. PKCS# 1 padding will be removed as part of
     * the timing-sensitive code below.
     */
    /* TODO(size_t): Convert this function */
    decrypt_len = (int)RSA_private_decrypt((int)PACKET_remaining(&enc_premaster),
                                           PACKET_data(&enc_premaster),
                                           rsa_decrypt, rsa, RSA_NO_PADDING);

    if (decrypt_len < 0) {
        SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_TLS_PROCESS_CKE_RSA,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Check the padding. See RFC 3447, section 7.2.2. */

    /*
     * The smallest padded premaster is 11 bytes of overhead. Small keys
     * are publicly invalid, so this may return immediately. This ensures
     * PS is at least 8 bytes.
     */
    if (decrypt_len < 11 + SSL_MAX_MASTER_KEY_LENGTH) {
        SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_TLS_PROCESS_CKE_RSA,
                 SSL_R_DECRYPTION_FAILED);
        goto err;
    }

    padding_len = decrypt_len - SSL_MAX_MASTER_KEY_LENGTH;
    decrypt_good = constant_time_eq_int_8(rsa_decrypt[0], 0) &
        constant_time_eq_int_8(rsa_decrypt[1], 2);
    for (j = 2; j < padding_len - 1; j++) {
        decrypt_good &= ~constant_time_is_zero_8(rsa_decrypt[j]);
    }
    decrypt_good &= constant_time_is_zero_8(rsa_decrypt[padding_len - 1]);

    /*
     * If the version in the decrypted pre-master secret is correct then
     * version_good will be 0xff, otherwise it'll be zero. The
     * Klima-Pokorny-Rosa extension of Bleichenbacher's attack
     * (http://eprint.iacr.org/2003/052/) exploits the version number
     * check as a "bad version oracle". Thus version checks are done in
     * constant time and are treated like any other decryption error.
     */
    version_good =
        constant_time_eq_8(rsa_decrypt[padding_len],
                           (unsigned)(s->client_version >> 8));
    version_good &=
        constant_time_eq_8(rsa_decrypt[padding_len + 1],
                           (unsigned)(s->client_version & 0xff));

    /*
     * The premaster secret must contain the same version number as the
     * ClientHello to detect version rollback attacks (strangely, the
     * protocol does not offer such protection for DH ciphersuites).
     * However, buggy clients exist that send the negotiated protocol
     * version instead if the server does not support the requested
     * protocol version. If SSL_OP_TLS_ROLLBACK_BUG is set, tolerate such
     * clients.
     */
    if (s->options & SSL_OP_TLS_ROLLBACK_BUG) {
        unsigned char workaround_good;
        workaround_good = constant_time_eq_8(rsa_decrypt[padding_len],
                                             (unsigned)(s->version >> 8));
        workaround_good &=
            constant_time_eq_8(rsa_decrypt[padding_len + 1],
                               (unsigned)(s->version & 0xff));
        version_good |= workaround_good;
    }

    /*
     * Both decryption and version must be good for decrypt_good to
     * remain non-zero (0xff).
     */
    decrypt_good &= version_good;

    /*
     * Now copy rand_premaster_secret over from p using
     * decrypt_good_mask. If decryption failed, then p does not
     * contain valid plaintext, however, a check above guarantees
     * it is still sufficiently large to read from.
     */
    for (j = 0; j < sizeof(rand_premaster_secret); j++) {
        rsa_decrypt[padding_len + j] =
            constant_time_select_8(decrypt_good,
                                   rsa_decrypt[padding_len + j],
                                   rand_premaster_secret[j]);
    }

    if (!ssl_generate_master_secret(s, rsa_decrypt + padding_len,
                                    sizeof(rand_premaster_secret), 0)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    ret = 1;
 err:
    OPENSSL_free(rsa_decrypt);
    return ret;
# else
    /* Should never happen */
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_RSA,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int tls_process_cke_dhe(SSL *s, PACKET *pkt)
{
# ifndef OPENSSL_NO_DH
    EVP_PKEY *skey = NULL;
    DH *cdh;
    unsigned int i;
    BIGNUM *pub_key;
    const unsigned char *data;
    EVP_PKEY *ckey = NULL;
    int ret = 0;

    if (!PACKET_get_net_2(pkt, &i) || PACKET_remaining(pkt) != i) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CKE_DHE,
               SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG);
        goto err;
    }
    skey = s->s3->tmp.pkey;
    if (skey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_DHE,
                 SSL_R_MISSING_TMP_DH_KEY);
        goto err;
    }

    if (PACKET_remaining(pkt) == 0L) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CKE_DHE,
                 SSL_R_MISSING_TMP_DH_KEY);
        goto err;
    }
    if (!PACKET_get_bytes(pkt, &data, i)) {
        /* We already checked we have enough data */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_DHE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ckey = EVP_PKEY_new();
    if (ckey == NULL || EVP_PKEY_copy_parameters(ckey, skey) == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_DHE,
                 SSL_R_BN_LIB);
        goto err;
    }

    cdh = EVP_PKEY_get0_DH(ckey);
    pub_key = BN_bin2bn(data, i, NULL);
    if (pub_key == NULL || cdh == NULL || !DH_set0_key(cdh, pub_key, NULL)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_DHE,
                 ERR_R_INTERNAL_ERROR);
        BN_free(pub_key);
        goto err;
    }

    if (ssl_derive(s, skey, ckey, 1) == 0) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    ret = 1;
    EVP_PKEY_free(s->s3->tmp.pkey);
    s->s3->tmp.pkey = NULL;
 err:
    EVP_PKEY_free(ckey);
    return ret;
# else
    /* Should never happen */
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_DHE,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int tls_process_cke_ecdhe(SSL *s, PACKET *pkt)
{
# ifndef OPENSSL_NO_EC
    EVP_PKEY *skey = s->s3->tmp.pkey;
    EVP_PKEY *ckey = NULL;
    int ret = 0;

    if (PACKET_remaining(pkt) == 0L) {
        /* We don't support ECDH client auth */
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_TLS_PROCESS_CKE_ECDHE,
                 SSL_R_MISSING_TMP_ECDH_KEY);
        goto err;
    } else {
        unsigned int i;
        const unsigned char *data;

        /*
         * Get client's public key from encoded point in the
         * ClientKeyExchange message.
         */

        /* Get encoded point length */
        if (!PACKET_get_1(pkt, &i) || !PACKET_get_bytes(pkt, &data, i)
            || PACKET_remaining(pkt) != 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CKE_ECDHE,
                     SSL_R_LENGTH_MISMATCH);
            goto err;
        }
        if (skey == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_ECDHE,
                     SSL_R_MISSING_TMP_ECDH_KEY);
            goto err;
        }

        ckey = EVP_PKEY_new();
        if (ckey == NULL || EVP_PKEY_copy_parameters(ckey, skey) <= 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_ECDHE,
                     ERR_R_EVP_LIB);
            goto err;
        }
        if (EVP_PKEY_set1_tls_encodedpoint(ckey, data, i) == 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_ECDHE,
                     ERR_R_EC_LIB);
            goto err;
        }
    }

    if (ssl_derive(s, skey, ckey, 1) == 0) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    ret = 1;
    EVP_PKEY_free(s->s3->tmp.pkey);
    s->s3->tmp.pkey = NULL;
 err:
    EVP_PKEY_free(ckey);

    return ret;
# else
    /* Should never happen */
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_ECDHE,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int tls_process_cke_gost(SSL *s, PACKET *pkt)
{
# ifndef OPENSSL_NO_GOST
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *client_pub_pkey = NULL, *pk = NULL;
    unsigned char premaster_secret[32];
    const unsigned char *start;
    size_t outlen = 32, inlen;
    unsigned long alg_a;
    unsigned int asn1id, asn1len;
    int ret = 0;
    PACKET encdata;

    /* Get our certificate private key */
    alg_a = s->s3->tmp.new_cipher->algorithm_auth;
    if (alg_a & SSL_aGOST12) {
        /*
         * New GOST ciphersuites have SSL_aGOST01 bit too
         */
        pk = s->cert->pkeys[SSL_PKEY_GOST12_512].privatekey;
        if (pk == NULL) {
            pk = s->cert->pkeys[SSL_PKEY_GOST12_256].privatekey;
        }
        if (pk == NULL) {
            pk = s->cert->pkeys[SSL_PKEY_GOST01].privatekey;
        }
    } else if (alg_a & SSL_aGOST01) {
        pk = s->cert->pkeys[SSL_PKEY_GOST01].privatekey;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pk, NULL);
    if (pkey_ctx == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_GOST,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (EVP_PKEY_decrypt_init(pkey_ctx) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_GOST,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /*
     * If client certificate is present and is of the same type, maybe
     * use it for key exchange.  Don't mind errors from
     * EVP_PKEY_derive_set_peer, because it is completely valid to use a
     * client certificate for authorization only.
     */
    client_pub_pkey = X509_get0_pubkey(s->session->peer);
    if (client_pub_pkey) {
        if (EVP_PKEY_derive_set_peer(pkey_ctx, client_pub_pkey) <= 0)
            ERR_clear_error();
    }
    /* Decrypt session key */
    if (!PACKET_get_1(pkt, &asn1id)
            || asn1id != (V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED)
            || !PACKET_peek_1(pkt, &asn1len)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CKE_GOST,
                 SSL_R_DECRYPTION_FAILED);
        goto err;
    }
    if (asn1len == 0x81) {
        /*
         * Long form length. Should only be one byte of length. Anything else
         * isn't supported.
         * We did a successful peek before so this shouldn't fail
         */
        if (!PACKET_forward(pkt, 1)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_GOST,
                     SSL_R_DECRYPTION_FAILED);
            goto err;
        }
    } else  if (asn1len >= 0x80) {
        /*
         * Indefinite length, or more than one long form length bytes. We don't
         * support it
         */
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CKE_GOST,
                 SSL_R_DECRYPTION_FAILED);
        goto err;
    } /* else short form length */

    if (!PACKET_as_length_prefixed_1(pkt, &encdata)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CKE_GOST,
                 SSL_R_DECRYPTION_FAILED);
        goto err;
    }
    inlen = PACKET_remaining(&encdata);
    start = PACKET_data(&encdata);

    if (EVP_PKEY_decrypt(pkey_ctx, premaster_secret, &outlen, start,
                         inlen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CKE_GOST,
                 SSL_R_DECRYPTION_FAILED);
        goto err;
    }
    /* Generate master secret */
    if (!ssl_generate_master_secret(s, premaster_secret,
                                    sizeof(premaster_secret), 0)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }
    /* Check if pubkey from client certificate was used */
    if (EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_PEER_KEY, 2,
                          NULL) > 0)
        s->statem.no_cert_verify = 1;

    ret = 1;
 err:
    EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
# else
    /* Should never happen */
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CKE_GOST,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

MSG_PROCESS_RETURN tls_process_client_key_exchange_ntls(SSL *s, PACKET *pkt)
{
    unsigned long alg_k;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    /* For PSK parse and retrieve identity, obtain PSK key */
    if ((alg_k & SSL_PSK) && !tls_process_cke_psk_preamble(s, pkt)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    if (alg_k & SSL_kPSK) {
        /* Identity extracted earlier: should be nothing left */
        if (PACKET_remaining(pkt) != 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE_NTLS,
                     SSL_R_LENGTH_MISMATCH);
            goto err;
        }
        /* PSK handled by ssl_generate_master_secret */
        if (!ssl_generate_master_secret(s, NULL, 0, 0)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & (SSL_kRSA | SSL_kRSAPSK)) {
        if (!tls_process_cke_rsa(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & (SSL_kDHE | SSL_kDHEPSK)) {
        if (!tls_process_cke_dhe(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & (SSL_kECDHE | SSL_kECDHEPSK)) {
        if (!tls_process_cke_ecdhe(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & SSL_kGOST) {
        if (!tls_process_cke_gost(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE_NTLS,
                 SSL_R_UNKNOWN_CIPHER_TYPE);
        goto err;
    }

    return MSG_PROCESS_CONTINUE_PROCESSING;
 err:
    return MSG_PROCESS_ERROR;
}

WORK_STATE tls_post_process_client_key_exchange_ntls(SSL *s, WORK_STATE wst)
{
    if (s->statem.no_cert_verify || !s->session->peer) {
        /*
         * No certificate verify or no peer certificate so we no longer need
         * the handshake_buffer
         */
        if (!ssl3_digest_cached_records(s, 0)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }
        return WORK_FINISHED_CONTINUE;
    } else {
        if (!s->s3->handshake_buffer) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_POST_PROCESS_CLIENT_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return WORK_ERROR;
        }
        /*
         * For sigalgs freeze the handshake buffer. If we support
         * extms we've done this already so this is a no-op
         */
        if (!ssl3_digest_cached_records(s, 1)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }
    }

    return WORK_FINISHED_CONTINUE;
}

MSG_PROCESS_RETURN tls_process_client_certificate_ntls(SSL *s, PACKET *pkt)
{
    int i, j;
    MSG_PROCESS_RETURN ret = MSG_PROCESS_ERROR;
    X509 *x = NULL;
    unsigned long l;
    const unsigned char *certstart, *certbytes;
    STACK_OF(X509) *sk = NULL;
    PACKET spkt;
    size_t chainidx;
    SSL_SESSION *new_sess = NULL;

    /*
     * To get this far we must have read encrypted data from the client. We no
     * longer tolerate unencrypted alerts. This value is ignored if less than
     * TLSv1.3
     */
    s->statem.enc_read_state = ENC_READ_STATE_VALID;

    if ((sk = sk_X509_new_null()) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!PACKET_get_length_prefixed_3(pkt, &spkt)
            || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    for (chainidx = 0; PACKET_remaining(&spkt) > 0; chainidx++) {
        if (!PACKET_get_net_3(&spkt, &l)
            || !PACKET_get_bytes(&spkt, &certbytes, l)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                     SSL_R_CERT_LENGTH_MISMATCH);
            goto err;
        }

        certstart = certbytes;
        x = d2i_X509(NULL, (const unsigned char **)&certbytes, l);
        if (x == NULL) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS, ERR_R_ASN1_LIB);
            goto err;
        }
        if (certbytes != (certstart + l)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                     SSL_R_CERT_LENGTH_MISMATCH);
            goto err;
        }

        if (!sk_X509_push(sk, x)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        }
        x = NULL;
    }

    if (sk_X509_num(sk) <= 0) {
        /*for ECDHE-SM2, certificates are required */
        const SSL_CIPHER *cipher = s->s3->tmp.new_cipher;
        if (cipher->id == NTLS_CK_ECDHE_SM2_SM4_CBC_SM3
            || cipher->id == NTLS_CK_ECDHE_SM2_SM4_GCM_SM3) {
            SSLfatal_ntls(s, SSL_AD_CERTIFICATE_REQUIRED,
                          SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                          SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
            goto err;
        }

        /* Fail for TLS only if we required a certificate */
        else if ((s->verify_mode & SSL_VERIFY_PEER) &&
                 (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
            SSLfatal_ntls(s, SSL_AD_CERTIFICATE_REQUIRED,
                          SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                          SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
            goto err;
        }

        /* No client certificate so digest cached records */
        if (s->s3->handshake_buffer && !ssl3_digest_cached_records(s, 0)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (sk_X509_num(sk) < 2) {
        SSLfatal_ntls(s, SSL_AD_CERTIFICATE_REQUIRED,
                      SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                      SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
        goto err;
    } else {
        for (j = 0; j < 2; j++) {
            if (j == 0)
                sk_X509_push(sk, sk_X509_shift(sk));
            if (j == 1)
                sk_X509_unshift(sk, sk_X509_pop(sk));

            i = ssl_verify_cert_chain(s, sk);

            if (i <= 0) {
                SSLfatal_ntls(s, ssl_x509err2alert_ntls(s->verify_result),
                              SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                              SSL_R_CERTIFICATE_VERIFY_FAILED);
                goto err;
            }

            if (i > 1) {
                SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                              SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS, i);
                goto err;
            }

            if (X509_get0_pubkey(sk_X509_value(sk, 0)) == NULL) {
                SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                              SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                              SSL_R_UNKNOWN_CERTIFICATE_TYPE);
                goto err;
            }
        }
    }

    /*
     * Sessions must be immutable once they go into the session cache. Otherwise
     * we can get multi-thread problems. Therefore we don't "update" sessions,
     * we replace them with a duplicate. Here, we need to do this every time
     * a new certificate is received via post-handshake authentication, as the
     * session may have already gone into the session cache.
     */

    if (s->post_handshake_auth == SSL_PHA_REQUESTED) {
        if ((new_sess = ssl_session_dup(s->session, 0)) == 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE_NTLS,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        }

        SSL_SESSION_free(s->session);
        s->session = new_sess;
    }

    X509_free(s->session->peer);
    s->session->peer = sk_X509_shift(sk);
    s->session->verify_result = s->verify_result;

    sk_X509_pop_free(s->session->peer_chain, X509_free);
    /*
     * XXX:
     *
     * For NTLS, s->session->peer stores the client signing certificate
     * and s->session->peer_chain is an one item stack which stores
     * the client encryption certificate.
     */
    s->session->peer_chain = sk;

    /*
     * Inconsistency alert: cert_chain does *not* include the peer's own
     * certificate, while we do include it in statem_clnt.c
     */
    sk = NULL;
    ret = MSG_PROCESS_CONTINUE_READING;

 err:
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);
    return ret;
}

int tls_construct_server_certificate_ntls(SSL *s, WPACKET *pkt)
{
    CERT_PKEY *a_cpk = s->s3->tmp.sign_cert;
    CERT_PKEY *k_cpk = s->s3->tmp.enc_cert;

    if (a_cpk == NULL || k_cpk == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_TLS_CONSTRUCT_SERVER_CERTIFICATE_NTLS,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!ssl3_output_cert_chain_ntls(s, pkt, a_cpk, k_cpk)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }

    return 1;
}

static int create_ticket_prequel(SSL *s, WPACKET *pkt, uint32_t age_add,
                                 unsigned char *tick_nonce)
{
    /*
     * Ticket lifetime hint: For TLSv1.2 this is advisory only and we leave this
     * unspecified for resumed session (for simplicity).
     * In TLSv1.3 we reset the "time" field above, and always specify the
     * timeout.
     */
    if (!WPACKET_put_bytes_u32(pkt,
                               (s->hit)
                               ? 0 : s->session->timeout)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CREATE_TICKET_PREQUEL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Start the sub-packet for the actual ticket data */
    if (!WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CREATE_TICKET_PREQUEL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int construct_stateless_ticket(SSL *s, WPACKET *pkt, uint32_t age_add,
                                      unsigned char *tick_nonce)
{
    unsigned char *senc = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    HMAC_CTX *hctx = NULL;
    unsigned char *p, *encdata1, *encdata2, *macdata1, *macdata2;
    const unsigned char *const_p;
    int len, slen_full, slen, lenfinal;
    SSL_SESSION *sess;
    unsigned int hlen;
    SSL_CTX *tctx = s->session_ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char key_name[TLSEXT_KEYNAME_LENGTH];
    int iv_len, ok = 0;
    size_t macoffset, macendoffset;

    /* get session encoding length */
    slen_full = i2d_SSL_SESSION(s->session, NULL);
    /*
     * Some length values are 16 bits, so forget it if session is too
     * long
     */
    if (slen_full == 0 || slen_full > 0xFF00) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CONSTRUCT_STATELESS_TICKET,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }
    senc = OPENSSL_malloc(slen_full);
    if (senc == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_CONSTRUCT_STATELESS_TICKET, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ctx = EVP_CIPHER_CTX_new();
    hctx = HMAC_CTX_new();
    if (ctx == NULL || hctx == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CONSTRUCT_STATELESS_TICKET,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    p = senc;
    if (!i2d_SSL_SESSION(s->session, &p)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CONSTRUCT_STATELESS_TICKET,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * create a fresh copy (not shared with other threads) to clean up
     */
    const_p = senc;
    sess = d2i_SSL_SESSION(NULL, &const_p, slen_full);
    if (sess == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CONSTRUCT_STATELESS_TICKET,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    slen = i2d_SSL_SESSION(sess, NULL);
    if (slen == 0 || slen > slen_full) {
        /* shouldn't ever happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CONSTRUCT_STATELESS_TICKET,
                 ERR_R_INTERNAL_ERROR);
        SSL_SESSION_free(sess);
        goto err;
    }
    p = senc;
    if (!i2d_SSL_SESSION(sess, &p)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CONSTRUCT_STATELESS_TICKET,
                 ERR_R_INTERNAL_ERROR);
        SSL_SESSION_free(sess);
        goto err;
    }
    SSL_SESSION_free(sess);

    /*
     * Initialize HMAC and cipher contexts. If callback present it does
     * all the work otherwise use generated values from parent ctx.
     */
    if (tctx->ext.ticket_key_cb) {
        /* if 0 is returned, write an empty ticket */
        int ret = tctx->ext.ticket_key_cb(s, key_name, iv, ctx,
                                             hctx, 1);

        if (ret == 0) {

            /* Put timeout and length */
            if (!WPACKET_put_bytes_u32(pkt, 0)
                    || !WPACKET_put_bytes_u16(pkt, 0)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_CONSTRUCT_STATELESS_TICKET,
                         ERR_R_INTERNAL_ERROR);
                goto err;
            }
            OPENSSL_free(senc);
            EVP_CIPHER_CTX_free(ctx);
            HMAC_CTX_free(hctx);
            return 1;
        }
        if (ret < 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CONSTRUCT_STATELESS_TICKET,
                     SSL_R_CALLBACK_FAILED);
            goto err;
        }
        iv_len = EVP_CIPHER_CTX_iv_length(ctx);
    } else {
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();

        iv_len = EVP_CIPHER_iv_length(cipher);
        if (RAND_bytes(iv, iv_len) <= 0
                || !EVP_EncryptInit_ex(ctx, cipher, NULL,
                                       tctx->ext.secure->tick_aes_key, iv)
                || !HMAC_Init_ex(hctx, tctx->ext.secure->tick_hmac_key,
                                 sizeof(tctx->ext.secure->tick_hmac_key),
                                 EVP_sha256(), NULL)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CONSTRUCT_STATELESS_TICKET,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(key_name, tctx->ext.tick_key_name,
               sizeof(tctx->ext.tick_key_name));
    }

    if (!create_ticket_prequel(s, pkt, age_add, tick_nonce)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    if (!WPACKET_get_total_written(pkt, &macoffset)
               /* Output key name */
            || !WPACKET_memcpy(pkt, key_name, sizeof(key_name))
               /* output IV */
            || !WPACKET_memcpy(pkt, iv, iv_len)
            || !WPACKET_reserve_bytes(pkt, slen + EVP_MAX_BLOCK_LENGTH,
                                      &encdata1)
               /* Encrypt session data */
            || !EVP_EncryptUpdate(ctx, encdata1, &len, senc, slen)
            || !WPACKET_allocate_bytes(pkt, len, &encdata2)
            || encdata1 != encdata2
            || !EVP_EncryptFinal(ctx, encdata1 + len, &lenfinal)
            || !WPACKET_allocate_bytes(pkt, lenfinal, &encdata2)
            || encdata1 + len != encdata2
            || len + lenfinal > slen + EVP_MAX_BLOCK_LENGTH
            || !WPACKET_get_total_written(pkt, &macendoffset)
            || !HMAC_Update(hctx,
                            (unsigned char *)s->init_buf->data + macoffset,
                            macendoffset - macoffset)
            || !WPACKET_reserve_bytes(pkt, EVP_MAX_MD_SIZE, &macdata1)
            || !HMAC_Final(hctx, macdata1, &hlen)
            || hlen > EVP_MAX_MD_SIZE
            || !WPACKET_allocate_bytes(pkt, hlen, &macdata2)
            || macdata1 != macdata2) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_CONSTRUCT_STATELESS_TICKET, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Close the sub-packet created by create_ticket_prequel() */
    if (!WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_CONSTRUCT_STATELESS_TICKET,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ok = 1;
 err:
    OPENSSL_free(senc);
    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_free(hctx);
    return ok;
}

int tls_construct_new_session_ticket_ntls(SSL *s, WPACKET *pkt)
{
    SSL_CTX *tctx = s->session_ctx;
    unsigned char tick_nonce[TICKET_NONCE_SIZE];
    union {
        unsigned char age_add_c[sizeof(uint32_t)];
        uint32_t age_add;
    } age_add_u;

    age_add_u.age_add = 0;

    if (tctx->generate_ticket_cb != NULL &&
        tctx->generate_ticket_cb(s, tctx->ticket_cb_data) == 0)
        goto err;

    if (!construct_stateless_ticket(s, pkt, age_add_u.age_add,
                                           tick_nonce)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    return 1;
 err:
    return 0;
}

/*
 * In TLSv1.3 this is called from the extensions code, otherwise it is used to
 * create a separate message. Returns 1 on success or 0 on failure.
 */
int tls_construct_cert_status_body_ntls(SSL *s, WPACKET *pkt)
{
    if (!WPACKET_put_bytes_u8(pkt, s->ext.status_type)
            || !WPACKET_sub_memcpy_u24(pkt, s->ext.ocsp.resp,
                                       s->ext.ocsp.resp_len)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CERT_STATUS_BODY_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_construct_cert_status_ntls(SSL *s, WPACKET *pkt)
{
    if (!tls_construct_cert_status_body_ntls(s, pkt)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }

    return 1;
}

# ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * tls_process_next_proto_ntls reads a Next Protocol Negotiation handshake message.
 * It sets the next_proto member in s if found
 */
MSG_PROCESS_RETURN tls_process_next_proto_ntls(SSL *s, PACKET *pkt)
{
    PACKET next_proto, padding;
    size_t next_proto_len;

    /*-
     * The payload looks like:
     *   uint8 proto_len;
     *   uint8 proto[proto_len];
     *   uint8 padding_len;
     *   uint8 padding[padding_len];
     */
    if (!PACKET_get_length_prefixed_1(pkt, &next_proto)
        || !PACKET_get_length_prefixed_1(pkt, &padding)
        || PACKET_remaining(pkt) > 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_NEXT_PROTO_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    if (!PACKET_memdup(&next_proto, &s->ext.npn, &next_proto_len)) {
        s->ext.npn_len = 0;
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_NEXT_PROTO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    s->ext.npn_len = (unsigned char)next_proto_len;

    return MSG_PROCESS_CONTINUE_READING;
}
# endif

static int tls_construct_encrypted_extensions(SSL *s, WPACKET *pkt)
{
    if (!tls_construct_extensions_ntls(s, pkt, SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                                  NULL, 0)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }

    return 1;
}

MSG_PROCESS_RETURN tls_process_end_of_early_data_ntls(SSL *s, PACKET *pkt)
{
    if (PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_END_OF_EARLY_DATA_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    if (s->early_data_state != SSL_EARLY_DATA_READING
            && s->early_data_state != SSL_EARLY_DATA_READ_RETRY) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_END_OF_EARLY_DATA_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * EndOfEarlyData signals a key change so the end of the message must be on
     * a record boundary.
     */
    if (RECORD_LAYER_processed_read_pending(&s->rlayer)) {
        SSLfatal_ntls(s, SSL_AD_UNEXPECTED_MESSAGE,
                 SSL_F_TLS_PROCESS_END_OF_EARLY_DATA_NTLS,
                 SSL_R_NOT_ON_RECORD_BOUNDARY);
        return MSG_PROCESS_ERROR;
    }

    s->early_data_state = SSL_EARLY_DATA_FINISHED_READING;
    if (!s->method->ssl3_enc->change_cipher_state(s,
                SSL3_CC_HANDSHAKE | SSL3_CHANGE_CIPHER_SERVER_READ)) {
        /* SSLfatal_ntls() already called */
        return MSG_PROCESS_ERROR;
    }

    return MSG_PROCESS_CONTINUE_READING;
}
#endif
