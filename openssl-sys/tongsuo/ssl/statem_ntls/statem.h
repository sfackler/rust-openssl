/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

/*****************************************************************************
 *                                                                           *
 * These enums should be considered PRIVATE to the state machine. No         *
 * non-state machine code should need to use these                           *
 *                                                                           *
 *****************************************************************************/
/*
 * Valid return codes used for functions performing work prior to or after
 * sending or receiving a message
 */

typedef enum {
    /* Something went wrong */
    WORK_ERROR_NTLS,
    /* We're done working and there shouldn't be anything else to do after */
    WORK_FINISHED_STOP_NTLS,
    /* We're done working move onto the next thing */
    WORK_FINISHED_CONTINUE_NTLS,
    /* We're working on phase A */
    WORK_MORE_A_NTLS,
    /* We're working on phase B */
    WORK_MORE_B_NTLS,
    /* We're working on phase C */
    WORK_MORE_C_NTLS
} WORK_STATE_NTLS;

/* Write transition return codes */
typedef enum {
    /* Something went wrong */
    WRITE_TRAN_ERROR_NTLS,
    /* A transition was successfully completed and we should continue */
    WRITE_TRAN_CONTINUE_NTLS,
    /* There is no more write work to be done */
    WRITE_TRAN_FINISHED_NTLS
} WRITE_TRAN_NTLS;

/* Message flow states */
typedef enum {
    /* No handshake in progress */
    MSG_FLOW_UNINITED_NTLS,
    /* A permanent error with this connection */
    MSG_FLOW_ERROR_NTLS,
    /* We are reading messages */
    MSG_FLOW_READING_NTLS,
    /* We are writing messages */
    MSG_FLOW_WRITING_NTLS,
    /* Handshake has finished */
    MSG_FLOW_FINISHED_NTLS
} MSG_FLOW_STATE_NTLS;

/* Read states */
typedef enum {
    READ_STATE_HEADER_NTLS,
    READ_STATE_BODY_NTLS,
    READ_STATE_POST_PROCESS_NTLS
} READ_STATE_NTLS;

/* Write states */
typedef enum {
    WRITE_STATE_TRANSITION_NTLS,
    WRITE_STATE_PRE_WORK_NTLS,
    WRITE_STATE_SEND_NTLS,
    WRITE_STATE_POST_WORK_NTLS
} WRITE_STATE_NTLS;

typedef enum {
    /* The enc_write_ctx can be used normally */
    ENC_WRITE_STATE_VALID_NTLS,
    /* The enc_write_ctx cannot be used */
    ENC_WRITE_STATE_INVALID_NTLS,
    /* Write alerts in plaintext, but otherwise use the enc_write_ctx */
    ENC_WRITE_STATE_WRITE_PLAIN_ALERTS_NTLS
} ENC_WRITE_STATES_NTLS;

typedef enum {
    /* The enc_read_ctx can be used normally */
    ENC_READ_STATE_VALID_NTLS,
    /* We may receive encrypted or plaintext alerts */
    ENC_READ_STATE_ALLOW_PLAIN_ALERTS_NTLS
} ENC_READ_STATES_NTLS;

/*****************************************************************************
 *                                                                           *
 * This structure should be considered "opaque" to anything outside of the   *
 * state machine. No non-state machine code should be accessing the members  *
 * of this structure.                                                        *
 *                                                                           *
 *****************************************************************************/

struct ossl_statem_st_ntls {
    MSG_FLOW_STATE_NTLS state;
    WRITE_STATE_NTLS write_state;
    WORK_STATE_NTLS write_state_work;
    READ_STATE_NTLS read_state;
    WORK_STATE_NTLS read_state_work;
    OSSL_HANDSHAKE_STATE hand_state;
    /* The handshake state requested by an API call (e.g. HelloRequest) */
    OSSL_HANDSHAKE_STATE request_state;
    int in_init;
    int read_state_first_init;
    /* true when we are actually in SSL_accept() or SSL_connect() */
    int in_handshake;
    /*
     * True when are processing a "real" handshake that needs cleaning up (not
     * just a HelloRequest or similar).
     */
    int cleanuphand;
    /* Should we skip the CertificateVerify message? */
    unsigned int no_cert_verify;
    int use_timer;
    ENC_WRITE_STATES_NTLS enc_write_state;
    ENC_READ_STATES_NTLS enc_read_state;
};

typedef struct ossl_statem_st_ntls OSSL_STATEM_NTLS;

/*****************************************************************************
 *                                                                           *
 * The following macros/functions represent the libssl internal API to the   *
 * state machine. Any libssl code may call these functions/macros            *
 *                                                                           *
 *****************************************************************************/

__owur int ossl_statem_accept_ntls(SSL *s);
__owur int ossl_statem_connect_ntls(SSL *s);
void ossl_statem_clear_ntls(SSL *s);
void ossl_statem_set_renegotiate_ntls(SSL *s);
void ossl_statem_fatal_ntls(SSL *s, int al, int func, int reason, const char *file,
                       int line);
# define SSL_AD_NO_ALERT    -1
# ifndef OPENSSL_NO_ERR
#  define SSLfatal_ntls(s, al, f, r)  ossl_statem_fatal_ntls((s), (al), (f), (r), \
                                                   OPENSSL_FILE, OPENSSL_LINE)
# else
#  define SSLfatal_ntls(s, al, f, r)  ossl_statem_fatal_ntls((s), (al), (f), (r), NULL, 0)
# endif

int ossl_statem_in_error_ntls(const SSL *s);
void ossl_statem_set_in_init_ntls(SSL *s, int init);
int ossl_statem_get_in_handshake_ntls(SSL *s);
void ossl_statem_set_in_handshake_ntls(SSL *s, int inhand);
__owur int ossl_statem_skip_early_data_ntls(SSL *s);
void ossl_statem_check_finish_init_ntls(SSL *s, int send);
void ossl_statem_set_hello_verify_done_ntls(SSL *s);
__owur int ossl_statem_app_data_allowed_ntls(SSL *s);
__owur int ossl_statem_export_allowed_ntls(SSL *s);
__owur int ossl_statem_export_early_allowed_ntls(SSL *s);

/* Flush the write BIO */
int statem_flush_ntls(SSL *s);
int state_machine_ntls(SSL *s, int server);

int SSL_connection_is_ntls(SSL *s, int is_server);
