/*
 * EAP server method: EAP-NOOB
 *  Copyright (c) 2016, Aalto University
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of the Aalto University nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL AALTO UNIVERSITY BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  See CONTRIBUTORS for more information.
 */

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <signal.h>

#include <base64.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <jansson.h>
#include "common.h"
#include "utils/json.h"
#include "eap_i.h"
#include "eap_noob.h"
#include "../../wpa_supplicant/config.h"
#include "../../wpa_supplicant/wpa_supplicant_i.h"
#include "../../wpa_supplicant/blacklist.h"

static struct eap_noob_globle_conf eap_noob_globle_conf = {0};

/*
 * eap_noob_Base64Decode : Decodes a base64url string.
 * @b64message : input base64url string
 * @buffer : output
 * Returns : Len of decoded string
**/
static int eap_noob_Base64Decode(const char * b64message, unsigned char ** buffer)
{
    fprintf(stderr, "ENTER B64DECODE FUN\n");
    size_t len = os_strlen(b64message);
    size_t b64pad = 4*((len + 3)/4) - len;
    char *temp = os_zalloc(len + b64pad + 1);
    if (temp == NULL) 
	    return -1;
    os_memcpy(temp, b64message, len);
    for(int i = 0; i < len; i++) {
	    if (temp[i] == '-')
		    temp[i] = '+';
            else if (temp[i] == '_')
		    temp[i] = '/';
    }
    for(int i = 0; i < b64pad; i++) 
	    temp[len + i] = '=';
    size_t decodeLen;
    unsigned char *tempX;
    tempX = base64_decode(temp, len + b64pad, &decodeLen);
    if (tempX == NULL)
	    return -1;
    *buffer = os_zalloc(decodeLen + 1);
    memcpy(*buffer, tempX, decodeLen);
    return decodeLen;
}

/**
 * eap_noob_Base64Encode : Encode an ascii string to base64url. Dealloc b64text
 * as needed from the caller.
 * @buffer : input buffer
 * @length : input buffer length
 * @b64text : converted base64url text
 * Returns : SUCCESS/FAILURE
 **/
int eap_noob_Base64Encode(const unsigned char * buffer, size_t length, char ** b64text)
{
    size_t len = 0;
    char *tmp;
    tmp = base64_encode(buffer, length, &len);
    if (tmp == NULL)
	    return -1;
    for(int i = 0; i < len; i++) {
	    if (tmp[i] == '+') 
		    tmp[i] = '-';
	    else if (tmp[i] == '/') 
		    tmp[i] = '_';
	    else if (tmp[i] == '=') {
		    tmp[i] = '\0';
		    len = i;
		    break;
	    }
    }

    *b64text = os_zalloc(len);
    if (*b64text == NULL)
	    return -1;
    os_memcpy(*b64text, tmp, len);

    return SUCCESS;
}


/**
 *eap_noob_ECDH_KDF_X9_63: generates KDF
 *@out:
 *@outlen:
 * Z:
 * Zlen:
 * alorithm_id:
 * alorithm_id_len:
 * partyUinfo:
 * partyUinfo_len:
 * partyVinfo:
 * partyVinfo_len
 * suppPrivinfo:
 * suppPrivinfo_len:
 * EVP_MD:
 * Returns:
**/
static int eap_noob_ECDH_KDF_X9_63(unsigned char *out, size_t outlen,
        const unsigned char * Z, size_t Zlen,
        const unsigned char * algorithm_id, size_t algorithm_id_len,
        const unsigned char * partyUinfo, size_t partyUinfo_len,
        const unsigned char * partyVinfo, size_t partyVinfo_len,
        const unsigned char * suppPrivinfo, size_t suppPrivinfo_len,
        const EVP_MD * md)
{
    EVP_MD_CTX * mctx = NULL;
    unsigned char ctr[4] = {0};
    unsigned int i = 0;
    size_t mdlen = 0;
    int rv = 0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: KDF start");
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Value:", Z, Zlen);

    if (algorithm_id_len > ECDH_KDF_MAX || outlen > ECDH_KDF_MAX ||
        Zlen > ECDH_KDF_MAX || partyUinfo_len > ECDH_KDF_MAX ||
        partyVinfo_len > ECDH_KDF_MAX || suppPrivinfo_len > ECDH_KDF_MAX)
        return 0;

    mctx = EVP_MD_CTX_create();
    if (mctx == NULL)
        return 0;

    mdlen = EVP_MD_size(md);
    wpa_printf(MSG_DEBUG,"EAP-NOOB: KDF begin %d", (int)mdlen);
    for (i = 1;; i++) {
        unsigned char mtmp[EVP_MAX_MD_SIZE];
        EVP_DigestInit_ex(mctx, md, NULL);
        ctr[3] = (i & 0xFF);
        ctr[2] = ((i >> 8) & 0xFF);
        ctr[1] = ((i >> 16) & 0xFF);
        ctr[0] = (i >> 24);
        if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
            goto err;
        if (!EVP_DigestUpdate(mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(mctx, algorithm_id, algorithm_id_len))
            goto err;
        if (!EVP_DigestUpdate(mctx, partyUinfo, partyUinfo_len))
            goto err;
        if (!EVP_DigestUpdate(mctx, partyVinfo, partyVinfo_len))
            goto err;

        if (suppPrivinfo != NULL)
            if (!EVP_DigestUpdate(mctx, suppPrivinfo, suppPrivinfo_len))
                goto err;

        if (outlen >= mdlen) {
            if (!EVP_DigestFinal(mctx, out, NULL))
                goto err;
            outlen -= mdlen;
            if (outlen == 0)
                break;
            out += mdlen;
        } else {
            if (!EVP_DigestFinal(mctx, mtmp, NULL))
                goto err;
            memcpy(out, mtmp, outlen);
            OPENSSL_cleanse(mtmp, mdlen);
            break;
        }
    }
    rv = 1;
err:
    wpa_printf(MSG_DEBUG,"EAP-NOOB:KDF finished %d",rv);
    EVP_MD_CTX_destroy(mctx);
    return rv;
}


/**
 * eap_noob_gen_KDF : generates and updates the KDF inside the peer context.
 * @data  : peer context.
 * @state : EAP_NOOB state
 * Returns:
**/
static int eap_noob_gen_KDF(struct eap_noob_peer_context * data, int state)
{

    const EVP_MD * md = EVP_sha256();
    unsigned char * out = os_zalloc(KDF_LEN);
    int counter = 0, len = 0;
    u8 * Noob;

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Algorith ID:", ALGORITHM_ID,ALGORITHM_ID_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce_Peer", data->server_attr->kdf_nonce_data->Np,
                      NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce_Serv", data->server_attr->kdf_nonce_data->Ns,
                      NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Shared Key", data->server_attr->ecdh_exchange_data->shared_key,
                      ECDH_SHARED_SECRET_LEN);
    if (state == COMPLETION_EXCHANGE) {
        len = eap_noob_Base64Decode(data->server_attr->oob_data->Noob_b64, &Noob);
        if (len != NOOB_LEN) {
		    wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode Noob");
		    return FAILURE;
	    }
        wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Noob", Noob, NOOB_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->server_attr->ecdh_exchange_data->shared_key, ECDH_SHARED_SECRET_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->server_attr->kdf_nonce_data->Np, NONCE_LEN,
                data->server_attr->kdf_nonce_data->Ns, NONCE_LEN,
                Noob, NOOB_LEN, md);
    } else {

        wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: kz", data->peer_attr->Kz,KZ_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->peer_attr->Kz, KZ_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->server_attr->kdf_nonce_data->Np, NONCE_LEN,
                data->server_attr->kdf_nonce_data->Ns, NONCE_LEN,
                NULL, 0, md);
    }
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: KDF",out,KDF_LEN);

    if (out != NULL) {
        data->server_attr->kdf_out->msk = os_zalloc(MSK_LEN);
        data->server_attr->kdf_out->emsk = os_zalloc(EMSK_LEN);
        data->server_attr->kdf_out->amsk = os_zalloc(AMSK_LEN);
        data->server_attr->kdf_out->MethodId = os_zalloc(METHOD_ID_LEN);        
        data->server_attr->kdf_out->Kms = os_zalloc(KMS_LEN);
        data->server_attr->kdf_out->Kmp = os_zalloc(KMP_LEN);
        data->server_attr->kdf_out->Kz = os_zalloc(KZ_LEN);

        memcpy(data->server_attr->kdf_out->msk,out,MSK_LEN);
        counter += MSK_LEN;
        memcpy(data->server_attr->kdf_out->emsk, out + counter, EMSK_LEN);
        counter += EMSK_LEN;
        memcpy(data->server_attr->kdf_out->amsk, out + counter, AMSK_LEN);
        counter += AMSK_LEN;
        memcpy(data->server_attr->kdf_out->MethodId, out + counter, METHOD_ID_LEN);
        counter += METHOD_ID_LEN;        
        memcpy(data->server_attr->kdf_out->Kms, out + counter, KMS_LEN);
        counter += KMS_LEN;
        memcpy(data->server_attr->kdf_out->Kmp, out + counter, KMP_LEN);
        counter += KMP_LEN;
        memcpy(data->server_attr->kdf_out->Kz, out + counter, KZ_LEN);

//Copy it to the peer_context also. Kz is used reconnect exchange. 
        if(state == COMPLETION_EXCHANGE) {
            data->peer_attr->Kz = os_zalloc(KZ_LEN);
            memcpy(data->peer_attr->Kz, out + counter, KZ_LEN);
        }
        counter += KZ_LEN;
    } else { 
    	wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory, %s", __func__);
    	return FAILURE;
    }
    return SUCCESS;
}

/**
 * eap_noob_prepare_peer_info_json : Append a Json object for peer information.
 * @data : peer context.
 * @json : wpabuf json object to which the peer info object should be appended.
 * @name : name for the peer info json object, or NULL.
**/
static void eap_noob_prepare_peer_info_json(struct eap_sm * sm, struct eap_noob_peer_config_params * data, wpabuf * json, char * name)
{
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;
    char bssid[18] = {0};

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    json_start_object(json, name);
    json_add_string(json, PEER_MAKE, data->Peer_name);
    json_value_sep(json);
    json_add_string(json, PEER_TYPE, eap_noob_globle_conf.peer_type);
    json_value_sep(json);
    json_add_string(json, PEER_SERIAL_NUM, data->Peer_ID_Num);
    json_value_sep(json);
    json_add_string(json, PEER_SSID, (char *) wpa_s->current_ssid->ssid);
    json_value_sep(json);

    sprintf(bssid,"%x:%x:%x:%x:%x:%x",wpa_s->current_ssid->bssid[0],wpa_s->current_ssid->bssid[1],
            wpa_s->current_ssid->bssid[2],wpa_s->current_ssid->bssid[3],wpa_s->current_ssid->bssid[4],
            wpa_s->current_ssid->bssid[5]);

    json_add_string(json, PEER_BSSID, bssid);
    json_end_object(json);
}

/**
 * Generate a string representation of a JSON peer information object.
 * @data: peer context
 */
static char * eap_noob_prepare_peer_info_string(struct eap_sm * sm,
        struct eap_noob_peer_config_params * data)
{
    struct wpabuf * json = NULL;
    char * resp = NULL;

    json = wpabuf_alloc(MAX_INFO_LEN);
    if (!json) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for JSON wpabuf");
        return NULL;
    }

    // Append JSON peer info object without a name
    eap_noob_prepare_peer_info_json(sm, data, json, NULL);

    // Get a string representation of the JSON object
    resp = strndup(wpabuf_head(json), wpabuf_len(json));

    wpabuf_free(json);

    return resp;
}

/**
 * eap_noob_db_statements : execute one or more sql statements that do not return rows
 * @db : open sqlite3 database handle
 * @query : query to be executed
 * Returns  :  SUCCESS/FAILURE
 **/
static int eap_noob_db_statements(sqlite3 * db, const char * query)
{
    int nByte = os_strlen(query);
    sqlite3_stmt * stmt;
    const char * tail = query, * sql_error;
    int ret = SUCCESS;

    if (NULL == db || NULL == query) return FAILURE;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

    /* Loop through multiple SQL statements in sqlite3 */
    while (tail < query + nByte) {
        if (SQLITE_OK != sqlite3_prepare_v2(db, tail, -1, &stmt, &tail)
            || NULL == stmt) {
            ret = FAILURE; goto EXIT; }
        if (SQLITE_DONE != sqlite3_step(stmt)) {
            ret = FAILURE; goto EXIT; }
    }
EXIT:
    if (ret == FAILURE) {
        sql_error = sqlite3_errmsg(db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s", sql_error);
    }
    if (stmt) sqlite3_finalize(stmt);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d",__func__, ret);
    return ret;
}

static int eap_noob_encode_vers_cryptosuites(struct eap_noob_peer_context * data,
        char ** Vers, char ** Cryptosuites)
{
    struct wpabuf * vers = wpabuf_alloc(100); 
    struct wpabuf * cryptosuites = wpabuf_alloc(100); 

    if (!vers || !cryptosuites) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: JSON allocation for Vers and Cryptosuites failed");
        return FAILURE;
    }

    // Populate the vers array
    json_start_array(vers, NULL);
    for (int i = 0; i < MAX_SUP_VER; i++) { 
        wpabuf_printf(vers, "%s%u", i ? "," : "", data->server_attr->version[i]);
    }
    json_end_array(vers);

    // Populate the cryptosuites array
    json_start_array(cryptosuites, NULL);
    for (int i = 0; i < MAX_SUP_CSUITES; i++) {
        wpabuf_printf(cryptosuites, "%s%u", i ? "," : "", data->server_attr->cryptosuite[i]);
    }

    // Duplicate strings to output pointers
    *Vers = strndup(wpabuf_head(vers), wpabuf_len(vers));
    *Cryptosuites = strndup(wpabuf_head(cryptosuites), wpabuf_len(cryptosuites));
}

static void eap_noob_decode_vers_cryptosuites(struct eap_noob_peer_context * data,
        const char * Vers, const char * Cryptosuites)
{
    struct json_token * vers_obj = json_parse(Vers);
    struct json_token * cryptosuites_obj = json_parse(Cryptosuites);

    struct json_token * child = vers_obj->child;
    int i = 0;

    // Populate the version array
    while (child) {
        data->server_attr->version[i] = child->number;
        child = child->sibling;
        i++;
    }

    child = cryptosuites_obj->child;
    i = 0;
    
    // Populate the cryptosuite array
    while (child) {
        data->server_attr->cryptosuite[i] = child->number;
        child = child->sibling;
        i++;
    }
}


static void columns_persistentstate(struct eap_noob_peer_context * data, sqlite3_stmt * stmt)
{

    char * Vers, * Cryptosuites;
    data->server_attr->ssid = os_strdup((char *)sqlite3_column_text(stmt, 0));
    data->server_attr->PeerId = os_strdup((char *)sqlite3_column_text(stmt, 1));
    data->peer_attr->PeerId = os_strdup(data->server_attr->PeerId);
    Vers = os_strdup((char *)sqlite3_column_text(stmt, 2));
    Cryptosuites = os_strdup((char *)sqlite3_column_text(stmt, 3));
    data->server_attr->Realm = os_strdup((char *) sqlite3_column_text(stmt, 4));
    data->peer_attr->Realm = os_strdup(data->server_attr->Realm);
    data->peer_attr->Kz = os_memdup(sqlite3_column_blob(stmt,5), KZ_LEN);
    eap_noob_decode_vers_cryptosuites(data, Vers, Cryptosuites);
    data->server_attr->state = data->peer_attr->state = RECONNECTING_STATE;
}

static void columns_ephemeralstate(struct eap_noob_peer_context * data, sqlite3_stmt * stmt)
{
    char * Vers, * Cryptosuites;
    data->server_attr->ssid = os_strdup((char *)sqlite3_column_text(stmt, 0));
    data->server_attr->PeerId = os_strdup((char *) sqlite3_column_text(stmt, 1));
    data->peer_attr->PeerId = os_strdup(data->server_attr->PeerId);
    Vers = os_strdup((char *)sqlite3_column_text(stmt, 2));
    Cryptosuites = os_strdup((char *)sqlite3_column_text(stmt, 3));
    data->server_attr->Realm = os_strdup((char *) sqlite3_column_text(stmt, 4));
    data->peer_attr->Realm = os_strdup(data->server_attr->Realm);
    data->server_attr->dir = sqlite3_column_int(stmt, 5);
    data->server_attr->server_info = os_strdup((char *) sqlite3_column_text(stmt, 6));
    data->server_attr->kdf_nonce_data->Ns = os_memdup(sqlite3_column_blob(stmt, 7), NONCE_LEN);
    data->server_attr->kdf_nonce_data->Np = os_memdup(sqlite3_column_blob(stmt, 8), NONCE_LEN);
    data->server_attr->ecdh_exchange_data->shared_key = os_memdup(sqlite3_column_blob(stmt, 9), ECDH_SHARED_SECRET_LEN) ;
    data->server_attr->mac_input_str = os_strdup((char *) sqlite3_column_text(stmt, 10));
    //data->server_attr->creation_time = (uint64_t) sqlite3_column_int64(stmt, 11);
    data->server_attr->err_code = sqlite3_column_int(stmt, 12);
    data->server_attr->state = sqlite3_column_int(stmt, 13);
    eap_noob_decode_vers_cryptosuites(data, Vers, Cryptosuites);
}

static void columns_ephemeralnoob(struct eap_noob_peer_context * data, sqlite3_stmt * stmt)
{
    data->server_attr->ssid = os_strdup((char *)sqlite3_column_text(stmt, 0));
    data->server_attr->PeerId = os_strdup((char *) sqlite3_column_text(stmt, 1));
    data->peer_attr->PeerId = os_strdup(data->server_attr->PeerId);
    data->server_attr->oob_data->NoobId_b64 = os_strdup((char *)sqlite3_column_text(stmt, 2));
    data->server_attr->oob_data->Noob_b64 = os_strdup((char *)sqlite3_column_text(stmt, 3));
    data->server_attr->oob_data->Hoob_b64 = os_strdup((char *)sqlite3_column_text(stmt, 4));
    //sent time
}

/**
 * eap_noob_gen_MAC : generate an HMAC for user authentication.
 * @data : peer context
 * type  : MAC type
 * @key  : key to generate MAC
 * @keylen: key length
 * Returns : MAC on success or NULL on error.
 **/
static u8 * eap_noob_gen_MAC(const struct eap_noob_peer_context * data, int type, u8 * key, int keylen, int state)
{
    u8 * mac = NULL;
    struct wpabuf * mac_json;
    char * mac_str;
    char * nonce;

    // TODO: Verify that all required information exists

    // Allocate memory to the JSON string to be built
    mac_json = wpabuf_alloc(MAX_MAC_INPUT_LEN);
    if (!mac_json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for MAC JSON");
        return NULL;
    }

    // Build the MAC input string from all components as specified in draft 8 
    // https://tools.ietf.org/html/draft-ietf-emu-eap-noob-00 
    json_start_array(mac_json, NULL);

    // Integer to indicate whether this MAC is from the server or the peer
    if (type == MACS_TYPE) {
        wpabuf_printf(mac_json, "%u", 2);
    } else {
        wpabuf_printf(mac_json, "%u", 1);
    }

    // Versions supported by server
    json_value_sep(mac_json);
    json_start_array(mac_json, NULL);
    for (int i = 0; i < MAX_SUP_VER; i++) {
        wpabuf_printf(mac_json, "%s%u", i ? "," : "", data->server_attr->version[i]);
    }

    // Version chosen by peer
    wpabuf_printf(mac_json, ",%u", data->peer_attr->version);

    // PeerId assigned by the server to the peer
    wpabuf_printf(mac_json, ",\"%s\"", data->peer_attr->PeerId);

    // Cryptosuites supported by the server
    json_value_sep(mac_json);
    json_start_array(mac_json, NULL);
    for (int i = 0; i < MAX_SUP_CSUITES; i++) {
        wpabuf_printf(mac_json, "%s%u", i ? "," : "", data->server_attr->cryptosuite[i]);
    }

    // Direction supported by the server
    if (type == RECONNECT_EXCHANGE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%u", data->server_attr->dir);
    }

    // Server info object
    if (type == RECONNECT_EXCHANGE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->server_attr->server_info);
    }

    // Cryptosuite chosen by peer
    wpabuf_printf(mac_json, ",%u", data->peer_attr->cryptosuite);

    // Direction supported by the peer
    if (type == RECONNECT_EXCHANGE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%u", data->peer_attr->dir);
    }

    // If the Realm is specified, include it
    // Otherwise, insert an empty string
    if (data->server_attr->Realm) {
        wpabuf_printf(mac_json, ",\"%s\"", data->server_attr->Realm);
    } else {
        wpabuf_printf(mac_json, ",\"\"");
    }

    // Peer info object
    if (type == RECONNECT_EXCHANGE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->peer_attr->PeerInfo);
    }

    // KeyingMode
    if (type == RECONNECT_EXCHANGE) {
        // Include KeyingMode
    } else {
        wpabuf_printf(mac_json, ",0");
    }

    // Public key server
    if (type == RECONNECT_EXCHANGE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->server_attr->jwk_serv);
    }

    // Server nonce
    eap_noob_Base64Encode(data->server_attr->kdf_nonce_data->Ns, NONCE_LEN, &nonce);
    wpabuf_printf(mac_json, ",\"%s\"", nonce);

    // Public key peer
    if (type == RECONNECT_EXCHANGE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->server_attr->jwk_peer);
    }

    // Peer nonce
    eap_noob_Base64Encode(data->server_attr->kdf_nonce_data->Np, NONCE_LEN, &nonce);
    wpabuf_printf(mac_json, ",\"%s\"", nonce);
    
    // Nonce out of band
    if (type == RECONNECT_EXCHANGE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",\"%s\"", data->server_attr->oob_data->Noob_b64);
    }

    json_end_array(mac_json);

    // Dump to string
    data->server_attr->mac_input_str = strndup(wpabuf_head(mac_json), wpabuf_len(mac_json));
    if (!data->server_attr->mac_input_str) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to copy MAC input string");
        return NULL;
    }

    json_free(mac_json);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: In %s: MAC=%s, length=%d", __func__,
            data->server_attr->mac_input_str,
            (int) os_strlen(data->server_attr->mac_input_str));

    // Calculate MAC
    mac = HMAC(EVP_sha256(), key, keylen,
            (u8 *) data->server_attr->mac_input_str,
            os_strlen(data->server_attr->mac_input_str), NULL, NULL);

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Generated MAC", mac, MAC_LEN);

    return mac;
}

static int eap_noob_derive_secret(struct eap_noob_peer_context * data, size_t * secret_len)
{
    EVP_PKEY_CTX * ctx = NULL;
    EVP_PKEY * serverkey = NULL;
    unsigned char * server_pub_key  = NULL;
    size_t skeylen = 0, len = 0;
    int ret = SUCCESS;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);
    if (NULL == data || NULL == secret_len) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return FAILURE;
    }
    EAP_NOOB_FREE(data->server_attr->ecdh_exchange_data->shared_key);
    len = eap_noob_Base64Decode(data->server_attr->ecdh_exchange_data->x_serv_b64, &server_pub_key);
    if (len == 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode");
        ret = FAILURE; goto EXIT;
    }

    serverkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_pub_key, len);

    ctx = EVP_PKEY_CTX_new(data->server_attr->ecdh_exchange_data->dh_key, NULL);
    if (!ctx) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to create context");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to init key derivation");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive_set_peer(ctx, serverkey) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to set peer key");
        ret = FAILURE; goto EXIT;
    }	

    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get secret key len");
        ret = FAILURE; goto EXIT;
    }

    data->server_attr->ecdh_exchange_data->shared_key  = OPENSSL_malloc(skeylen);

    if (!data->server_attr->ecdh_exchange_data->shared_key) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for secret");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive(ctx, data->server_attr->ecdh_exchange_data->shared_key, &skeylen) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to derive secret key");
        ret = FAILURE; goto EXIT;
    }

    (*secret_len) = skeylen;

    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",
            data->server_attr->ecdh_exchange_data->shared_key, *secret_len);

EXIT:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    EAP_NOOB_FREE(server_pub_key);

    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->server_attr->ecdh_exchange_data->shared_key);

    return ret;
}

static int eap_noob_get_key(struct eap_noob_server_data * data)
{
    EVP_PKEY_CTX * pctx = NULL;
    BIO * mem_pub = BIO_new(BIO_s_mem());
    unsigned char * pub_key_char = NULL;
    size_t pub_key_len = 0;
    int ret = SUCCESS;


/*
	Uncomment this code for using the test vectors of Curve25519 in RFC	7748. 
	Peer = Bob
	Server = Alice
*/
    
	char * priv_key_test_vector = "MC4CAQAwBQYDK2VuBCIEIF2rCH5iSopLeeF/i4OADuZvO7EpJhi2/Rwviyf/iODr";
    BIO* b641 = BIO_new(BIO_f_base64());
    BIO* mem1 = BIO_new(BIO_s_mem());	
    BIO_set_flags(b641,BIO_FLAGS_BASE64_NO_NL);
    BIO_puts(mem1,priv_key_test_vector);
    mem1 = BIO_push(b641,mem1);
    

    wpa_printf(MSG_DEBUG, "EAP-NOOB: entering %s", __func__);

    /* Initialize context to generate keys - Curve25519 */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for parameter generation.");
        ret = FAILURE; goto EXIT;
    }

    EVP_PKEY_keygen_init(pctx);

    /* Generate X25519 key pair */       
    //EVP_PKEY_keygen(pctx, &data->ecdh_exchange_data->dh_key);

/* 
	If you are using the RFC 7748 test vector, you do not need to generate a key pair. Instead you use the
    private key from the RFC. In this case, comment out the line above and uncomment the following line 
    code
*/
    d2i_PrivateKey_bio(mem1,&data->ecdh_exchange_data->dh_key);
    
    PEM_write_PrivateKey(stdout, data->ecdh_exchange_data->dh_key,
                         NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(stdout, data->ecdh_exchange_data->dh_key);

    /* Get public key */
    if (1 != i2d_PUBKEY_bio(mem_pub, data->ecdh_exchange_data->dh_key)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to copy public key to bio.");
        ret = FAILURE; goto EXIT;
    }

    pub_key_char = os_zalloc(MAX_X25519_LEN);
    pub_key_len = BIO_read(mem_pub, pub_key_char, MAX_X25519_LEN);

/* 
 * This code removes the openssl internal ASN encoding and only keeps the 32 bytes of curve25519  
 * public key which is then encoded in the JWK format and sent to the other party. This code may
 * need to be updated when openssl changes its internal format for public-key encoded in PEM. 
*/
    unsigned char * pub_key_char_asn_removed = pub_key_char + (pub_key_len-32);
    pub_key_len = 32;

    EAP_NOOB_FREE(data->ecdh_exchange_data->x_b64);
    eap_noob_Base64Encode(pub_key_char_asn_removed, pub_key_len, &data->ecdh_exchange_data->x_b64);

EXIT:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    EAP_NOOB_FREE(pub_key_char);
    BIO_free_all(mem_pub);
    return ret;
}

/**
 * eap_noob_verify_param_len : verify lengths of string type parameters
 * @data : peer context
**/
static void eap_noob_verify_param_len(struct eap_noob_server_data * data)
{
    u32 count  = 0;
    u32 pos = 0x01;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }

    for(count  = 0; count < 32; count++) {

        if (data->rcvd_params & pos) {
            switch(pos) {

                case PEERID_RCVD:
                    if (strlen(data->PeerId) > MAX_PEER_ID_LEN) {
                        data->err_code = E1003;
                    }
                    break;
                case NONCE_RCVD:
                    if (strlen((char *)data->kdf_nonce_data->Ns) > NONCE_LEN) {
                        data->err_code = E1003;
                    }
                    break;
                case MAC_RCVD:
                    if (strlen(data->MAC) > MAC_LEN) {
                        data->err_code = E1003;
                    }
                    break;
                case INFO_RCVD:
                    if (strlen(data->server_info) > MAX_INFO_LEN) {
                        data->err_code = E5002;
                    }
                    break;
            }
        }
        pos = pos<<1;
    }
}


/**
 * Dump a json token to a string.
 * @json: output buffer to write the json string to
 * @token: the json_token to dump
 */
static void json_token_to_string(struct wpabuf * json, struct json_token * token) {
    struct json_token * sibling = token;
    int element_nr = 0;

    while (sibling) {
        // Insert a value separator when this is not the first element
        if (element_nr) {
            json_value_sep(json);
        }

        switch (sibling->type) {
            case JSON_OBJECT:
                json_start_object(json, sibling->name);
                json_token_to_string(json, sibling->child);
                json_end_object(json);
                break;
            case JSON_ARRAY:
                json_start_array(json, sibling->name);
                struct json_token * child = sibling->child;
                int i = 0;
                while (child) {
                    // Assume we are only dealing with arrays containing numbers or strings

                    /*if (child->type == JSON_OBJECT || child->type == JSON_ARRAY) {
                        struct wpabuf * child_json = wpabuf_alloc(wpabuf_size(json));
                        if (!child_json) continue;

                        json_token_to_string(child_json, child);
                        char * child_str = strndup(wpabuf_head(child_json), wpabuf_len(child_json));
                        printf("Generated child string: %s\n", child_str);

                        wpabuf_printf(json, "%s%s", i ? "," : "", child_str);

                        wpabuf_free(child_json);
                        os_free(child_str);
                    }*/
                    if (child->type == JSON_STRING) {
                        wpabuf_printf(json, "%s\"%s\"", i ? "," : "", child->string);
                    } else if (child->type == JSON_NUMBER) {
                        wpabuf_printf(json, "%s%u", i ? "," : "", child->number);
                    }

                    child = child->sibling;
                    i++;
                }
                json_end_array(json);
                break;
            case JSON_STRING:
                json_add_string(json, sibling->name, sibling->string);
                break;
            case JSON_NUMBER:
                json_add_int(json, sibling->name, sibling->number);
                break;
            default:
                ;
        }

        sibling = sibling->sibling;
        element_nr++;
    }
}

/**
 * Wrapper function that dumps a json_token to a string.
 * @token: the token to be dumped
 * Returns: a string representation of the token
 */
static char * json_dump(struct json_token * token) {
    struct wpabuf * dump = wpabuf_alloc(10000);
    if (!dump) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory in %s", __func__);
        return NULL;
    }

    json_token_to_string(dump, token);

    char * str = strndup(wpabuf_head(dump), wpabuf_len(dump));

    wpabuf_free(dump);

    return str;
}

/**
 * eap_noob_decode_obj : Decode parameters from incoming messages
 * @data : peer context
 * @root : incoming json object with message parameters
**/
static void eap_noob_decode_obj(struct eap_noob_server_data * data, struct json_token * root)
{
    struct json_token * child;
    char * key;
    struct json_token * el;

    if (!data || !root) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    if (root->type != JSON_OBJECT) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Request data does not have a JSON object as root");
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    // Loop over all children of the JSON root object
    child = root->child;
    while (child) {
        switch (child->type) {
            key = child->name;

            case JSON_OBJECT:
                // Pks or Pks2
                if (!os_strcmp(key, PKS) || !os_strcmp(key, PKS2)) {
                    data->ecdh_exchange_data->jwk_serv = json_dump(child);
                    if (!data->ecdh_exchange_data->jwk_serv) {
                        data->err_code = E1003;
                        goto EXIT;
                    }

                    data->rcvd_params |= PKEY_RCVD;
                }
                // ServerInfo
                else if (!os_strcmp(key, SERVERINFO)) {
                    struct wpabuf * str = wpabuf_alloc(MAX_INFO_LEN);
                    if (!str) {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for JSON object");
                        goto EXIT;
                    }

                    struct json_token * child_copy;
                    memcpy(&child_copy, &child, sizeof(child));
                    if (!child_copy) {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while copying json_token");
                        goto EXIT;
                    }

                    // Exclude name of the new root object from the JSON dump
                    child_copy->name = NULL;
                    json_token_to_string(str, child);

                    // Retrieve string
                    char * server_info = strndup(wpabuf_head(str), wpabuf_len(str));

                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Server info: %s", server_info);

                    data->server_info = server_info;

                    // Free intermediate variables
                    json_free(child_copy);
                    wpabuf_free(str);
                    
                    data->rcvd_params |= INFO_RCVD;
                }
                break;
            case JSON_ARRAY:
                // Vers
                if (!os_strcmp(key, VERS)) {
                    el = child->child;
                    int i = 0;

                    while (el) {
                        data->version[i] = el->number;
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Version array value = %d",
                                data->version[i]);
                        el = el->sibling;
                        i++;
                    }

                    data->rcvd_params |= VERSION_RCVD;
                }
                // Cryptosuites
                else if (!os_strcmp(key, CRYPTOSUITES)) {
                    el = child->child;
                    int i = 0;

                    while (el) {
                        data->cryptosuite[i] = el->number;
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Cryptosuites array value = %d",
                                data->cryptosuite[i]);
                        el = el->sibling;
                        i++;
                    }
                     data->rcvd_params |= CRYPTOSUITES_RCVD;
                }
                break;
            case JSON_STRING:
                const char * val = child->string;
                if (!val) {
                    data->err_code = E1003;
                    goto EXIT;
                }

                // PeerId
                if (!os_strcmp(key, PEERID)) {
                    data->PeerId = os_strdup(val);
                    data->rcvd_params |= PEERID_RCVD;
                }
                // Realm
                else if (!os_strcmp(key, REALM)) {
                    EAP_NOOB_FREE(data->Realm);
                    data->Realm = os_strdup(val);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Realm %s", data->Realm);
                }
                // Ns or Ns2
                else if (!os_strcmp(key, NS) || !os_strcmp(key, NS2)) {
                    size_t decode_len = eap_noob_Base64Decode(val, &data->kdf_nonce_data->Ns);
                    if (decode_len) {
                        data->rcvd_params |= NONCE_RCVD;
                    }
                }
                // NoobId
                else if (!os_strcmp(key, HINT_SERV)) {
                    data->oob_data->NoobId_b64 = os_strdup(val);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received NoobId = %s", data->oob_data->NoobId_b64);
                    data->rcvd_params |= HINT_RCVD;
                }
                // MACs or MACs2
                else if (!os_strcmp(key, MACS) || !os_strcmp(key, MACS2)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received MAC %s", val);
                    size_t decode_len = eap_noob_Base64Decode(val, &data->MAC);
                    data->rcvd_params |= MAC_RCVD;
                }
                // x
                else if (!os_strcmp(key, X_COORDINATE)) {
                    data->ecdh_exchange_data->x_serv_b64 = os_strdup(val);
                    wpa_printf(MSG_DEBUG, "X coordinate %s", data->ecdh_exchange_data->x_serv_b64);
                }
                // y
                else if (!os_strcmp(key, Y_COORDINATE)) {
                    data->ecdh_exchange_data->y_serv_b64 = os_strdup(val);
                    wpa_printf(MSG_DEBUG, "Y coordinate %s", data->ecdh_exchange_data->y_serv_b64);
                }
                break;
            case JSON_NUMBER:
                int val = child->number;
                if (!val && os_strcmp(key, TYPE) && os_strcmp(key, SLEEPTIME)) {
                    data->err_code = E1003;
                    goto EXIT;
                }
                // Dirs
                else if (!os_strcmp(key, DIRS)) {
                    data->dir = val;
                    data->rcvd_params |= DIRS_RCVD;
                }
                // SleepTime
                else if (!os_strcmp(key, SLEEPTIME)) {
                    data->minsleep = val;
                    //data->rcvd_params |= MINSLP_RCVD;
                }
                // ErrorCode
                else if (!os_strcmp(key, ERRORCODE)) {
                    data->err_code = val;
                }
                break;
            default:
                ;
        }

        // Done handling this child,
        // now update the reference to the next child of the JSON root object
        child = child->sibling;
    }

    eap_noob_verify_param_len(data);
EXIT:
    json_free(child);
    json_free(el);
    EAP_NOOB_FREE(key);
}

/**
 * eap_noob_assign_waittime : assign time fow which the SSID should be disabled.
 * @sm : eap state machine context
 * data: peer context
**/
static void eap_noob_assign_waittime(struct eap_sm * sm, struct eap_noob_peer_context * data)
{
    struct timespec tv;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    clock_gettime(CLOCK_BOOTTIME, &tv);
    if (0 == data->server_attr->minsleep && 0 != eap_noob_globle_conf.default_minsleep)
        data->server_attr->minsleep = eap_noob_globle_conf.default_minsleep;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Wait time  = %d", data->server_attr->minsleep);
    if (0 == os_strcmp(wpa_s->driver->name,"wired")) {
        sm->disabled_wired = tv.tv_sec + data->server_attr->minsleep;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: disabled untill = %ld", sm->disabled_wired);
        data->wired = 1; return;
    }

    sm->disabled_wired = 0;
    wpa_s->current_ssid->disabled_until.sec = tv.tv_sec + data->server_attr->minsleep;
    wpa_blacklist_add(wpa_s, wpa_s->current_ssid->bssid);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: SSID %s, time now : %ld  disabled untill = %ld", wpa_s->current_ssid->ssid, tv.tv_sec,
               wpa_s->current_ssid->disabled_until.sec);
}

/**
 * eap_noob_check_compatibility : check peer's compatibility with server.
 * The type 1 message params are used for making any dicision
 * @data : peer context
 * Returns : SUCCESS/FAILURE
 **/
int eap_noob_check_compatibility(struct eap_noob_peer_context *data)
{
    u32 count = 0;
    u8 vers_supported = 0;
    u8 csuite_supp = 0;

    if (0 == (data->peer_attr->dir & data->server_attr->dir)) {
        data->server_attr->err_code = E3003; return FAILURE;
    }

    for(count = 0; count < MAX_SUP_CSUITES ; count ++) {
        if (0 != (data->peer_attr->cryptosuite & data->server_attr->cryptosuite[count])) {
            csuite_supp = 1; break;
        }
    }

    if (csuite_supp == 0) {
        data->server_attr->err_code = E3002;
        return FAILURE;
    }

    for(count = 0; count < MAX_SUP_VER ; count ++) {
        if (0 != (data->peer_attr->version & data->server_attr->version[count])) {
            vers_supported = 1; break;
        }
    }

    if (vers_supported == 0) {
        data->server_attr->err_code = E3001; return FAILURE;
    }
    return SUCCESS;
}

/**
 * eap_noob_config_change : write back the content of identity into .conf file
 * @data : peer context
 * @sm : eap state machine context.
**/
static void eap_noob_config_change(struct eap_sm *sm , struct eap_noob_peer_context *data)
{
    char buff[120] = {0};
    size_t len = 0;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *)sm->msg_ctx;

    if (wpa_s) {
        snprintf(buff,120,"%s+s%d@%s", data->peer_attr->PeerId, data->server_attr->state, data->peer_attr->Realm);
        len = os_strlen(buff);

        os_free(wpa_s->current_ssid->eap.identity);
        wpa_s->current_ssid->eap.identity = os_malloc(os_strlen(buff));

        os_memcpy(wpa_s->current_ssid->eap.identity, buff, len);
        wpa_s->current_ssid->eap.identity_len = len;

        wpa_config_write(wpa_s->confname,wpa_s->conf);
    }
}

/**
 * eap_noob_db_entry_check : check for an PeerId entry inside the DB
 * @priv : server context
 * @argc : argument count
 * @argv : argument 2d array
 * @azColName : colomn name 2d array
**/
int eap_noob_db_entry_check(void * priv , int argc, char **argv, char **azColName)
{
    struct eap_noob_server_data * data = priv;

    if (strtol(argv[0],NULL,10) == 1) {
        data->record_present = TRUE;
    }
    return 0;
}

/**
 * eap_noob_exec_query : Function to execute a sql query. Prepapres, binds and steps.
 * Takes variable number of arguments (TYPE, VAL). For Blob, (TYPE, LEN, VAL)
 * @data : Server context
 * @query : query to be executed
 * @callback : pointer to callback function
 * @num_args : number of variable inputs to function
 * Returns  :  SUCCESS/FAILURE
 **/
static int eap_noob_exec_query(struct eap_noob_peer_context * data, const char * query,
                               void (*callback)(struct eap_noob_peer_context *, sqlite3_stmt *),
                               int num_args, ...)
{
    sqlite3_stmt * stmt = NULL;
    va_list args;
    int ret, i, indx = 0, ival, bval_len;
    char * sval = NULL;
    u8 * bval = NULL; u64 bival;
    int query_type=0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, query - (%s), Number of arguments (%d)", __func__, query, num_args);
    
    if(os_strstr(query,"SELECT"))
        query_type=1;

    if (SQLITE_OK != (ret = sqlite3_prepare_v2(data->peer_db, query, strlen(query)+1, &stmt, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error preparing statement, ret (%d)", ret);
        ret = FAILURE; goto EXIT;
    }

    va_start(args, num_args);

    for (i = 0; i < num_args; i+=2, ++indx) {
        enum sql_datatypes type = va_arg(args, enum sql_datatypes);
        switch(type) {
            case INT:
                ival = va_arg(args, int);
                printf("exec_query int %d, indx %d\n", ival, indx+1);
                if (SQLITE_OK != sqlite3_bind_int(stmt, (indx+1), ival)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %d at index %d", ival, i+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case UNSIGNED_BIG_INT:
                bival = va_arg(args, u64);
                if (SQLITE_OK != sqlite3_bind_int64(stmt, (indx+1), bival)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %lu at index %d", bival, i+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case TEXT:
                sval = va_arg(args, char *);
                printf("exec_query string %s, indx %d\n", sval, indx+1);
                if (SQLITE_OK != sqlite3_bind_text(stmt, (indx+1), sval, strlen(sval), NULL)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB:Error binding %s at index %d", sval, i+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case BLOB:
                bval_len = va_arg(args, int);
                bval = va_arg(args, u8 *);
                if (SQLITE_OK != sqlite3_bind_blob(stmt, (indx+1), (void *)bval, bval_len, NULL)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %.*s at index %d", bval_len, bval, indx+1);
                    ret = FAILURE; goto EXIT;
                } i++;
                break;
            default:
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Wrong data type");
                ret = FAILURE; goto EXIT;
        }
    }
    i=0;
    while(1) {
        ret = sqlite3_step(stmt);
        if (ret == SQLITE_DONE) {
            if(i==0 && query_type==1){
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Done executing SELECT query that returned 0 rows, ret (%d)\n", ret);
                ret = EMPTY; break;
            }
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Done executing the query, ret (%d)\n", ret);
            ret = SUCCESS; break;
        } else if (ret != SQLITE_ROW) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in step, ret (%d)", ret);
            ret = FAILURE; goto EXIT;
        }
        i++;
        if (NULL != callback) {
            callback(data, stmt);
        }
    }

EXIT:
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d", __func__, ret);
    if (ret == FAILURE) {
        char * sql_error = (char *)sqlite3_errmsg(data->peer_db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s\n", sql_error);
    }
    va_end(args);
    sqlite3_finalize(stmt);
    return ret;
}

/**
 * eap_noob_db_update : prepare a DB update query
 * @data : peer context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_db_update(struct eap_noob_peer_context * data, u8 type)
{
    char * query = os_zalloc(MAX_QUERY_LEN);
    int ret = FAILURE;

    switch(type) {
        case UPDATE_PERSISTENT_STATE:
            snprintf(query, MAX_QUERY_LEN, "UPDATE PersistentState SET PeerState=? where PeerID=?");
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->server_attr->state, TEXT, data->server_attr->PeerId);
            break;
        case UPDATE_STATE_ERROR:
            snprintf(query, MAX_QUERY_LEN, "UPDATE EphemeralState SET ErrorCode=? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->server_attr->err_code, TEXT, data->server_attr->PeerId);
            break;
        case DELETE_SSID:
            snprintf(query, MAX_QUERY_LEN, "DELETE FROM EphemeralState WHERE Ssid=?");
            ret = eap_noob_exec_query(data, query, NULL, 2, TEXT, data->server_attr->ssid);
            snprintf(query, MAX_QUERY_LEN, "DELETE FROM EphemeralNoob WHERE Ssid=?");
            ret = eap_noob_exec_query(data, query, NULL, 2, TEXT, data->server_attr->ssid);
            break;
        default:
            wpa_printf(MSG_ERROR, "EAP-NOOB: Wrong DB update type");
            return FAILURE;
    }
    if (FAILURE == ret) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB update failed");
    }

    os_free(query);
    return ret;
}

/**
 * eap_noob_db_entry : Make an entery of the current SSID context inside the DB
 * @sm : eap statemachine context
 * @data : peer context
 * Returns : FAILURE/SUCCESS
**/
static int eap_noob_db_update_initial_exchange_info(struct eap_sm * sm, struct eap_noob_peer_context * data)
{
    struct wpa_supplicant * wpa_s = NULL;
    char query[MAX_QUERY_LEN] = {0}, * Vers, * Cryptosuites;
    int ret = 0, err = 0;

    if (NULL == data || NULL == sm) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__); return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);
    wpa_s = (struct wpa_supplicant *)sm->msg_ctx;
    err -= (FAILURE == eap_noob_encode_vers_cryptosuites(data, &Vers, &Cryptosuites));
    //err -= (NULL == (data->server_attr->mac_input_str = json_dumps(data->server_attr->mac_input, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (data->server_attr->mac_input)
        wpa_printf(MSG_DEBUG, "EAP-NOOB: MAC str %s", data->server_attr->mac_input_str);
    if (err < 0) { ret = FAILURE; goto EXIT; }

    snprintf(query, MAX_QUERY_LEN,"INSERT INTO EphemeralState (Ssid, PeerId, Vers, Cryptosuites, Realm, Dirs, "
            "ServerInfo, Ns, Np, Z, MacInput, PeerState) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    ret = eap_noob_exec_query(data, query, NULL, 27, TEXT, wpa_s->current_ssid->ssid, TEXT, data->server_attr->PeerId,
            TEXT,  Vers_str, TEXT, Cryptosuites_str, TEXT, data->server_attr->Realm, INT, data->server_attr->dir,
            TEXT, data->server_attr->server_info, BLOB, NONCE_LEN, data->server_attr->kdf_nonce_data->Ns, BLOB,
            NONCE_LEN, data->server_attr->kdf_nonce_data->Np, BLOB, ECDH_SHARED_SECRET_LEN,
            data->server_attr->ecdh_exchange_data->shared_key, TEXT, data->server_attr->mac_input_str, INT,
            data->server_attr->state);

    if (FAILURE == ret) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
    }
EXIT:
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
    EAP_NOOB_FREE(Vers); EAP_NOOB_FREE(Cryptosuites);
    return ret;
}

static int eap_noob_update_persistentstate(struct eap_noob_peer_context * data)
{
    char query[MAX_QUERY_LEN] = {0}, * Vers, * Cryptosuites;
    int ret = SUCCESS, err = 0;

    if (NULL == data) { wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__); return FAILURE; }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

    err -= (FAILURE == eap_noob_db_statements(data->peer_db, DELETE_EPHEMERAL_FOR_ALL));
    err -= (FAILURE == eap_noob_encode_vers_cryptosuites(data, &Vers, &Cryptosuites));
    if (err < 0) { ret = FAILURE; goto EXIT; }
    /* snprintf(query, MAX_QUERY_LEN, "INSERT INTO PersistentState (Ssid, PeerId, Vers, Cryptosuites, Realm, Kz, "
        "creation_time, last_used_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"); */
    snprintf(query, MAX_QUERY_LEN, "INSERT INTO PersistentState (Ssid, PeerId, Vers, Cryptosuites, Realm, Kz, PeerState) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)");

    if(data->server_attr->kdf_out->Kz){
    	 wpa_printf(MSG_DEBUG, "NOT NULL and state %d",data->server_attr->state);
    	 wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KZ is", data->server_attr->kdf_out->Kz, KZ_LEN);}
    else
    	 wpa_printf(MSG_DEBUG, "Kz is somehow null and state %d", data->server_attr->state);

   

    err -= (FAILURE == eap_noob_exec_query(data, query, NULL, 15, TEXT, data->server_attr->ssid, TEXT, data->server_attr->PeerId,
            TEXT, Vers_str, TEXT, Cryptosuites_str, TEXT, data->server_attr->Realm, BLOB, KZ_LEN, data->server_attr->kdf_out->Kz,
            INT, data->server_attr->state));
    if (err < 0) { ret = FAILURE; goto EXIT; }
EXIT:
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, return %d",__func__, ret);
    EAP_NOOB_FREE(Vers); EAP_NOOB_FREE(Cryptosuites);
    return ret;
}

/**
 * eap_noob_err_msg : prepares error message
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_err_msg(struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(ERRORCODE) + strlen(ERRORINFO);
    size_t code = 0;

    if (!data || !data->peer_attr || !(code = data->server_attr->err_code)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is NULL", __func__);
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Build error message");

    len += strlen(error_info[code]);

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, NONE);
    json_value_sep(json);
    if (data->peer_attr->PeerId) {
        json_add_string(json, PEERID, data->peer_attr->PeerId);
        json_value_sep(json);
    }
    json_add_int(json, ERRORCODE, error_code[code]);
    json_value_sep(json);
    json_add_string(json, ERRORINFO, error_info[code]);
    json_end_object(json);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for error message response");
        goto EXIT;
    }

    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    return resp;
}

/**
 * eap_noob_verify_PeerId : compares recived PeerId with the assigned one
 * @data : peer context
 * @id : response message ID
**/
static struct wpabuf * eap_noob_verify_PeerId(struct eap_noob_peer_context * data, u8  id)
{
    if ((data->server_attr->PeerId) && (data->peer_attr->PeerId) &&
        (0 != os_strcmp(data->peer_attr->PeerId, data->server_attr->PeerId))) {
        data->server_attr->err_code = E2004;
        return eap_noob_err_msg(data, id);
    }
    return NULL;
}

/**
 * eap_noob_rsp_type_four : prepares message type four
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_four(const struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN + strlen(MACP) + MAC_LEN;
    char * mac_b64 = NULL;
    u8 * mac = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    mac = eap_noob_gen_MAC(data, MACP_TYPE, data->server_attr->kdf_out->Kmp,
            KMP_LEN, COMPLETION_EXCHANGE);
    if (!mac) {
        goto EXIT;
    }

    if (FAILURE == eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64)) {
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_4);
    json_value_sep(json);
    json_add_string(json, PEERID, data->server_attr->PeerId);
    json_value_sep(json);
    json_add_string(json, MACP, mac_b64);
    json_end_object(json);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Completion Response");
        goto EXIT;
    }

    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(mac_b64);
    return resp;
}

/**
 * eap_noob_rsp_type_three : prepares message type three
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_three(const struct eap_noob_peer_context *data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 3");
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_9);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_end_object(json);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Response/NOOB-WE");
        goto EXIT;
    }
    
    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    return resp;
}

/**
 *  eap_noob_build_JWK : Builds a JWK object to send in the inband message
 *  @jwk : output json object
 *  @x_64 : x co-ordinate in base64url format
 *  @y_64 : y co-ordinate in base64url format
 *  Returns : FAILURE/SUCCESS
**/
static int eap_noob_build_JWK(char ** jwk, const char * x_b64)
{
    struct wpabuf * json;
    size_t len = 500; 

    if (!x_b64) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: X-coordinate is NULL when building JWK");
        return FAILURE;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory while building JWK");
        return FAILURE;
    }

    json_start_object(json, NULL);
    json_add_string(json, KEY_TYPE, "EC");
    json_value_sep(json);
    json_add_string(json, CURVE, "Curve25519");
    json_value_sep(json);
    json_add_string(json, X_COORDINATE, x_b64);

    *jwk = strndup(wpabuf_head(json), wpabuf_len(json));
    if (!*jwk) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to copy JWK");
        wpabuf_free(json);
        return FAILURE;
    }

    wpabuf_free(json);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: JWK key is %s", *jwk);

    return SUCCESS;
}

/**
 * eap_noob_rsp_type_two : prepares message type two
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_two(struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(PKP) + 500 + strlen(NP) + NONCE_LEN * 1.5;
    size_t secret_len = ECDH_SHARED_SECRET_LEN;
    char * Np_b64;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    // Generate peer nonce
    data->server_attr->kdf_nonce_data->Np = os_zalloc(NONCE_LEN);
    int rc = RAND_bytes(data->server_attr->kdf_nonce_data->Np, NONCE_LEN);
    unsigned long error = ERR_get_error();
    if (rc != 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. Error=%lu", error);
        os_free(data->server_attr->kdf_nonce_data->Np);
        goto EXIT;
    }

    // Encode the nonce in base 64
    eap_noob_Base64Encode(data->server_attr->kdf_nonce_data->Np, NONCE_LEN, &Np_b64);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Nonce %s", Np_b64);

    // Generate key material
    if (eap_noob_get_key(data->server_attr) == FAILURE) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
        goto EXIT;
    }

    // Build JWK to represent peer
    if (eap_noob_build_JWK(&data->server_attr->ecdh_exchange_data->jwk_peer,
                data->server_attr->ecdh_exchange_data->x_b64)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to build JWK in response type 2");
        goto EXIT;
    }

    // Derive shared secret and encode in base 64
    eap_noob_derive_secret(data, &secret_len);
    data->server_attr->ecdh_exchange_data->shared_key_b64_len = eap_noob_Base64Encode(
                data->server_attr->ecdh_exchange_data->shared_key,
                ECDH_SHARED_SECRET_LEN,
                &data->server_attr->ecdh_exchange_data->shared_key_b64
            );

    // Create JSON EAP message

    json = wpabuf_alloc(len);
    if (!json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for json response");
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_2);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    json_add_string(json, PKP, data->server_attr->ecdh_exchange_data->jwk_peer);
    json_value_sep(json);
    json_add_string(json, NP, Np_b64);
    json_end_object(json);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Response/NOOB-IE");
        goto EXIT;
    }

    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(Np_b64);
    return resp;
}

/**
 * eap_noob_rsp_type_one : prepares message type one
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_one(struct eap_sm *sm,const struct eap_noob_peer_context *data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(VERP) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(CRYPTOSUITEP) + strlen(DIRP) + strlen(PEERINFO) + MAX_INFO_LEN;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Building message response type 1");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_1);
    json_value_sep(json);
    json_add_int(json, VERP, data->peer_attr->version);
    json_value_sep(json);
    json_add_string(json, PEERID, data->server_attr->Peerid);
    json_value_sep(json);
    json_add_int(json, CRYPTOSUITEP, data->peer_attr->cryptosuite);
    json_value_sep(json);
    json_add_int(json, DIRP, data->peer_attr->dir);
    json_value_sep(json);
    json_add_string(json, PEERINFO, data->peer_attr->PeerInfo);
    json_end_object(json);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Response/NOOB-IE");
        goto EXIT;
    }

    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    return resp;
}

/**
 * eap_noob_rsp_type_eight : prepares message type eight
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_eight(const struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(HINT_PEER) + NOOBID_LEN;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Building message response type 8");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_HINT);
    json_value_sep(json);
    json_add_string(json, PEERID, data->server_attr->PeerId);
    json_value_sep(json);
    json_add_string(json, HINT_PEER, data->server_attr->oob_data->NoobId_b64);
    json_end_object(json);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Hint is %s", data->server_attr->oob_data->NoobId_b64);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for NoobId hint response");
        goto EXIT;
    }

    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    return resp;
}

/**
 * Prepare peer response to common handshake
 * @data   : peer context
 * @id     : response message id
 * Returns : pointer to message buffer containing json response as string
 */ 
static struct wpabuf * eap_noob_rsp_type_nine(const struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN + strlen(PEERSTATE);
    
    if (!data) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }
	
    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }
    
    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_9);
    json_value_sep(json);
    
    // Only include PeerId if peer is not in Unregistered state (0)
    if (data->server_attr->state != UNREGISTERED_STATE) {
        json_add_string(json, PEERID, data->server_attr->PeerId);
        json_value_sep(json);
    }
    
    json_add_int(json, PEERSTATE, data->server_attr->state);
    json_end_object(json);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for handshake response");
        goto EXIT;
    }

    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    return resp;
}

/**
 * eap_noob_rsp_type_five : prepares message type file
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_five(struct eap_sm *sm,const struct eap_noob_peer_context *data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(VERP) + strlen(PEERID) + MAX_PEER_ID_LEN + strlen(CRYPTOSUITEP)
        + strlen(PEERINFO) + MAX_INFO_LEN;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, VERP, data->peer_attr->version);
    json_value_sep(json);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_5);
    json_value_sep(json);
    json_add_string(json, PEERID, data->server_attr->PeerId);
    json_value_sep(json);
    json_add_int(json, CRYPTOSUITEP, data->peer_attr->cryptosuite);
    json_value_sep(json);

    // Helper method to add JSON object to the wpabuf
    eap_noob_prepare_peer_info_json(sm, data, json, PEERINFO);
    json_end_object(json);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Reconnect Exchange Response");
        goto EXIT;
    }

    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    return resp;
}

/**
 * To-Do Based on the cryptosuite and server request decide whether new key has to be derived or not
 * eap_noob_rsp_type_six : prepares message type six
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_six(struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(NP) + NONCE_LEN * 1.5;
    char * Np_b64;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    // Generate peer nonce
    data->server_attr->kdf_nonce_data->Np = os_zalloc(NONCE_LEN);
    int rc = RAND_bytes(data->server_attr->kdf_nonce_data->Np, NONCE_LEN);
    unsigned long error = ERR_get_error();
    if (rc != SUCCESS) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. Error=%lu", error);
        os_free(data->server_attr->kdf_nonce_data->Np);
        goto EXIT;
    }

    // Encode the nonce in base 64
    eap_noob_Base64Encode(data->server_attr->kdf_nonce_data->Np, NONCE_LEN, &Np_b64);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Nonce %s", Np_b64);

    // Create JSON EAP message

    json = wpabuf_alloc(len);
    if (!json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for json response");
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_6);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    json_add_string(json, NP2, Np_b64);
    json_end_object(json);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Response/RE");
        goto EXIT;
    }

    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(Np_b64);
    return resp;
}

/**
 * eap_noob_rsp_type_seven : prepares message type seven
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_seven(const struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    size_t len = 100 + strlen(TYPE), strlen(PEERID) + MAX_PEER_ID_LEN + strlen(MACP2) + MAC_LEN;
    u8 * mac = NULL;
    char * mac_b64 = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 7");

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    // Generate the MAC
    mac = eap_noob_gen_MAC(data, MACP_TYPE, data->server_attr->kdf_out->Kmp, KMP_LEN, RECONNECT_EXCHANGE);
    if (!mac) {
        goto EXIT;
    }

    // Convert MAC to base 64
    if (FAILURE == eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64)) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_7);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    json_add_string(json, MACP2, mac_b64);
    json_end_object(json);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Response/NOOB-RE");
        goto EXIT;
    }

    wpabuf_put_buf(resp, json);
EXIT:
    wpabuf_free(json);
    return resp;
}

/**
 * eap_noob_req_type_seven :  Decodes request type seven
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_seven(struct eap_sm * sm, json_t * req_obj, struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * resp = NULL;
    u8 * mac = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__); return NULL;
    }
    eap_noob_decode_obj(data->server_attr, req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id); return resp;
    }
    if (data->server_attr->rcvd_params != TYPE_SEVEN_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }
    data->server_attr->rcvd_params = 0;
    if (NULL != (resp = eap_noob_verify_PeerId(data,id))) return resp;
    
    /* Generate KDF and MAC */
    if (SUCCESS != eap_noob_gen_KDF(data,RECONNECT_EXCHANGE)) {
    	wpa_printf(MSG_ERROR, "EAP-NOOB: Error in KDF during Request/NOOB-FR"); return NULL;
    }
    mac = eap_noob_gen_MAC(data, MACS_TYPE, data->server_attr->kdf_out->Kms, KMS_LEN, RECONNECT_EXCHANGE);
    if (NULL == mac) return NULL;

    if (0 != strcmp((char *)mac,data->server_attr->MAC)) {
        data->server_attr->err_code = E4001;
        resp = eap_noob_err_msg(data, id); return resp;
    }

    resp = eap_noob_rsp_type_seven(data, id);
    data->server_attr->state = REGISTERED_STATE;
    eap_noob_config_change(sm, data);

    if (FAILURE == eap_noob_db_update(data, UPDATE_PERSISTENT_STATE)) {
        os_free(resp); return NULL;
    }
    return resp;
}

/**
 * eap_noob_req_type_six :  Decodes request type six
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_six(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context *data, u8 id)
{
    struct wpabuf * resp = NULL;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 6");

    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_SIX_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (NULL == (resp = eap_noob_verify_PeerId(data,id))) {
        resp = eap_noob_rsp_type_six(data,id);
    }

    data->server_attr->rcvd_params = 0;
    return resp;
}

/**
 * eap_noob_req_type_five :  Decodes request type five
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_five(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * resp = NULL;
    int err = 0;
    json_t * macinput = NULL, * Vers = NULL, * Cryptosuites = NULL, * emptystr = json_string("");
    json_error_t error;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 5");
    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id); return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_FIVE_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }
    data->peer_attr->PeerId = os_strdup(data->server_attr->PeerId);
    //TODO: handle eap_noob failure scenario
    if (SUCCESS == eap_noob_check_compatibility(data))
        resp = eap_noob_rsp_type_five(sm,data, id);
    else
        resp = eap_noob_err_msg(data,id);

    err -= (NULL == (Vers = json_array()));
    for (int i = 0; i < MAX_SUP_VER; ++i)
        err += json_array_append_new(Vers, json_integer(data->server_attr->version[i]));
    err -= (NULL == (Cryptosuites = json_array()));
    for (int i = 0; i < MAX_SUP_CSUITES ; i++)
        err += json_array_append_new(Cryptosuites, json_integer(data->server_attr->cryptosuite[i]));
    err -= (NULL == (macinput = json_array()));
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, Vers);
    err += json_array_append_new(macinput, json_integer(data->peer_attr->version));
    err += json_array_append_new(macinput, json_string(data->server_attr->PeerId));
    err += json_array_append(macinput, Cryptosuites);
    err += json_array_append(macinput, emptystr);
    err += json_array_append_new(macinput, json_loads(data->server_attr->server_info, JSON_COMPACT|JSON_PRESERVE_ORDER, &error));
    err += json_array_append_new(macinput, json_integer(data->peer_attr->cryptosuite));
    err += json_array_append(macinput, emptystr);
    err += json_array_append_new(macinput, json_string(data->server_attr->Realm));
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    data->server_attr->mac_input = macinput;
    if (err < 0) wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected JSON processing error when creating mac input template.");

    data->server_attr->rcvd_params = 0;
    json_decref(Vers); json_decref(Cryptosuites); json_decref(emptystr);
    return resp;
}

static int eap_noob_exec_noobid_queries(struct eap_noob_peer_context * data)
{
    char query[MAX_QUERY_LEN] = {0};
    snprintf(query, MAX_QUERY_LEN, "SELECT * from EphemeralNoob WHERE PeerId = ? AND NoobId = ?;");
    return eap_noob_exec_query(data, query, columns_ephemeralnoob, 4, TEXT, data->server_attr->PeerId, TEXT,
        data->server_attr->oob_data->NoobId_b64);
}

/**
 * eap_noob_req_type_four :  Decodes request type four
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_four(struct eap_sm * sm, json_t * req_obj, struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * resp = NULL;
    u8 * mac = NULL;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    eap_noob_decode_obj(data->server_attr, req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id); return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_FOUR_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }
    data->server_attr->rcvd_params = 0;
    /* Execute Hint query in peer to server direction */
    if (data->peer_attr->dir == PEER_TO_SERV){
       int ret = eap_noob_exec_noobid_queries(data);
       if(ret == FAILURE || ret == EMPTY){ 
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Unrecognized NoobId");
        data->server_attr->err_code = E2003;
        resp = eap_noob_err_msg(data,id); 
        return resp;
       }
    }
    /* generate Keys */
    if (SUCCESS != eap_noob_gen_KDF(data, COMPLETION_EXCHANGE)) {
    	wpa_printf(MSG_ERROR, "EAP-NOOB: Error in KDF during Request/NOOB-CE"); return NULL;
    }
    if (NULL != (resp = eap_noob_verify_PeerId(data, id))) return resp;

    mac = eap_noob_gen_MAC(data, MACS_TYPE, data->server_attr->kdf_out->Kms, KMS_LEN, COMPLETION_EXCHANGE);
    if (NULL == mac) { os_free(resp); return NULL; }

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MAC received ", data->server_attr->MAC, 32);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MAC calculated ", mac, 32);
    if (0 != os_memcmp(mac, data->server_attr->MAC, MAC_LEN)) {
        data->server_attr->err_code = E4001;
        resp = eap_noob_err_msg(data,id); return resp;
    }

    resp = eap_noob_rsp_type_four(data, id);
    data->server_attr->state = REGISTERED_STATE;
    eap_noob_config_change(sm, data);
    if (resp == NULL) wpa_printf(MSG_DEBUG, "EAP-NOOB: Null resp 4");

    if (FAILURE == eap_noob_update_persistentstate(data)) {
        os_free(resp); return NULL;
    }
    wpa_printf(MSG_DEBUG,"PEER ID IS STILL: %s",data->peer_attr->PeerId);
    return resp;
}

/**
 * eap_noob_req_type_three :  Decodes request type three
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_three(struct eap_sm * sm, json_t * req_obj, struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * resp = NULL;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__); return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id); return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_THREE_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }

    if (NULL == (resp = eap_noob_verify_PeerId(data,id))) {
        resp = eap_noob_rsp_type_three(data,id);
        if (0 != data->server_attr->minsleep) eap_noob_assign_waittime(sm,data);
    }

    return resp;
}

/**
 * eap_noob_req_type_two :  Decodes request type two
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id : pointer to response message buffer or null
**/
static struct wpabuf * eap_noob_req_type_two(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf *resp = NULL;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "Entering %s", __func__);
    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data, id); return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_TWO_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }

    if (NULL == (resp = eap_noob_verify_PeerId(data,id))) {
        resp = eap_noob_rsp_type_two(data,id);
        data->server_attr->state = WAITING_FOR_OOB_STATE;
        if (SUCCESS == eap_noob_db_update_initial_exchange_info(sm, data)) eap_noob_config_change(sm, data);
    }
    if (0!= data->server_attr->minsleep)
        eap_noob_assign_waittime(sm,data);

    return resp;
}

/**
 * eap_noob_req_type_one :  Decodes request type one
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_one(struct eap_sm * sm, json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * resp = NULL;
    char * url = NULL;
    char url_cpy[2 * MAX_URL_LEN] = {0};
    int err = 0;
    json_t * macinput = NULL, * Vers = NULL, * Cryptosuites = NULL, * emptystr = json_string("");
    json_error_t error;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id); return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_ONE_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }

    /* checks on the received URL */
    if ( NULL == (url = os_strstr(data->server_attr->server_info, "https://"))) {
        data->server_attr->err_code = E5003;
        resp = eap_noob_err_msg(data,id); return resp;
    }
    strcpy(url_cpy,url);
    url_cpy[strlen(url_cpy)-2] = '\0';

    if (NULL == url || strlen(url_cpy) > MAX_URL_LEN ) {
        data->server_attr->err_code = E5003;
        resp = eap_noob_err_msg(data,id); return resp;
    }

    data->peer_attr->PeerId = os_strdup(data->server_attr->PeerId);
    if (NULL != data->server_attr->Realm && strlen(data->server_attr->Realm) > 0) {
//If the server sent a realm, then add it to the peer attr
        data->peer_attr->Realm = os_strdup(data->server_attr->Realm);
    } else {
        data->peer_attr->Realm = os_strdup(DEFAULT_REALM);
        data->server_attr->Realm = os_strdup("");
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Realm %s", data->server_attr->Realm);

    if (SUCCESS == eap_noob_check_compatibility(data)) {
        resp = eap_noob_rsp_type_one(sm,data, id);
    } else resp = eap_noob_err_msg(data,id);

    /* Create MAC imput template */
    /* 1/2,Vers,Verp,PeerId,Cryptosuites,Dirs,ServerInfo,Cryptosuitep,Dirp,[Realm],PeerInfo,PKs,Ns,PKp,Np,Noob */
    err -= (NULL == (Vers = json_array()));
    for (int i = 0; i < MAX_SUP_VER; ++i)
        err += json_array_append_new(Vers, json_integer(data->server_attr->version[i]));
    err -= (NULL == (Cryptosuites = json_array()));
    for (int i = 0; i < MAX_SUP_CSUITES ; i++)
        err += json_array_append_new(Cryptosuites, json_integer(data->server_attr->cryptosuite[i]));
    
    err -= (NULL == (macinput = json_array()));
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, Vers);
    err += json_array_append_new(macinput, json_integer(data->peer_attr->version));
    err += json_array_append_new(macinput, json_string(data->server_attr->PeerId));
    err += json_array_append(macinput, Cryptosuites);
    err += json_array_append_new(macinput, json_integer(data->server_attr->dir));
    err += json_array_append_new(macinput, json_loads(data->server_attr->server_info, JSON_COMPACT|JSON_PRESERVE_ORDER, &error));
    err += json_array_append_new(macinput, json_integer(data->peer_attr->cryptosuite));
    err += json_array_append_new(macinput, json_integer(data->peer_attr->dir));
//  If no realm is assinged, use empty string for mac calculation
    if (os_strlen(data->server_attr->Realm)>0)
        err += json_array_append_new(macinput, json_string(data->server_attr->Realm));
    else
        err += json_array_append_new(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    data->server_attr->mac_input = macinput;
    if (err < 0) wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected JSON processing error when creating mac input template.");
    data->server_attr->rcvd_params = 0;
    json_decref(Vers); json_decref(Cryptosuites); json_decref(emptystr);
    return resp;
}


static struct wpabuf * eap_noob_req_type_eight(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf *resp = NULL;

    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_HINT_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (NULL == (resp = eap_noob_verify_PeerId(data,id))) {
        resp = eap_noob_rsp_type_eight(data,id);
    }
    return resp;
}

static struct wpabuf * eap_noob_req_type_nine(struct eap_sm * sm, json_t * req_obj, struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf *resp = NULL;

    // Message of type 9 from server does not contain any information,
    // thus the request object does not need to be parsed.
    
    resp = eap_noob_rsp_type_nine(data, id);
    
    return resp;
}

/**
 * eap_noob_req_err_handling :  handle received error message
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static void eap_noob_req_err_handling(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    if (!data->server_attr->err_code) {
        eap_noob_db_update(data, UPDATE_STATE_ERROR);
    }
}

/**
 * eap_noob_process :  Process recieved message
 * @eap_sm : eap statemachine context
 * @priv : peer context
 * @ret : eap method data
 * @reqData : received request message objecti
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process(struct eap_sm * sm, void * priv, struct eap_method_ret *ret,
                                        const struct wpabuf * reqData)
{
    struct eap_noob_peer_context * data = priv;
    struct wpabuf * resp = NULL;
    const u8 * pos;
    size_t len;
    json_t * req_obj = NULL;
    json_t * req_type = NULL;
    json_error_t error;
    int msgtype;
    u8 id =0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, reqData, &len);
    if (pos == NULL || len < 1) {
        ret->ignore = TRUE;
        return NULL;
    }
 /**
 * https://tools.ietf.org/html/rfc4137 Not dropping packets if header is valid. 
 * Consider using this for Error messages received when not expected. 
**/   
    ret->ignore = FALSE;

    ret->methodState = METHOD_CONT;
    ret->decision = DECISION_FAIL;

  /**
 * https://tools.ietf.org/html/rfc3748 EAP-NOOB does not use 
 * or handle EAP Notificiation type messages.  
**/      
    ret->allowNotifications = FALSE;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received Request = %s", pos);
    req_obj = json_loads((char *)pos, JSON_COMPACT, &error);
    id = eap_get_id(reqData);

    if ((NULL != req_obj) && (json_is_object(req_obj) > 0)) {
        req_type = json_object_get(req_obj,TYPE);

        if ((NULL != req_type) && (json_is_integer(req_type) > 0)) {
            msgtype = json_integer_value(req_type);
        } else {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown type received");
            data->server_attr->err_code = E1003;
            resp = eap_noob_err_msg(data,id);
            goto EXIT;
        }
    } else {
        data->server_attr->err_code = E1003;
        resp = eap_noob_err_msg(data,id);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown format received");
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: State :%d, message type = %d",data->server_attr->state, msgtype);
    if (VALID != state_message_check[data->server_attr->state][msgtype]) {
        data->server_attr->err_code = E2002;
        resp = eap_noob_err_msg(data, id);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: State mismatch"); goto EXIT;
    } else if ((data->server_attr->state == WAITING_FOR_OOB_STATE || data->server_attr->state == OOB_RECEIVED_STATE) &&
                msgtype == EAP_NOOB_TYPE_1) {
        if (FAILURE == eap_noob_db_update(data, DELETE_SSID)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to delete SSID"); goto EXIT;
        }
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Deleted SSID");
    }

    switch(msgtype) {
        case NONE:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error message received");
            eap_noob_req_err_handling(sm,req_obj,data, id);
            break;
        case EAP_NOOB_TYPE_1:
            resp = eap_noob_req_type_one(sm,req_obj ,data,id);
            break;
        case EAP_NOOB_TYPE_2:
            resp = eap_noob_req_type_two(sm,req_obj ,data, id);
            break;
        case EAP_NOOB_TYPE_3:
            resp = eap_noob_req_type_three(sm,req_obj ,data, id);
            break;
        case EAP_NOOB_TYPE_4:
            resp = eap_noob_req_type_four(sm,req_obj ,data, id);
            if(data->server_attr->err_code == NO_ERROR) {
                ret->methodState = METHOD_MAY_CONT;
                ret->decision = DECISION_COND_SUCC;
            }
            break;
        case EAP_NOOB_TYPE_5:
            resp = eap_noob_req_type_five(sm, req_obj, data, id);
            break;
        case EAP_NOOB_TYPE_6:
            resp = eap_noob_req_type_six(sm, req_obj, data, id);
            break;
        case EAP_NOOB_TYPE_7:
            resp = eap_noob_req_type_seven(sm, req_obj, data, id);
            if(data->server_attr->err_code == NO_ERROR) {
                ret->methodState = METHOD_MAY_CONT;
                ret->decision = DECISION_COND_SUCC;
            }
            break;
        case EAP_NOOB_HINT:
            resp = eap_noob_req_type_eight(sm, req_obj, data, id);
            break;
        case EAP_NOOB_TYPE_9:
            resp = eap_noob_req_type_nine(sm, req_obj, data, id);
            break;
        default:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unknown EAP-NOOB request received");
            break;
    }
EXIT:
    data->server_attr->err_code = NO_ERROR;
    if (req_type)
        json_decref(req_type);
    else if (req_obj)
        json_decref(req_obj);
    return resp;
}

/**
 * eap_noob_free_ctx : free all the allocations from peer context
 * @data : peer context
 *
**/
static void eap_noob_free_ctx(struct eap_noob_peer_context * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }
    struct eap_noob_peer_data * peer = data->peer_attr;
    struct eap_noob_server_data * serv = data->server_attr;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    if (serv) {
        wpa_printf(MSG_DEBUG, "EAP_NOOB: Clearing server data");
        EAP_NOOB_FREE(serv->server_info);
        EAP_NOOB_FREE(serv->MAC);
        EAP_NOOB_FREE(serv->ssid);
        EAP_NOOB_FREE(serv->PeerId);
        EAP_NOOB_FREE(serv->Realm);
        json_decref(serv->mac_input);
        EAP_NOOB_FREE(serv->mac_input_str);

        if (serv->ecdh_exchange_data) {
            EVP_PKEY_free(serv->ecdh_exchange_data->dh_key);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->x_serv_b64);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->y_serv_b64);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->x_b64);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->y_b64);
            json_decref(serv->ecdh_exchange_data->jwk_serv);
            json_decref(serv->ecdh_exchange_data->jwk_peer);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->shared_key);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->shared_key_b64);
            os_free(serv->ecdh_exchange_data);
        }
        if (serv->oob_data) {
            EAP_NOOB_FREE(serv->oob_data->Noob_b64);
            EAP_NOOB_FREE(serv->oob_data->Hoob_b64);
            EAP_NOOB_FREE(serv->oob_data->NoobId_b64);
            os_free(serv->oob_data);
        }
        if (serv->kdf_nonce_data) {
            EAP_NOOB_FREE(serv->kdf_nonce_data->Ns);
            EAP_NOOB_FREE(serv->kdf_nonce_data->Np);
            os_free(serv->kdf_nonce_data);
        }
        if (serv->kdf_out) {
            EAP_NOOB_FREE(serv->kdf_out->msk);
            EAP_NOOB_FREE(serv->kdf_out->emsk);
            EAP_NOOB_FREE(serv->kdf_out->amsk);
            EAP_NOOB_FREE(serv->kdf_out->MethodId);            
            EAP_NOOB_FREE(serv->kdf_out->Kms);
            EAP_NOOB_FREE(serv->kdf_out->Kmp);
            EAP_NOOB_FREE(serv->kdf_out->Kz);
            os_free(serv->kdf_out);
        }
        os_free(serv);
    }

    if (peer) {
        wpa_printf(MSG_DEBUG, "EAP_NOOB: Clearing peer data");
        EAP_NOOB_FREE(peer->PeerId);
        json_decref(peer->PeerInfo);
        EAP_NOOB_FREE(peer->MAC);
        EAP_NOOB_FREE(peer->Realm);
        if (peer->peer_config_params) {
            EAP_NOOB_FREE(peer->peer_config_params->Peer_name);
            EAP_NOOB_FREE(peer->peer_config_params->Peer_ID_Num);
            os_free(peer->peer_config_params);
        }
        os_free(peer);
    }

    /* Close DB */
    /* TODO check again */
    if (data->peer_db)
    if (SQLITE_OK != sqlite3_close_v2(data->peer_db)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
        const char * sql_error = sqlite3_errmsg(data->peer_db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s", sql_error);
    }
    EAP_NOOB_FREE(data->db_name);
    os_free(data); data = NULL;
    wpa_printf(MSG_DEBUG, "EAP_NOOB: Exit %s", __func__);
}

/**
 * eap_noob_deinit : de initialises the eap method context
 * @sm : eap statemachine context
 * @priv : method context
**/
static void eap_noob_deinit(struct eap_sm * sm, void * priv)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB DEINIT");
    struct eap_noob_peer_context * data = priv;

    eap_noob_free_ctx(data);
}

/**
 * eap_noob_create_db : Creates a new DB or opens the existing DB and populates the context
 * @sm : eap statemachine context
 * @data : peer context
 * returns : SUCCESS/FAILURE
**/
static int eap_noob_create_db(struct eap_sm *sm, struct eap_noob_peer_context * data)
{
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

    if (SQLITE_OK != sqlite3_open_v2(data->db_name, &data->peer_db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: No DB found,new DB willbe created");
        wpa_printf(MSG_ERROR, "EAP-NOOB: sqlite error: %s", sqlite3_errmsg(data->peer_db));
        return FAILURE;
    }

    if (FAILURE == eap_noob_db_statements(data->peer_db, CREATE_TABLES_EPHEMERALSTATE) ||
        FAILURE == eap_noob_db_statements(data->peer_db, CREATE_TABLES_PERSISTENTSTATE)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected error in table cration");
        return FAILURE;
    }
    if ((wpa_s->current_ssid->ssid) || (0 == os_strcmp(wpa_s->driver->name,"wired"))) {

        int ret = eap_noob_exec_query(data, QUERY_EPHEMERALSTATE, columns_ephemeralstate, 2,
                       TEXT, wpa_s->current_ssid->ssid);
        if (ret == FAILURE || ret == EMPTY ) {
            ret = eap_noob_exec_query(data, QUERY_PERSISTENTSTATE, columns_persistentstate, 2,
                       TEXT, wpa_s->current_ssid->ssid);
            if (ret == FAILURE || ret == EMPTY ) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: SSID not present in any tables");
                return SUCCESS;
            }  else { data->server_attr->state = REGISTERED_STATE; } 
        } else {
            if (FAILURE != eap_noob_exec_query(data, QUERY_EPHEMERALNOOB, columns_ephemeralnoob, 2,
                           TEXT, wpa_s->current_ssid->ssid)) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: WAITING FOR OOB state");
                return SUCCESS;
            }
        }
    }
    if (data->server_attr->PeerId)
        data->peer_attr->PeerId = os_strdup(data->server_attr->PeerId);
    return SUCCESS;
}

/**
 * eap_noob_assign_config : identify each config item and store the read value
 * @confname : name of the conf item
 * @conf_value : value of the conf item
 * @data : peer context
**/
static void eap_noob_assign_config(char * conf_name,char * conf_value,struct eap_noob_peer_data * data)
{
    //TODO : version and csuite are directly converted to integer.This needs to be changed if
    //more than one csuite or version is supported.

    wpa_printf(MSG_DEBUG, "EAP-NOOB:CONF Name = %s %d", conf_name, (int)strlen(conf_name));
    if (0 == strcmp("Version",conf_name)) {
        data->version = (int) strtol(conf_value, NULL, 10);
        data->config_params |= VERSION_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",data->version);
    }
    else if (0 == strcmp("Csuite",conf_name)) {
        data->cryptosuite = (int) strtol(conf_value, NULL, 10);
        data->config_params |= CRYPTOSUITES_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",data->cryptosuite);
    }
    else if (0 == strcmp("OobDirs",conf_name)) {
        data->dir = (int) strtol(conf_value, NULL, 10);
        data->config_params |= DIRS_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",data->dir);
    }
    else if (0 == strcmp("PeerMake", conf_name)) {
        data->peer_config_params->Peer_name = os_strdup(conf_value);
        data->config_params |= PEER_MAKE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",data->peer_config_params->Peer_name);
    }
    else if (0 == strcmp("PeerType", conf_name)) {
        eap_noob_globle_conf.peer_type = os_strdup(conf_value);
        data->config_params |= PEER_TYPE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",eap_noob_globle_conf.peer_type);
    }
    else if (0 == strcmp("PeerSNum", conf_name)) {
        data->peer_config_params->Peer_ID_Num = os_strdup(conf_value);
        data->config_params |= PEER_ID_NUM_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",data->peer_config_params->Peer_ID_Num);
    }
    else if (0 == strcmp("MinSleepDefault", conf_name)) {
        eap_noob_globle_conf.default_minsleep = (int) strtol(conf_value, NULL, 10);
        data->config_params |= DEF_MIN_SLEEP_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",eap_noob_globle_conf.default_minsleep);
    }
    else if (0 == strcmp("OobMessageEncoding", conf_name)) {
        eap_noob_globle_conf.oob_enc_fmt = (int) strtol(conf_value, NULL, 10);
        data->config_params |= MSG_ENC_FMT_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",eap_noob_globle_conf.oob_enc_fmt);
    }

}

/**
 * eap_noob_parse_config : parse eacj line from the config file
 * @buff : read line
 * data : peer_context
**/
static void eap_noob_parse_config(char * buff,struct eap_noob_peer_data * data)
{
    char * pos = buff;
    char * conf_name = NULL;
    char * conf_value = NULL;
    char * token = NULL;

    for(; *pos == ' ' || *pos == '\t' ; pos++);

    if (*pos == '#')
        return;

    if (os_strstr(pos, "=")) {
        conf_name = strsep(&pos,"=");
        /*handle if there are any space after the conf item name*/
        token = conf_name;
        for(; (*token != ' ' && *token != 0 && *token != '\t'); token++);
        *token = '\0';

        token = strsep(&pos,"=");
        /*handle if there are any space before the conf item value*/
        for(; (*token == ' ' || *token == '\t' ); token++);

        /*handle if there are any comments after the conf item value*/
        //conf_value = strsep(&token,"#");
        conf_value = token;

        for(; (*token != '\n' && *token != '\t'); token++);
        *token = '\0';
        //wpa_printf(MSG_DEBUG, "EAP-NOOB: conf_value = %s token = %s\n",conf_value,token);
        eap_noob_assign_config(conf_name,conf_value, data);
    }
}

/**
 * eap_noob_handle_incomplete_conf :  assigns defult value of the configuration is incomplete
 * @data : peer config
 * Returs : FAILURE/SUCCESS
**/
static int eap_noob_handle_incomplete_conf(struct eap_noob_peer_context * data)
{
    if (!(data->peer_attr->config_params & PEER_MAKE_RCVD) ||
        !(data->peer_attr->config_params & PEER_ID_NUM_RCVD) ||
        !(data->peer_attr->config_params&PEER_TYPE_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Peer Make or Peer Type or Peer Serial number missing");
        return FAILURE;
    }
    if (! (data->peer_attr->config_params & VERSION_RCVD))
        data->peer_attr->version = VERSION_ONE;
    if (! (data->peer_attr->config_params & CRYPTOSUITES_RCVD))
        data->peer_attr->cryptosuite = SUITE_ONE;
    if (! (data->peer_attr->config_params & DIRS_RCVD))
        data->peer_attr->dir = PEER_TO_SERV;
    if (! (data->peer_attr->config_params & DEF_MIN_SLEEP_RCVD))
        eap_noob_globle_conf.default_minsleep = 0;
    if (! (data->peer_attr->config_params & MSG_ENC_FMT_RCVD))
        eap_noob_globle_conf.oob_enc_fmt = FORMAT_BASE64URL;

    return SUCCESS;
}

/**
 * eap_noob_read_config : read configuraions from config file
 * @data : peer context
 * Returns : SUCCESS/FAILURE
**/

static int eap_noob_read_config(struct eap_sm *sm,struct eap_noob_peer_context * data)
{
    FILE * conf_file = NULL;
    char * buff = NULL, * PeerInfo_str = NULL;

    if (NULL == (conf_file = fopen(CONF_FILE,"r"))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Configuration file not found");
        return FAILURE;
    }

    if ((NULL == (buff = malloc(MAX_CONF_LEN))) || (NULL == (data->peer_attr->peer_config_params = \
                 malloc(sizeof(struct eap_noob_peer_config_params)))) )
        return FAILURE;

    data->peer_attr->config_params = 0;
    while(!feof(conf_file)) {
        if (fgets(buff,MAX_CONF_LEN, conf_file)) {
            eap_noob_parse_config(buff, data->peer_attr);
            memset(buff,0,MAX_CONF_LEN);
        }
    }
    free(buff);
    fclose(conf_file);

    if ((data->peer_attr->version >MAX_SUP_VER) || (data->peer_attr->cryptosuite > MAX_SUP_CSUITES) ||
        (data->peer_attr->dir > BOTH_DIR)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect confing value");
        return FAILURE;
    }

    if (eap_noob_globle_conf.oob_enc_fmt != FORMAT_BASE64URL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unsupported OOB message encoding format");
        return FAILURE;
    }

    if (data->peer_attr->config_params != CONF_PARAMS && FAILURE == eap_noob_handle_incomplete_conf(data))
        return FAILURE;

    if (NULL != (data->peer_attr->PeerInfo = eap_noob_prepare_peer_info_string(sm, data->peer_attr->peer_config_params))) {
            PeerInfo_str =  json_dumps(data->peer_attr->PeerInfo, JSON_COMPACT|JSON_PRESERVE_ORDER);
            if (NULL == PeerInfo_str || os_strlen(PeerInfo_str) > MAX_INFO_LEN) {
                wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect or no peer info");
                return FAILURE;
            }
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: PEER INFO = %s", PeerInfo_str);
    os_free(PeerInfo_str);
    return SUCCESS;
}

/**
 * eap_noob_peer_ctxt_alloc : Allocates the subcontexts inside the peer context
 * @sm : eap method context
 * @peer : peer context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_peer_ctxt_alloc(struct eap_sm *sm,  struct eap_noob_peer_context * data)
{
    if (NULL == (data->peer_attr = os_zalloc( sizeof (struct eap_noob_peer_data)))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr = os_zalloc( sizeof (struct eap_noob_server_data))))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr->ecdh_exchange_data = os_zalloc( sizeof (struct eap_noob_ecdh_key_exchange))))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr->oob_data = os_zalloc( sizeof (struct eap_noob_oob_data))))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr->kdf_out = os_zalloc( sizeof (struct eap_noob_ecdh_kdf_out))))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr->kdf_nonce_data = os_zalloc( sizeof (struct eap_noob_ecdh_kdf_nonce))))) {
        return FAILURE;
    }
    return SUCCESS;
}

/**
 * eap_noob_peer_ctxt_init : initialises peer context
 * @sm : eap statemachine data
 * @data : peer context
 * Returns: SUCCESS/FAILURE
**/
static int eap_noob_peer_ctxt_init(struct eap_sm * sm,  struct eap_noob_peer_context * data)
{
    int retval = FAILURE;
    if (FAILURE == (retval = eap_noob_peer_ctxt_alloc(sm, data))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating peer context");
        goto EXIT;
    }

    data->server_attr->state = UNREGISTERED_STATE;
    data->server_attr->rcvd_params = 0;
    data->server_attr->err_code = 0;
    data->db_name = os_strdup(DB_NAME);

    if (FAILURE == (retval = eap_noob_create_db(sm , data)))
        goto EXIT;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: State = %d", data->server_attr->state);
    if (FAILURE == eap_noob_read_config(sm,data)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to initialize context");
        goto EXIT;
    }

EXIT:
    if (FAILURE == retval)
        eap_noob_free_ctx(data);
    return retval;
}

/**
 * eap_noob_init : initialise the eap noob method
 *  @sm : eap statemachine context
 * Returns : eap  noob peer context
**/
static void * eap_noob_init(struct eap_sm * sm)
{
    struct eap_noob_peer_context * data = NULL;
    wpa_printf(MSG_DEBUG, "Entering %s", __func__);
    if (NULL == (data = os_zalloc(sizeof(struct eap_noob_peer_context))) )
        return NULL;

    if (FAILURE == eap_noob_peer_ctxt_init(sm,data)) return NULL;
    return data;
}

/**
 * eap_noob_isKeyAvailable : Checks if the shared key is presesnt
 * @sm : eap statemachine context
 * @priv : eap noob data
 * Returns : TRUE/FALSE
*/
static Boolean eap_noob_isKeyAvailable(struct eap_sm *sm, void *priv)
{
    struct eap_noob_peer_context * data = priv;
    Boolean retval = ((data->server_attr->state == REGISTERED_STATE) && (data->server_attr->kdf_out->msk != NULL));
    wpa_printf(MSG_DEBUG, "EAP-NOOB: State = %d, Key Available? %d", data->server_attr->state, retval);
    return retval;
}

/**
 * eap_noob_getKey : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns MSK or NULL
**/
static u8 * eap_noob_getKey(struct eap_sm * sm, void * priv, size_t * len)
{
    struct eap_noob_peer_context * data = priv;
    u8 * key;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: GET  KEY");
    if ((data->server_attr->state != REGISTERED_STATE) || (!data->server_attr->kdf_out->msk))
        return NULL;

    if (NULL == (key = os_malloc(MSK_LEN))) return NULL;

    *len = MSK_LEN; os_memcpy(key, data->server_attr->kdf_out->msk, MSK_LEN);
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: MSK Derived",key,MSK_LEN);
    return key;
}

/**
 * eap_noob_get_emsk : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns EMSK or NULL
**/
static u8 * eap_noob_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_noob_peer_context *data = priv;
    u8 *key;
    wpa_printf(MSG_DEBUG,"EAP-NOOB:Get EMSK Called");
    if ((data->server_attr->state != REGISTERED_STATE) || (!data->server_attr->kdf_out->emsk))
        return NULL;

    if (NULL == (key = os_malloc(MSK_LEN)))
        return NULL;

    *len = EAP_EMSK_LEN;
    os_memcpy(key, data->server_attr->kdf_out->emsk, EAP_EMSK_LEN);
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: EMSK",key,EAP_EMSK_LEN);
    return key;
}


/**
 * eap_noob_get_session_id : gets the session id if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : session id len
 * Returns Session Id or NULL
**/
static u8 * eap_noob_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_noob_peer_context *data = priv;
    u8 *session_id=NULL;
    wpa_printf(MSG_DEBUG,"EAP-NOOB:Get Session ID Called");
    if ((data->server_attr->state != REGISTERED_STATE) || (!data->server_attr->kdf_out->MethodId))
        return NULL;

    *len = 1 + METHOD_ID_LEN;
    session_id = os_malloc(*len);
    if (session_id == NULL)
    return NULL;

    session_id[0] = EAP_TYPE_NOOB;

    os_memcpy(session_id + 1, data->server_attr->kdf_out->MethodId, METHOD_ID_LEN);
    *len = 1 + METHOD_ID_LEN;

    return session_id;
}



/**
 * eap_noob_deinit_for_reauth : release data not needed for fast reauth
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static void eap_noob_deinit_for_reauth(struct eap_sm *sm, void *priv)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
}

/**
 * eap_noob_init_for_reauth : initialise the reauth context
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static void * eap_noob_init_for_reauth(struct eap_sm * sm, void * priv)
{
     wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
     struct eap_noob_peer_context * data=priv;
     data->server_attr->state = RECONNECTING_STATE;
     return data;
}

/**
 * eap_noob_has_reauth_data : Changes the state to RECONNECT. Called by state machine to check if method has enough data to do fast reauth
 * if the current state is REGISTERED_STATE
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static Boolean eap_noob_has_reauth_data(struct eap_sm * sm, void * priv)
{
    struct eap_noob_peer_context * data = priv;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, Current SSID = %s, Stored SSID = %s", __func__,
               wpa_s->current_ssid->ssid, data->server_attr->ssid);
    if ((data->server_attr->state == REGISTERED_STATE ||  data->server_attr->state == RECONNECTING_STATE) &&
        (0 == strcmp((char *)wpa_s->current_ssid->ssid, data->server_attr->ssid))) {
        data->server_attr->state = RECONNECTING_STATE;
        data->peer_attr->state = RECONNECTING_STATE;
        if(!data->peer_attr->Realm || os_strlen(data->peer_attr->Realm)==0)
            data->peer_attr->Realm = os_strdup(DEFAULT_REALM);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Peer ID and Realm Reauth, %s %s", data->peer_attr->PeerId, data->peer_attr->Realm);
        eap_noob_config_change(sm, data); eap_noob_db_update(data, UPDATE_PERSISTENT_STATE);
        return TRUE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Returning False, %s", __func__);
    return FALSE;
}

/**
 * eap_peer_noob_register : register eap noob method
**/
int eap_peer_noob_register(void)
{
    struct eap_method * eap = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: NOOB REGISTER");
    eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION, EAP_VENDOR_IETF, EAP_TYPE_NOOB, "NOOB");

    if (eap == NULL) return -1;

    eap->init = eap_noob_init;
    eap->deinit = eap_noob_deinit;
    eap->process = eap_noob_process;
    eap->isKeyAvailable = eap_noob_isKeyAvailable;
    eap->getKey = eap_noob_getKey;
    eap->get_emsk = eap_noob_get_emsk;
    eap->getSessionId = eap_noob_get_session_id;
    eap->has_reauth_data = eap_noob_has_reauth_data;
    eap->init_for_reauth = eap_noob_init_for_reauth;
    eap->deinit_for_reauth = eap_noob_deinit_for_reauth;

    return eap_peer_method_register(eap);
}
