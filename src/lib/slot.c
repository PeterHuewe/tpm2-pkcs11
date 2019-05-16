/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "db.h"
#include "pkcs11.h"
#include "slot.h"
#include "token.h"
#include "utils.h"
#include "tpm.h"

static struct {
    size_t token_cnt;
    token *token;
} global;

CK_RV slot_init(void) {

    return db_get_tokens(&global.token, &global.token_cnt);
}

void slot_destroy(void) {

    token_free_list(global.token, global.token_cnt);
}

token *slot_get_token(CK_SLOT_ID slot_id) {

    size_t i;
    for (i=0; i < global.token_cnt; i++) {
        token *t = &global.token[i];
        if (slot_id == t->id) {
            return t;
        }
    }

    return NULL;
}

CK_RV slot_get_list (CK_BYTE token_present, CK_SLOT_ID *slot_list, CK_ULONG_PTR count) {

    /*
     * True for token present only returns slots with tokens, False all slots. All
     * of our slots always have a token, so we can ignore this.
     */
    UNUSED(token_present);

    check_pointer(count);

    if (!slot_list) {
        *count = global.token_cnt;
        return CKR_OK;
    }

    if (*count < global.token_cnt) {
        return CKR_BUFFER_TOO_SMALL;
    }

    size_t i;
    for (i=0; i < global.token_cnt; i++) {
        token *t = &global.token[i];
        slot_list[i] = t->id;
    }

    *count = global.token_cnt;

    return CKR_OK;
}

CK_RV slot_get_info (CK_SLOT_ID slot_id, CK_SLOT_INFO *info) {

    const CK_BYTE manufacturerID[] = "foo";
    const CK_BYTE slotDescription[] = "bar";

    check_pointer(info);

    if (!slot_get_token(slot_id)) {
        return CKR_SLOT_ID_INVALID;
    }

    memset(info, 0, sizeof(*info));

    /* TODO pull these from TPM */
    info->firmwareVersion.major =
            info->firmwareVersion.minor = 13;

    info->hardwareVersion.major =
    info->hardwareVersion.minor = 42;

    str_padded_copy(info->manufacturerID, manufacturerID, sizeof(info->manufacturerID));
    str_padded_copy(info->slotDescription, slotDescription, sizeof(info->slotDescription));

    info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

    return CKR_OK;
}

static const CK_MECHANISM_TYPE mechs[] = {
    CKM_AES_CBC,
    CKM_AES_CFB1,
    CKM_AES_ECB,
    CKM_ECDSA,
    CKM_ECDSA_SHA1,
    CKM_EC_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS_OAEP,
    CKM_RSA_X_509,
    CKM_SHA_1,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512,
    CKM_SHA512_RSA_PKCS,
};

CK_RV slot_mechanism_list_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE *mechanism_list, CK_ULONG_PTR count) {
    int supported = 0;
    token *t;

    t = slot_get_token(slot_id);
    if (!t) {
        return CKR_SLOT_ID_INVALID;
    }

    if (!count) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!mechanism_list) {
        // It is acceptable to request more storage than we might really need.
        *count = ARRAY_LEN(mechs);
        return CKR_OK;
    }

    if (*count < ARRAY_LEN(mechs)) {
        return CKR_BUFFER_TOO_SMALL;
    }

    TPMS_CAPABILITY_DATA *capabilityData;
    if (tpm_get_algorithms (t->tctx, &capabilityData) != CKR_OK) {
        return CKR_GENERAL_ERROR;
    }

    TPMU_CAPABILITIES *algs= &capabilityData->data;

    for (unsigned int i = 0; i < ARRAY_LEN(mechs); i++){
        switch (mechs[i]){
            case CKM_AES_CBC:
                if (is_algorithm_supported(algs, TPM2_ALG_CBC)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_AES_CFB1:
                if (is_algorithm_supported(algs, TPM2_ALG_CFB)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_AES_ECB:
                if (is_algorithm_supported(algs, TPM2_ALG_ECB)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_ECDSA:
                if (is_algorithm_supported(algs, TPM2_ALG_ECDSA)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_ECDSA_SHA1:
                if (is_algorithm_supported(algs, TPM2_ALG_ECDSA) &&
                    is_algorithm_supported(algs, TPM2_ALG_SHA1)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_EC_KEY_PAIR_GEN:
                if (is_algorithm_supported(algs, TPM2_ALG_ECC)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_RSA_PKCS:
                if (is_algorithm_supported(algs, TPM2_ALG_RSA)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_RSA_PKCS_KEY_PAIR_GEN:
                if (is_algorithm_supported(algs, TPM2_ALG_RSA)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_RSA_PKCS_OAEP:
                if (is_algorithm_supported(algs, TPM2_ALG_OAEP)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_RSA_X_509:
                if (is_algorithm_supported(algs, TPM2_ALG_RSA)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
            case CKM_SHA_1:
                if (is_algorithm_supported(algs, TPM2_ALG_SHA1)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_SHA1_RSA_PKCS:
                if (is_algorithm_supported(algs, TPM2_ALG_SHA1) &&
                    is_algorithm_supported(algs, TPM2_ALG_RSA)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_SHA256:
                if (is_algorithm_supported(algs, TPM2_ALG_SHA256)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_SHA256_RSA_PKCS:
                if (is_algorithm_supported(algs, TPM2_ALG_SHA256) &&
                    is_algorithm_supported(algs, TPM2_ALG_RSA)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_SHA384:
                if (is_algorithm_supported(algs, TPM2_ALG_SHA384)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_SHA384_RSA_PKCS:
                if (is_algorithm_supported(algs, TPM2_ALG_SHA384) &&
                    is_algorithm_supported(algs, TPM2_ALG_RSA)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_SHA512:
                if (is_algorithm_supported(algs, TPM2_ALG_SHA512)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
            case CKM_SHA512_RSA_PKCS:
                if (is_algorithm_supported(algs, TPM2_ALG_SHA512) &&
                    is_algorithm_supported(algs, TPM2_ALG_RSA)) {
                    mechanism_list[supported] = mechs[i];
                    supported++;
                }
                break;
        }
    }

    *count = supported;
    free(capabilityData);

    return CKR_OK;
}

CK_RV slot_mechanism_info_get (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info) {

    check_pointer(info);

    if (!slot_get_token(slot_id)) {
        return CKR_SLOT_ID_INVALID;
    }

    // TODO support more of these and check with the TPM for sizes.
    switch(type) {
    case CKM_AES_KEY_GEN:
        info->ulMinKeySize = 128;
        info->ulMaxKeySize = 512;
        info->flags = CKF_GENERATE;
        break;
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        info->ulMinKeySize = 1024;
        info->ulMaxKeySize = 4096;
        info->flags = CKF_GENERATE_KEY_PAIR;
        break;
    case CKM_EC_KEY_PAIR_GEN:
        info->ulMinKeySize = 192;
        info->ulMaxKeySize = 256;
        info->flags = CKF_GENERATE_KEY_PAIR;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}
