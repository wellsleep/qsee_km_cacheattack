#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
//#include <UniquePtr.h>

#include "keymaster_commands.h"
#include "keymaster_common.h"
#include "keymaster_qcom.h"

int generate_keymaster_key(struct qcom_keymaster_handle* km_handle, uint8_t** key_blob, size_t* key_blob_length) {

    //Generating a keypair using the keymaster application, to cause the KEK 
    //and IV to be loaded into the application!
    struct keymaster_rsa_keygen_params rsa_params;
    rsa_params.modulus_size = 1024;
    rsa_params.public_exponent = 3;
    int res = keymaster_generate_keypair(km_handle, TYPE_RSA, &rsa_params, key_blob, key_blob_length);
    if (res < 0) {
        perror("[-] Failed to generate RSA keypair");
        return -EINVAL;
    }

	//Dumping the keypair blob
    printf("[+] Generated encrypted keypair blob!\n");
//    for (uint32_t i=0; i<*key_blob_length; i++)
//        printf("%02X", (*key_blob)[i]);
//    printf("\n");

    return 0;
}

int keymaster_generate_keypair(struct qcom_keymaster_handle* handle,
							   enum keymaster_keypair key_type, const void* key_params,
							   uint8_t** keyBlob, size_t* keyBlobLength) {

	//Initializing the request and response buffers
	uint32_t cmd_req_size = QSEECOM_ALIGN(sizeof(struct keymaster_gen_keypair_cmd));
	uint32_t cmd_resp_size = QSEECOM_ALIGN(sizeof(struct keymaster_gen_keypair_resp));
	uint32_t* cmd_req = malloc(cmd_req_size);
	uint32_t* cmd_resp = malloc(cmd_resp_size);
	memset(cmd_req, 0, cmd_req_size);
	memset(cmd_resp, 0, cmd_resp_size);
	struct keymaster_rsa_keygen_params* rsa_params = (struct keymaster_rsa_keygen_params*) key_params;

	//Filling in the request data
	((struct keymaster_gen_keypair_cmd*)cmd_req)->cmd_id = KEYMASTER_GENERATE_KEYPAIR;
	((struct keymaster_gen_keypair_cmd*)cmd_req)->key_type = key_type;
	((struct keymaster_gen_keypair_cmd*)cmd_req)->rsa_params.modulus_size = rsa_params->modulus_size;
	((struct keymaster_gen_keypair_cmd*)cmd_req)->rsa_params.public_exponent = rsa_params->public_exponent;

	//Filling in the response data
	((struct keymaster_gen_keypair_resp*)cmd_resp)->status = KEYMASTER_FAILURE;
	((struct keymaster_gen_keypair_resp*)cmd_resp)->key_blob_len = sizeof(struct qcom_km_key_blob);
	
	//Sending the command
	int res = (*handle->QSEECom_set_bandwidth)(handle->qseecom, true);
    if (res < 0) {
        free(cmd_req);
        free(cmd_resp);
        perror("[-] Unable to enable clks");
        return -errno;
    }

    res = (*handle->QSEECom_send_cmd)(handle->qseecom,
                                      cmd_req,
                                      cmd_req_size,
                                      cmd_resp,
                                      cmd_resp_size);

    if ((*handle->QSEECom_set_bandwidth)(handle->qseecom, false)) {
        perror("[-] Import key command: (unable to disable clks)");
    }

	//Writing back the data to the user
	*keyBlobLength = ((struct keymaster_gen_keypair_resp*)cmd_resp)->key_blob_len;
	*keyBlob = malloc(*keyBlobLength);
	memcpy(*keyBlob, &(((struct keymaster_gen_keypair_resp*)cmd_resp)->key_blob), *keyBlobLength); 

	//Freeing the request and response buffers
    free(cmd_req);
    free(cmd_resp);
	
	return res;
}

struct qcom_km_ion_info_t {
    int32_t ion_fd;
    int32_t ifd_data_fd;
    //struct ion_handle_data ion_alloc_handle;
    unsigned char * ion_sbuffer;
    uint32_t sbuf_len;
};

int qcom_km_sign_data(struct qcom_keymaster_handle *km_handle,
        void* params,
        uint8_t* keyBlob, size_t keyBlobLength,
        uint8_t* data, size_t dataLength,
        uint8_t** signedData, size_t* signedDataLength)
{
    
    if (dataLength > KM_KEY_SIZE_MAX) {
        printf("Input data to be signed is too long %d bytes", dataLength);
        return -EINVAL;
    }
    if (data == NULL) {
        perror("input data to sign == NULL");
        return -EINVAL;
    } else if (signedData == NULL || signedDataLength == NULL) {
        perror("Output signature buffer == NULL");
        return -EINVAL;
    }
    struct keymaster_rsa_sign_params* sign_params = (struct keymaster_rsa_sign_params*) params;
    if (sign_params->digest_type != DIGEST_NONE) {
        printf("Cannot handle digest type %d", sign_params->digest_type);
        return -EINVAL;
    } else if (sign_params->padding_type != PADDING_NONE) {
        printf("Cannot handle padding type %d", sign_params->padding_type);
        return -EINVAL;
    }

    struct QSEECom_handle *handle = NULL;
    struct keymaster_sign_data_cmd *send_cmd = NULL;
    struct keymaster_sign_data_resp  *resp = NULL;
    struct QSEECom_ion_fd_info  ion_fd_info;
    //struct qcom_km_ion_info_t ihandle;
    int ret = 0;
    printf("got qseecom handle!\n");
    handle = (struct QSEECom_handle *)(km_handle->qseecom);
    //ihandle.ion_fd = 0;
    //ihandle.ion_alloc_handle.handle = NULL;
    //if (qcom_km_ION_memalloc(&ihandle, dataLength) < 0) {
    //    ALOGE("ION allocation  failed");
    //    return -1;
    //}
    
    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));

    struct keymaster_sign_data_cmd *send_buffer = malloc(QSEECOM_ALIGN(sizeof(struct keymaster_sign_data_cmd)));
    struct keymaster_sign_data_resp *resp_buffer = malloc(QSEECOM_ALIGN(sizeof(struct keymaster_sign_data_resp)));

    /* Populate the send data structure */
    //ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].fd = (uint32_t)resp_buffer;
    ion_fd_info.data[0].cmd_buf_offset = sizeof(enum keymaster_cmd) +
         sizeof(struct qcom_km_key_blob) + sizeof(struct keymaster_rsa_sign_params);

    //send_cmd = (struct keymaster_sign_data_cmd *)handle->ion_sbuffer;
    //resp = (struct keymaster_sign_data_resp *)(handle->ion_sbuffer +
    //                        QSEECOM_ALIGN(sizeof(struct keymaster_sign_data_cmd)));

    printf("before filling buffers!\n");
    send_buffer->cmd_id = KEYMASTER_SIGN_DATA ;
    send_buffer->sign_param.digest_type = sign_params->digest_type;
    send_buffer->sign_param.padding_type = sign_params->padding_type;
    memcpy((unsigned char *)(&send_buffer->key_blob), keyBlob, keyBlobLength);
    //memcpy((unsigned char *)ihandle.ion_sbuffer, data, dataLength);
    memcpy((uint8_t *)(&send_buffer->data), data, dataLength);

    //send_cmd->data = (uint32_t)ihandle.ion_sbuffer;
    send_buffer->dlen = dataLength;
    resp_buffer->sig_len = KM_KEY_SIZE_MAX;
    resp_buffer->status = KEYMASTER_FAILURE;

    ret = (*km_handle->QSEECom_set_bandwidth)(handle, true);
    if (ret < 0) {
        printf("Sign data command failed (unable to enable clks) ret =%d", ret);
        //qcom_km_ion_dealloc(&ihandle);
	free(send_buffer);
	free(resp_buffer);
        return -1;
    }

    printf("before sending cmd!\n");
    ret = (*km_handle->QSEECom_send_modified_cmd)(handle, send_buffer,
                               QSEECOM_ALIGN(sizeof(*send_buffer)), resp_buffer,
                               QSEECOM_ALIGN(sizeof(*resp_buffer)), &ion_fd_info);
    printf("sent! getting resp\n");
    if((*km_handle->QSEECom_set_bandwidth)(handle, false))
        perror("Sign data command: (unable to disable clks)");

    if ( (ret < 0)  ||  (resp_buffer->status  < 0)) {
        printf("Sign data command failed resp->status = %d ret =%d", resp_buffer->status, ret);
        //qcom_km_ion_dealloc(&ihandle);
	free(send_buffer);
	free(resp_buffer);
        return -1;
    } else {
        /*UniquePtr<uint8_t> signedDataPtr(reinterpret_cast<uint8_t*>(malloc(resp->sig_len)));
        if (signedDataPtr.get() == NULL) {
            ALOGE("Sign data memory allocation failed");
            return -1;
        }*/
    	printf("printing resp!\n");
        uint8_t *p = malloc(resp_buffer->sig_len);
	printf("0! sig_len = 0x%02zx\n", resp_buffer->sig_len);
        //memcpy(p, (unsigned char *)(&resp_buffer->signed_data), resp_buffer->sig_len);
	printf("1!\n");
        *signedDataLength = resp_buffer->sig_len;
        //*signedData = signedDataPtr.release();
        //**signedData = NULL;
        printf("2!\n");
        //Dumping the signed data
        printf("[+] Printing signed data!\n");
	printf("[+] resp_buffer data!\n");
        //for (uint32_t i=0; i<*signedDataLength; i++)
	for (uint32_t i=0; i<8; i++)
            printf("%02X", resp_buffer->signed_data[i]);
        printf("\n");
	printf("[+] send_buffer data!\n");
	for (uint32_t i=0; i<1; i++)
            printf("%08X", *(&send_buffer->data));
        printf("\n");
	printf("[+] key_blob data!\n");
	for (uint32_t i=0; i<8; i++)
            printf("%02X", keyBlob[i]);
        printf("\n");

	free(send_buffer);
	free(resp_buffer);
    }
    return 0;
}

int keymaster_sign_data(struct qcom_keymaster_handle *km_handle, uint8_t* key_blob, size_t key_blob_length) {

    printf("ok\n");

    struct keymaster_rsa_sign_params rsa_params;
    rsa_params.digest_type = DIGEST_NONE;
    rsa_params.padding_type = PADDING_NONE;
    uint8_t data[32] = {0x11,0xAA,0x2B,0x3C,4,5,6,7,8,9,10,11,12,13,14,15,16};
    size_t dataLength = 32;
    uint8_t signedData[64] = {0};
    size_t signedDataLength = 32;
    int res = -1;

    uint8_t *sd0 = signedData;
    uint8_t **sd1 = &sd0;

    printf("start to sign!\n");
    res = qcom_km_sign_data(km_handle, &rsa_params, key_blob, key_blob_length, data, dataLength, sd1, &signedDataLength);
    if (res < 0) {
        perror("[-] Failed to sign!");
        return -EINVAL;
    }
    return res;
}
