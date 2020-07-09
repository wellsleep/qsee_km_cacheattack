#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


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

static int32_t qcom_km_ION_memalloc(struct qcom_km_ion_info_t *handle,
                                uint32_t size)
{
    int32_t ret = 0;
    int32_t iret = 0;
    int32_t fd = 0;
    unsigned char *v_addr;
    struct ion_allocation_data ion_alloc_data;
    int32_t ion_fd;
    int32_t rc;
    struct ion_fd_data ifd_data;
    struct ion_handle_data handle_data;

    /* open ION device for memory management
     * O_DSYNC -> uncached memory
    */
    if(handle == NULL){
      ALOGE("Error:: null handle received");
      return -1;
    }
    ion_fd  = open("/dev/ion", O_RDONLY | O_DSYNC);
    if (ion_fd < 0) {
       ALOGE("Error::Cannot open ION device");
       return -1;
    }
    handle->ion_sbuffer = NULL;
    handle->ifd_data_fd = 0;

    /* Size of allocation */
    ion_alloc_data.len = (size + 4095) & (~4095);

    /* 4K aligned */
    ion_alloc_data.align = 4096;

    /* memory is allocated from EBI heap */
   ion_alloc_data.ION_HEAP_MASK = ION_HEAP(ION_QSECOM_HEAP_ID);

    /* Set the memory to be uncached */
    ion_alloc_data.flags = 0;

    /* IOCTL call to ION for memory request */
    rc = ioctl(ion_fd, ION_IOC_ALLOC, &ion_alloc_data);
    if (rc) {
       ret = -1;
       goto alloc_fail;
    }

    if (ion_alloc_data.handle != NULL) {
       ifd_data.handle = ion_alloc_data.handle;
    } else {
       ret = -1;
       goto alloc_fail;
    }
    /* Call MAP ioctl to retrieve the ifd_data.fd file descriptor */
    rc = ioctl(ion_fd, ION_IOC_MAP, &ifd_data);
    if (rc) {
       ret = -1;
       goto ioctl_fail;
    }

    /* Make the ion mmap call */
    v_addr = (unsigned char *)mmap(NULL, ion_alloc_data.len,
                                    PROT_READ | PROT_WRITE,
                                    MAP_SHARED, ifd_data.fd, 0);
    if (v_addr == MAP_FAILED) {
       ALOGE("Error::ION MMAP failed");
       ret = -1;
       goto map_fail;
    }
    handle->ion_fd = ion_fd;
    handle->ifd_data_fd = ifd_data.fd;
    handle->ion_sbuffer = v_addr;
    handle->ion_alloc_handle.handle = ion_alloc_data.handle;
    handle->sbuf_len = size;
    return ret;

map_fail:
    if (handle->ion_sbuffer != NULL) {
        iret = munmap(handle->ion_sbuffer, ion_alloc_data.len);
        if (iret)
           ALOGE("Error::Failed to unmap memory for load image. ret = %d", ret);
    }

ioctl_fail:
    handle_data.handle = ion_alloc_data.handle;
    if (handle->ifd_data_fd)
        close(handle->ifd_data_fd);
    iret = ioctl(ion_fd, ION_IOC_FREE, &handle_data);
    if (iret) {
       ALOGE("Error::ION FREE ioctl returned error = %d",iret);
    }

alloc_fail:
    if (ion_fd > 0)
       close(ion_fd);
    return ret;
}

/** @brief: Deallocate ION memory
 *
 *
 */
static int32_t qcom_km_ion_dealloc(struct qcom_km_ion_info_t *handle)
{
    struct ion_handle_data handle_data;
    int32_t ret = 0;

    /* Deallocate the memory for the listener */
    ret = munmap(handle->ion_sbuffer, (handle->sbuf_len + 4095) & (~4095));
    if (ret) {
        ALOGE("Error::Unmapping ION Buffer failed with ret = %d", ret);
    }

    handle_data.handle = handle->ion_alloc_handle.handle;
    close(handle->ifd_data_fd);
    ret = ioctl(handle->ion_fd, ION_IOC_FREE, &handle_data);
    if (ret) {
        ALOGE("Error::ION Memory FREE ioctl failed with ret = %d", ret);
    }
    close(handle->ion_fd);
    return ret;
}

static int qcom_km_import_keypair(struct qcom_keymaster_handle *km_handle,
        const uint8_t* key, const size_t key_length,
        uint8_t** keyBlob, size_t* keyBlobLength)
{
    if (key == NULL) {
        ALOGE("Input key == NULL");
        return -1;
    } else if (keyBlob == NULL || keyBlobLength == NULL) {
        ALOGE("Output key blob or length == NULL");
        return -1;
    }

    struct QSEECom_ion_fd_info  ion_fd_info;
    struct qcom_km_ion_info_t ihandle;
    int ret = 0;

    ihandle.ion_fd = 0;
    ihandle.ion_alloc_handle.handle = NULL;
    if (qcom_km_ION_memalloc(&ihandle, QSEECOM_ALIGN(key_length)) < 0) {
        ALOGE("ION allocation  failed");
        return -1;
    }
    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));

    /* Populate the send data structure */
    ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].cmd_buf_offset = sizeof(enum keymaster_cmd_t);


    struct QSEECom_handle *handle = NULL;
    keymaster_import_keypair_cmd_t *send_cmd = NULL;
    keymaster_import_keypair_resp_t  *resp = NULL;
	
    handle = (struct QSEECom_handle *)(km_handle->qseecom);
    send_cmd = (keymaster_import_keypair_cmd_t *)handle->ion_sbuffer;
    resp = (keymaster_import_keypair_resp_t *)(handle->ion_sbuffer +
                                        QSEECOM_ALIGN(sizeof(keymaster_import_keypair_cmd_t)));
    send_cmd->cmd_id = KEYMASTER_IMPORT_KEYPAIR;
    send_cmd->pkcs8_key = (uint32_t)ihandle.ion_sbuffer;

    memcpy((unsigned char *)ihandle.ion_sbuffer, key, key_length);

    send_cmd->pkcs8_key_len = key_length;
    resp->status = KEYMASTER_FAILURE;
    resp->key_blob_len =  sizeof(qcom_km_key_blob_t);

    ret = (*km_handle->QSEECom_set_bandwidth)(handle, true);
    if (ret < 0) {
        ALOGE("Import key command failed (unable to enable clks) ret =%d", ret);
        qcom_km_ion_dealloc(&ihandle);
        return -1;
    }
    ret = (*km_handle->QSEECom_send_modified_cmd)(handle, send_cmd,
                               QSEECOM_ALIGN(sizeof(*send_cmd)), resp,
                               QSEECOM_ALIGN(sizeof(*resp)), &ion_fd_info);

    if((*km_handle->QSEECom_set_bandwidth)(handle, false))
        ALOGE("Import key command: (unable to disable clks)");

    if ( (ret < 0)  ||  (resp->status  < 0)) {
        ALOGE("Import key command failed resp->status = %d ret =%d", resp->status, ret);
        qcom_km_ion_dealloc(&ihandle);
        return -1;
    } else {
        UniquePtr<unsigned char[]> keydata(new unsigned char[resp->key_blob_len]);
        if (keydata.get() == NULL) {
            ALOGE("could not allocate memory for key blob");
            return -1;
        }
        unsigned char* p = keydata.get();
        memcpy(p, (unsigned char *)(&resp->key_blob), resp->key_blob_len);
        *keyBlob = keydata.release();
        *keyBlobLength = resp->key_blob_len;

    }
    qcom_km_ion_dealloc(&ihandle);
    return 0;
}

static int qcom_km_sign_data(struct qcom_keymaster_handle *km_handle,
        const void* params,
        const uint8_t* keyBlob, const size_t keyBlobLength,
        const uint8_t* data, const size_t dataLength,
        uint8_t** signedData, size_t* signedDataLength)
{
    
    if (dataLength > KM_KEY_SIZE_MAX) {
        ALOGE("Input data to be signed is too long %d bytes", dataLength);
        return -1;
    }
    if (data == NULL) {
        ALOGE("input data to sign == NULL");
        return -1;
    } else if (signedData == NULL || signedDataLength == NULL) {
        ALOGE("Output signature buffer == NULL");
        return -1;
    }
    keymaster_rsa_sign_params_t* sign_params = (keymaster_rsa_sign_params_t*) params;
    if (sign_params->digest_type != DIGEST_NONE) {
        ALOGE("Cannot handle digest type %d", sign_params->digest_type);
        return -1;
    } else if (sign_params->padding_type != PADDING_NONE) {
        ALOGE("Cannot handle padding type %d", sign_params->padding_type);
        return -1;
    }

    struct QSEECom_handle *handle = NULL;
    keymaster_sign_data_cmd_t *send_cmd = NULL;
    keymaster_sign_data_resp_t  *resp = NULL;
    struct QSEECom_ion_fd_info  ion_fd_info;
    struct qcom_km_ion_info_t ihandle;
    int ret = 0;

    handle = (struct QSEECom_handle *)(km_handle->qseecom);
    ihandle.ion_fd = 0;
    ihandle.ion_alloc_handle.handle = NULL;
    if (qcom_km_ION_memalloc(&ihandle, dataLength) < 0) {
        ALOGE("ION allocation  failed");
        return -1;
    }
    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));

    /* Populate the send data structure */
    ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].cmd_buf_offset = sizeof(enum keymaster_cmd_t) +
         sizeof(qcom_km_key_blob_t) + sizeof(keymaster_rsa_sign_params_t);

    send_cmd = (keymaster_sign_data_cmd_t *)handle->ion_sbuffer;
    resp = (keymaster_sign_data_resp_t *)(handle->ion_sbuffer +
                            QSEECOM_ALIGN(sizeof(keymaster_sign_data_cmd_t)));
    send_cmd->cmd_id = KEYMASTER_SIGN_DATA ;
    send_cmd->sign_param.digest_type = sign_params->digest_type;
    send_cmd->sign_param.padding_type = sign_params->padding_type;
    memcpy((unsigned char *)(&send_cmd->key_blob), keyBlob, keyBlobLength);
    memcpy((unsigned char *)ihandle.ion_sbuffer, data, dataLength);

    send_cmd->data = (uint32_t)ihandle.ion_sbuffer;
    send_cmd->dlen = dataLength;
    resp->sig_len = KM_KEY_SIZE_MAX;
    resp->status = KEYMASTER_FAILURE;

    ret = (*km_handle->QSEECom_set_bandwidth)(handle, true);
    if (ret < 0) {
        ALOGE("Sign data command failed (unable to enable clks) ret =%d", ret);
        qcom_km_ion_dealloc(&ihandle);
        return -1;
    }

    ret = (*km_handle->QSEECom_send_modified_cmd)(handle, send_cmd,
                               QSEECOM_ALIGN(sizeof(*send_cmd)), resp,
                               QSEECOM_ALIGN(sizeof(*resp)), &ion_fd_info);

    if((*km_handle->QSEECom_set_bandwidth)(handle, false))
        ALOGE("Sign data command: (unable to disable clks)");

    if ( (ret < 0)  ||  (resp->status  < 0)) {
        ALOGE("Sign data command failed resp->status = %d ret =%d", resp->status, ret);
        qcom_km_ion_dealloc(&ihandle);
        return -1;
    } else {
        UniquePtr<uint8_t> signedDataPtr(reinterpret_cast<uint8_t*>(malloc(resp->sig_len)));
        if (signedDataPtr.get() == NULL) {
            ALOGE("Sign data memory allocation failed");
            qcom_km_ion_dealloc(&ihandle);
            return -1;
        }
        unsigned char* p = signedDataPtr.get();
        memcpy(p, (unsigned char *)(&resp->signed_data), resp->sig_len);

        *signedDataLength = resp->sig_len;
        *signedData = signedDataPtr.release();
    }
    qcom_km_ion_dealloc(&ihandle);
    return 0;
}

static int qcom_km_verify_data(struct qcom_keymaster_handle *km_handle,
        const void* params,
        const uint8_t* keyBlob, const size_t keyBlobLength,
        const uint8_t* signedData, const size_t signedDataLength,
        const uint8_t* signature, const size_t signatureLength)
{

    if (signedData == NULL || signature == NULL) {
        ALOGE("data or signature buffers == NULL");
        return -1;
    }

    keymaster_rsa_sign_params_t* sign_params = (keymaster_rsa_sign_params_t*) params;
    if (sign_params->digest_type != DIGEST_NONE) {
        ALOGE("Cannot handle digest type %d", sign_params->digest_type);
        return -1;
    } else if (sign_params->padding_type != PADDING_NONE) {
        ALOGE("Cannot handle padding type %d", sign_params->padding_type);
        return -1;
    } else if (signatureLength != signedDataLength) {
        ALOGE("signed data length must be signature length");
        return -1;
    }

    struct QSEECom_handle *handle = NULL;
    keymaster_verify_data_cmd_t *send_cmd = NULL;
    keymaster_verify_data_resp_t  *resp = NULL;

    struct QSEECom_ion_fd_info  ion_fd_info;
    struct qcom_km_ion_info_t ihandle;
    int ret = 0;

    handle = (struct QSEECom_handle *)(km_handle->qseecom);
    ihandle.ion_fd = 0;
    ihandle.ion_alloc_handle.handle = NULL;
    if (qcom_km_ION_memalloc(&ihandle, signedDataLength + signatureLength) <0) {
        ALOGE("ION allocation  failed");
        return -1;
    }
    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));

    /* Populate the send data structure */
    ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].cmd_buf_offset = sizeof(enum keymaster_cmd_t) +
        sizeof(qcom_km_key_blob_t ) + sizeof(keymaster_rsa_sign_params_t);

    send_cmd = (keymaster_verify_data_cmd_t *)handle->ion_sbuffer;
    resp = (keymaster_verify_data_resp_t *)((char *)handle->ion_sbuffer +
                               sizeof(keymaster_verify_data_cmd_t));
    send_cmd->cmd_id = KEYMASTER_VERIFY_DATA ;
    send_cmd->sign_param.digest_type = sign_params->digest_type;
    send_cmd->sign_param.padding_type = sign_params->padding_type;
    memcpy((unsigned char *)(&send_cmd->key_blob), keyBlob, keyBlobLength);

    send_cmd->signed_data = (uint32_t)ihandle.ion_sbuffer;
    send_cmd->signed_dlen = signedDataLength;
    memcpy((unsigned char *)ihandle.ion_sbuffer, signedData, signedDataLength);

    send_cmd->signature = signedDataLength;
    send_cmd->slen = signatureLength;
    memcpy(((unsigned char *)ihandle.ion_sbuffer + signedDataLength),
                                  signature, signatureLength);
    resp->status = KEYMASTER_FAILURE;

    ret = (*km_handle->QSEECom_set_bandwidth)(handle, true);
    if (ret < 0) {
        ALOGE("Verify data  command failed (unable to enable clks) ret =%d", ret);
        qcom_km_ion_dealloc(&ihandle);
        return -1;
    }

    ret = (*km_handle->QSEECom_send_modified_cmd)(handle, send_cmd,
                               QSEECOM_ALIGN(sizeof(*send_cmd)), resp,
                               QSEECOM_ALIGN(sizeof(*resp)), &ion_fd_info);

    if((*km_handle->QSEECom_set_bandwidth)(handle, false))
        ALOGE("Verify data  command: (unable to disable clks)");

    if ( (ret < 0)  ||  (resp->status  < 0)) {
        ALOGE("Verify data command failed resp->status = %d ret =%d", resp->status, ret);
        qcom_km_ion_dealloc(&ihandle);
        return -1;
    }
    qcom_km_ion_dealloc(&ihandle);
    return 0;
}
