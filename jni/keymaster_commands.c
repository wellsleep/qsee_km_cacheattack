#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h> //for ion
#include <sys/mman.h> //for ion
#include <linux/ioctl.h> //for ion
#include "keymaster_commands.h"
#include "keymaster_common.h"
#include "keymaster_qcom.h"

#include "msm_ion.h" //for ion

struct qcom_km_ion_info_t {
    int32_t ion_fd;
    int32_t ifd_data_fd;
    struct ion_handle_data ion_alloc_handle;
    unsigned char * ion_sbuffer;
    uint32_t sbuf_len;
};

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
    //printf("[+] Generated encrypted keypair blob!\n");
    //for (uint32_t i=0; i<*key_blob_length; i++)
    //    printf("%02X", (*key_blob)[i]);
    //printf("\n");

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

/*
    if (key_type != TYPE_RSA) {
        printf("Unsupported key type %d", key_type);
        return -1;
    } else if (key_params == NULL) {
        printf("key_params == null");
        return -1;
    }
    if (keyBlob == NULL || keyBlobLength == NULL) {
        printf("output key blob or length == NULL");
        return -1;
    }
    struct keymaster_rsa_keygen_params* rsa_params = (struct keymaster_rsa_keygen_params*) key_params;

    struct keymaster_gen_keypair_cmd *send_cmd = NULL;
    struct keymaster_gen_keypair_resp  *resp = NULL;
    struct QSEECom_handle *handle = NULL;
    int ret = 0;
    //****
    uint32_t cmd_req_size = QSEECOM_ALIGN(sizeof(struct keymaster_gen_keypair_cmd));
    uint32_t cmd_resp_size = QSEECOM_ALIGN(sizeof(struct keymaster_gen_keypair_resp));
    uint32_t* cmd_req = malloc(cmd_req_size);
    uint32_t* cmd_resp = malloc(cmd_resp_size);
    memset(cmd_req, 0, cmd_req_size);
    memset(cmd_resp, 0, cmd_resp_size);
    //****
    handle = (struct QSEECom_handle *)(km_handle->qseecom);
    //send_cmd = (struct keymaster_gen_keypair_cmd *)handle->ion_sbuffer;
    //resp = (struct keymaster_gen_keypair_resp *)(handle->ion_sbuffer +
    //                           QSEECOM_ALIGN(sizeof(struct keymaster_gen_keypair_cmd)));
    send_cmd = (struct keymaster_gen_keypair_cmd *)cmd_req;
    resp = (struct keymaster_gen_keypair_resp *)cmd_resp;
    send_cmd->cmd_id = KEYMASTER_GENERATE_KEYPAIR;
    send_cmd->key_type = key_type;
    send_cmd->rsa_params.modulus_size = rsa_params->modulus_size;
    send_cmd->rsa_params.public_exponent = rsa_params->public_exponent;
    resp->status = KEYMASTER_FAILURE;
    resp->key_blob_len =  sizeof(struct qcom_km_key_blob);

    ret = (*km_handle->QSEECom_set_bandwidth)(handle, true);
    if (ret < 0) {
        printf("Generate key command failed (unable to enable clks) ret =%d", ret);
        return -1;
    }

    ret = (*km_handle->QSEECom_send_cmd)(handle, send_cmd,
                               QSEECOM_ALIGN(sizeof(struct keymaster_gen_keypair_cmd)), resp,
                               QSEECOM_ALIGN(sizeof(struct keymaster_gen_keypair_resp)));

    if((*km_handle->QSEECom_set_bandwidth)(handle, false))
        printf("Import key command: (unable to disable clks)");

    if ( (ret < 0)  ||  (resp->status  < 0)) {
        printf("Generate key command failed resp->status = %d ret =%d", resp->status, ret);
        return -1;
    } else {
        printf("DDDDDDDDDDDDDDDDDDDDDONE!\n");
/*        UniquePtr<unsigned char[]> keydata(new unsigned char[resp->key_blob_len]);
        if (keydata.get() == NULL) {
            ALOGE("could not allocate memory for key blob");
            return -1;
        }
        unsigned char* p = keydata.get();
        memcpy(p, (unsigned char *)(&resp->key_blob), resp->key_blob_len);
        *keyBlob = keydata.release();
        *keyBlobLength = resp->key_blob_len;



    
    }
    return 0;*/
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
      printf("Error:: null handle received");
      return -1;
    }
    ion_fd  = open("/dev/ion", O_RDONLY | O_DSYNC);
    if (ion_fd < 0) {
       printf("Error::Cannot open ION device");
       return -1;
    }
    handle->ion_sbuffer = NULL;
    handle->ifd_data_fd = 0;

    /* Size of allocation */
    ion_alloc_data.len = (size + 4095) & (~4095);

    /* 4K aligned */
    ion_alloc_data.align = 4096;

    /* memory is allocated from EBI heap */
   ion_alloc_data.heap_id_mask = ION_HEAP(ION_QSECOM_HEAP_ID);

    /* Set the memory to be uncached */
    ion_alloc_data.flags = 0;

    /* IOCTL call to ION for memory request */
    rc = ioctl(ion_fd, ION_IOC_ALLOC, &ion_alloc_data);
    if (rc) {
       ret = -1;
       goto alloc_fail;
    }

    if (ion_alloc_data.handle != 0) {
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
       printf("Error::ION MMAP failed");
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
           printf("Error::Failed to unmap memory for load image. ret = %d", ret);
    }

ioctl_fail:
    handle_data.handle = ion_alloc_data.handle;
    if (handle->ifd_data_fd)
        close(handle->ifd_data_fd);
    iret = ioctl(ion_fd, ION_IOC_FREE, &handle_data);
    if (iret) {
       printf("Error::ION FREE ioctl returned error = %d",iret);
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
        printf("Error::Unmapping ION Buffer failed with ret = %d", ret);
    }

    handle_data.handle = handle->ion_alloc_handle.handle;
    close(handle->ifd_data_fd);
    ret = ioctl(handle->ion_fd, ION_IOC_FREE, &handle_data);
    if (ret) {
        printf("Error::ION Memory FREE ioctl failed with ret = %d", ret);
    }
    close(handle->ion_fd);
    return ret;
}

int qcom_km_sign_data(struct qcom_keymaster_handle* km_handle,
        void* params,
        uint8_t* keyBlob, size_t keyBlobLength,
        uint8_t* data, size_t dataLength,
        uint8_t** signedData, size_t* signedDataLength)
{
    if (dataLength > KM_KEY_SIZE_MAX) {
        printf("Input data to be signed is too long %zu bytes", dataLength);
        return -1;
    }
    if (data == NULL) {
        printf("input data to sign == NULL");
        return -1;
    } else if (signedData == NULL || signedDataLength == NULL) {
        printf("Output signature buffer == NULL");
        return -1;
    }
    struct keymaster_rsa_sign_params* sign_params = (struct keymaster_rsa_sign_params*) params;
    if (sign_params->digest_type != DIGEST_NONE) {
        printf("Cannot handle digest type %d", sign_params->digest_type);
        return -1;
    } else if (sign_params->padding_type != PADDING_NONE) {
        printf("Cannot handle padding type %d", sign_params->padding_type);
        return -1;
    }
    
    printf("get in!\n");

    struct QSEECom_handle *handle = NULL;
    struct keymaster_sign_data_cmd *send_cmd = NULL;
    struct keymaster_sign_data_resp  *resp = NULL;
    struct QSEECom_ion_fd_info  ion_fd_info;
    struct qcom_km_ion_info_t ihandle;
    int ret = 0;

    handle = (struct QSEECom_handle *)(km_handle->qseecom);
    ihandle.ion_fd = 0;
    ihandle.ion_alloc_handle.handle = 0;
    if (qcom_km_ION_memalloc(&ihandle, dataLength) < 0) {
        printf("ION allocation  failed");
        return -1;
    }
    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));

    printf("prepare cmd!\n");

    /* Populate the send data structure */
    ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].cmd_buf_offset = sizeof(enum keymaster_cmd) +
         sizeof(struct qcom_km_key_blob) + sizeof(struct keymaster_rsa_sign_params);
    /* some problems with ion_sbuffer, discard
    send_cmd = (struct keymaster_sign_data_cmd *)handle->ion_sbuffer;
    resp = (struct keymaster_sign_data_resp *)(handle->ion_sbuffer +
                            QSEECOM_ALIGN(sizeof(struct keymaster_sign_data_cmd)));
    */

    uint32_t send_cmd_size = QSEECOM_ALIGN(sizeof(struct keymaster_sign_data_cmd));
    uint32_t resp_size = QSEECOM_ALIGN(sizeof(struct keymaster_sign_data_resp));

    //****
    uint32_t* cmd_req = malloc(send_cmd_size);
    uint32_t* cmd_resp = malloc(resp_size);
    memset(cmd_req, 0, send_cmd_size);
    memset(cmd_resp, 0, resp_size);
    //****
    send_cmd = (struct keymaster_sign_data_cmd *)cmd_req;
    resp = (struct keymaster_sign_data_resp *)cmd_resp;

    send_cmd->cmd_id = KEYMASTER_SIGN_DATA ;
    send_cmd->sign_param.digest_type = sign_params->digest_type;
    send_cmd->sign_param.padding_type = sign_params->padding_type;
    memcpy((unsigned char *)(&send_cmd->key_blob), keyBlob, keyBlobLength);
    memcpy((unsigned char *)ihandle.ion_sbuffer, data, dataLength);

    send_cmd->data = (uint32_t)ihandle.ion_sbuffer;
    send_cmd->dlen = dataLength;
    resp->sig_len = KM_KEY_SIZE_MAX;
    resp->status = 0x01;//KEYMASTER_FAILURE;

    printf("origin: resp->sig_len = %02zx, resp->status = %02zx\n", resp->sig_len, resp->status);
    printf("origin: keyblob = %02x %02x, data = %02x %02x\n", *(unsigned char *)(&send_cmd->key_blob), *((unsigned char *)(&send_cmd->key_blob)+1), \
                                                              *(unsigned char *)ihandle.ion_sbuffer, *((unsigned char *)ihandle.ion_sbuffer+1));

    ret = (*km_handle->QSEECom_set_bandwidth)(handle, true);
    if (ret < 0) {
        printf("Sign data command failed (unable to enable clks) ret =%d\n", ret);
        qcom_km_ion_dealloc(&ihandle);
        return -1;
    }

    printf("before send cmd!\n");
    //printf("[+] before resp data!\n");
    //for (uint32_t i=0; i<resp_size; i++)
    //    printf("%02X", *((uint8_t *)resp+i));
    //printf("\n");

    ret = (*km_handle->QSEECom_send_modified_cmd)(handle, send_cmd,
                               send_cmd_size, resp,
                               resp_size, &ion_fd_info);
    
    printf("after send cmd!\n");
    printf("send_cmd->dlen = %02x!\n", send_cmd->dlen);
    
    printf("resp->sig_len = %02x!\n", resp->sig_len);
    printf("resp->cmd_id = %02x!\n", resp->cmd_id);
    printf("resp->status = %02x!\n", resp->status);
    printf("send_cmd size = %02x, resp size = %02zx!\n", send_cmd_size, resp_size);
    printf("after: cmd keyblob = %02x %02x, data = %02x %02x\n", *(unsigned char *)(&send_cmd->key_blob), *((unsigned char *)(&send_cmd->key_blob)+1), \
                                                       *(unsigned char *)ihandle.ion_sbuffer, *((unsigned char *)ihandle.ion_sbuffer+1));

    printf("[+] send_cmd struct!\n");
    for (uint32_t i=0; i<16; i++)
        printf("%02X, at %p\n", *((uint8_t *)send_cmd+i), ((uint8_t *)send_cmd+i));
    printf("\n");

    printf("cmd pointer %p!\n", (uint32_t *)send_cmd);
    printf("dlen pointer! %p\n", (uint32_t *)&(send_cmd->dlen));
    printf("cmd->data ptr! %p\n", (uint32_t *)&(send_cmd->data)); //pointer to data
    printf("cmd->key_blob! %x, at %p\n", *(uint32_t *)(&send_cmd->key_blob), (uint32_t *)(&send_cmd->key_blob)); //key_blob
    printf("resp pointer! %p\n", (uint32_t *)resp);
    printf("resp->sig_len pointer! %p\n", (uint32_t *)&(resp->sig_len));

    //printf("[+] after resp data!\n");
    //for (uint32_t i=0; i<resp_size; i++)
    //    printf("%02X", *((uint8_t *)resp+i));
    //printf("\n");

    if((*km_handle->QSEECom_set_bandwidth)(handle, false))
        printf("Sign data command: (unable to disable clks)");

    if ( (ret < 0)  ||  (resp->status  < 0)) {
        printf("Sign data command failed resp->status = %d ret =%d\n", resp->status, ret);
        qcom_km_ion_dealloc(&ihandle);
        return -1;
    } else {/*
        UniquePtr<uint8_t> signedDataPtr(reinterpret_cast<uint8_t*>(malloc(resp->sig_len)));
        if (signedDataPtr.get() == NULL) {
            printf("Sign data memory allocation failed");
            qcom_km_ion_dealloc(&ihandle);
            return -1;
        }
        unsigned char* p = signedDataPtr.get();
        memcpy(p, (unsigned char *)(&resp->signed_data), resp->sig_len);

        *signedDataLength = resp->sig_len;
        *signedData = signedDataPtr.release();*/

	printf("printing resp!\n");
        uint8_t *p = malloc(resp->sig_len);
	printf("0! sig_len = 0x%02zx\n", resp->sig_len);
        //memcpy(p, (unsigned char *)(&resp->signed_data), resp->sig_len);
	printf("1!\n");
        *signedDataLength = resp->sig_len;
        printf("2!\n");
        //Dumping the signed data
        printf("[+] Printing signed data!\n");
	printf("[+] resp data!\n");
        //for (uint32_t i=0; i<*signedDataLength; i++)
	for (uint32_t i=0; i<16; i++)
            printf("%02X", resp->signed_data[i]);
        printf("\n");
	printf("[+] send_cmd data!\n");
	for (uint32_t i=0; i<1; i++)
            printf("%02X", *(&send_cmd->data));
        printf("\n");
	printf("[+] key_blob data!\n");
	for (uint32_t i=0; i<8; i++)
            printf("%02X", keyBlob[i]);
        printf("\n");

	free(p);
    }
    qcom_km_ion_dealloc(&ihandle);
    return 0;
}

int keymaster_sign_data(struct qcom_keymaster_handle *km_handle, uint8_t** key_blob, size_t* key_blob_length) {

    printf("ok\n");

    struct keymaster_rsa_sign_params rsa_params;
    rsa_params.digest_type = DIGEST_NONE;
    rsa_params.padding_type = PADDING_NONE;
    uint8_t data[128] = {0x11,0xAA,0x2B,0x3C,4,5,6,7,8,9,10,11,12,13,14,15,16};
    size_t dataLength = 128;
    uint8_t signedData[128] = {0};
    size_t signedDataLength = 128;
    int res = -1;

    uint8_t *sd0 = signedData;
    uint8_t **sd1 = &sd0;

    printf("start to sign!\n");
    res = qcom_km_sign_data(km_handle, &rsa_params, *key_blob, *key_blob_length, data, dataLength, sd1, &signedDataLength);
    if (res < 0) {
        perror("[-] Failed to sign!");
        return -EINVAL;
    }
    return res;
}
