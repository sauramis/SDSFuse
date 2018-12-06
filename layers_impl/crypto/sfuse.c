/*
  SafeFS
  (c) 2016 2018 INESC TEC. Written by J. Paulo, R. Pontes and R. Macedo

*/


#include "sfuse.h"
#include "../../logging/timestamps/timestamps.h"

// struct with original operations from mounted filesystem
static struct fuse_operations *originalfs_oper;
// struct with sfuse operations
static struct fuse_operations sfuse_oper;

// struct with encoding algorithms
static struct encode_driver enc_driver;

//TODO: in the future this needs to be restricted to a certain amount of memory defined in the conf file
ivdb filesize_cache;
GMutex filesize_mutex;
int cache=0;


// GSList *sfuse_write_list = NULL, *sfuse_read_list = NULL;

int BLOCK_SIZE;

void update_cache_filesize(char* path, uint64_t newsize){

        DEBUG_MSG("update size %s %llu\n",path, newsize);
        g_mutex_lock(&filesize_mutex);

        int contains = hash_contains_key(&filesize_cache, path);
        uint64_t curr_size = 0;
        value_db* value;

        if (contains > 0) {
            hash_get(&filesize_cache, path, &value);
            curr_size=value->file_size;
        }

        if(curr_size<newsize){
            value = malloc(sizeof(value_db));
            value->file_size=newsize;
            char* key=malloc(strlen(path));
            memcpy(key,path,strlen(path));
            hash_put(&filesize_cache, key, value);
        }
        g_mutex_unlock(&filesize_mutex);
        DEBUG_MSG("end update size %s %llu\n",path, newsize);

}

uint64_t get_cache_filesize(char* path){

        DEBUG_MSG("get size %s\n",path);
        g_mutex_lock(&filesize_mutex);

        uint64_t res=0;

        int contains = hash_contains_key(&filesize_cache, path);
        value_db* value;

        if (contains > 0) {
            hash_get(&filesize_cache, path, &value);
            res=value->file_size;
        }else{
            res=0;
        }

        g_mutex_unlock(&filesize_mutex);

        DEBUG_MSG("end get size %s\n",path);

        return  res;
        
}

static int sfuse_read_batch(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    // struct timespec tstart={0,0}, tend={0,0};
    // clock_gettime(CLOCK_MONOTONIC, &tstart);
    // struct timeval tstart, tend;
    // gettimeofday(&tstart, NULL);

    DEBUG_MSG("Going to read offset %ld with size %lu\n", offset, size);

    int cblock_size = enc_driver.get_cyphered_block_size(size);
    uint64_t cblock_offset = enc_driver.get_cyphered_block_offset(offset);

    int encrypted_chunk_size = enc_driver.get_cyphered_chunk_size();

    // DEBUG_MSG("Going to read path %s cblock_offset %ld with cblock_size %lu\n", path, cblock_offset, cblock_size);

    char full_encrypted_buffer[cblock_size];

    int res = originalfs_oper->read(path, full_encrypted_buffer, cblock_size, cblock_offset, fi);
    if (res <= 0) {
        return res;
    }

    DEBUG_MSG("READ path %s cblock_offset %ld with cblock_size %lu\n", path, cblock_offset, cblock_size);

    // struct key_info info;
    // info.path = path;
    // info.offset = cblock_offset;

    // calculate number of chunks (this needs to be asked to the encoding driver since it is dependent on the Padding size
    // -- in case of standard driver, it is also dependent on the IV size
    int decoding_cycles = enc_driver.get_total_decoding_cycles(res);
    // DEBUG_MSG("Decoding cycles -- %d\n", decoding_cycles);


    struct key_info* info = malloc(sizeof(struct key_info));
    info->path = malloc(sizeof(char)*(strlen(path)+1));
    memcpy((char *)info->path, path, (strlen(path)+1));

    int read_bytes = 0;
    // Decoding cycle
    for (int i = 0; i < decoding_cycles; i++) {
        int reverted_cycle = decoding_cycles-(i+1);

        // Calculate size and alloc memory for plaintext chunk. (mode == 1 == decryption)
        int plt_chunk_size = enc_driver.get_cycle_block_size(res, reverted_cycle, 1);
        char* plaintext_chunk;
        plaintext_chunk = malloc(sizeof(char)*plt_chunk_size);
        // DEBUG_MSG("Plaintext Chunk Size: %d\n", plt_chunk_size);

        // Calculate size and alloc memory for encrypted chunk
        int enc_chunk_size = enc_driver.get_encrypted_chunk_size(res, reverted_cycle);
        char* encrypted_chunk;
        encrypted_chunk = malloc(sizeof(char)*enc_chunk_size);
        // DEBUG_MSG("Encrypted Chunk size: %d\n", enc_chunk_size);

        // Copy encrypted data to the current chunk
        memcpy(encrypted_chunk, &full_encrypted_buffer[enc_driver.get_cycle_block_offset(i)], enc_chunk_size);

        info->offset = (i * encrypted_chunk_size) + cblock_offset;
        // DEBUG_MSG("(decode) info->offset = %d\n", info->offset);

        // Decrypt chunk
        int decode_result = 0;
        DEBUG_MSG("(READ)Going to decode bytes for chunk(%d) -- %d\n", i, enc_chunk_size);
        decode_result = enc_driver.decode((unsigned char*) plaintext_chunk, (unsigned char*) encrypted_chunk, enc_chunk_size, info);
        // DEBUG_MSG("Decoded bytes for chunk(%d) -- %d -- %d\n", i, enc_chunk_size, decode_result);

        if (decode_result < 0) {
            exit(-1);
            // return -1;
        } else {
            read_bytes += decode_result;
        }

        // Copy plaintext data to output buffer
        memcpy(&buf[enc_driver.get_plaintext_block_offset(i)], plaintext_chunk, decode_result);

        free(plaintext_chunk);
        free(encrypted_chunk);
    }
    free((char *)info->path);
    free(info);

    // gettimeofday(&tend, NULL);

    // clock_gettime(CLOCK_MONOTONIC, &tend);
    // store(&sfuse_read_list, tstart, tend);

    return read_bytes;
}

static int sfuse_write_batch(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    // struct timespec tstart={0,0}, tend={0,0};
    // clock_gettime(CLOCK_MONOTONIC, &tstart);
    // struct timeval tstart, tend;
    // gettimeofday(&tstart, NULL);

    DEBUG_MSG("Going to write path %s offset %ld with size %lu\n", path, offset, size);

    int encrypted_block_size = enc_driver.get_cyphered_block_size(size);
    uint64_t encrypted_block_offset = enc_driver.get_cyphered_block_offset(offset);
    int encrypted_chunk_size = enc_driver.get_cyphered_chunk_size();

    // DEBUG_MSG("Going to write path %s cblock_offset %ld with cblock_size %lu\n", path, encrypted_block_offset, encrypted_block_size);

    // Alloc total encrypted buffer size
    char* full_encrypted_buffer = malloc(sizeof(char)*encrypted_block_size);

    struct key_info* info = malloc(sizeof(struct key_info));
    info->path = malloc(sizeof(char)*(strlen(path)+1));
    memcpy((char *)info->path, path, (strlen(path)+1));
    info->offset = encrypted_block_offset;

    if(cache == 1){
        update_cache_filesize((char*) path, offset+size);
    }

    // calculate number of encoding cycles
    int complete_encrypt_cycles = (int) (size / BLOCK_SIZE);
    if ((size % BLOCK_SIZE) != 0) {
        complete_encrypt_cycles++;
    }
    // DEBUG_MSG("Complete_encrypt_cycles: %d\n", complete_encrypt_cycles);
    // DEBUG_MSG("CONV_GET_CYPHERED_CHUNK_SIZE: %d\n", enc_driver.get_cyphered_chunk_size());

    int writen_bytes = 0;
    
    // Encoding cycle
    for (int i = 0; i < complete_encrypt_cycles; i++) {
        int encrypted_bytes;
        // reverse cycle
        int reverse_cycle = complete_encrypt_cycles-(i+1);
        // calculate block size of the current cycle. Mode == 0 == encryption
        int cycle_encrypted_block_size = enc_driver.get_cycle_block_size(size, reverse_cycle, 0);
        // DEBUG_MSG("get_cycle_block_size (inner cycle) == %d -- %d\n", cycle_encrypted_block_size, reverse_cycle);

        char encrypted_chunk[cycle_encrypted_block_size];
        unsigned char* chunk;
        int chunk_size = BLOCK_SIZE;

        // calculate last block size
        if (reverse_cycle == 0) {
            int last_original_block_size = (int) (size - ((size / BLOCK_SIZE) * BLOCK_SIZE));

            if (last_original_block_size > 0) {
                chunk_size = last_original_block_size;
            }
        }

        info->offset = (i * encrypted_chunk_size) + encrypted_block_offset;
        // DEBUG_MSG("(decode) info->offset = %d\n", info->offset);

        // Allocate memory to the current chunk & copy the respective amount of data
        chunk = malloc(sizeof(char)*chunk_size);
        memcpy(chunk, &buf[BLOCK_SIZE*i], chunk_size);

        // Encrypt current chunk
        encrypted_bytes = enc_driver.encode((unsigned char *) encrypted_chunk, chunk, chunk_size, info);
        // DEBUG_MSG("%d Encoded bytes for chunk %d\n", encrypted_bytes, i);

        if (encrypted_bytes < 0) {
            return -1;
        } else {
            writen_bytes += encrypted_bytes;
        }

        // DEBUG_MSG("Written bytes - %d\n", writen_bytes);
        // Move encrypted chunk to full encrypted buffer
        memcpy(&full_encrypted_buffer[enc_driver.get_cycle_block_offset(i)], encrypted_chunk, encrypted_bytes);
        free(chunk);
    }
    free((char *)info->path);
    free(info);

    if (writen_bytes < encrypted_block_size) {
        ERROR_MSG("RES < cblock for encode Going to write path %s cblock_offset %ld with cblock_size %lu\n", path, encrypted_block_offset, encrypted_block_size);
        return -1;
    }

    int res;
    DEBUG_MSG("Before write to filesystem: full_encrypted_buffer_length - %d; writen_bytes - %d; cblock_size - %d\n", strlen(full_encrypted_buffer), writen_bytes, encrypted_block_size);
    res = originalfs_oper->write(path, full_encrypted_buffer, encrypted_block_size, encrypted_block_offset, fi);
    DEBUG_MSG("After write to filesystem\n");

    free(full_encrypted_buffer);

    if (res < 0) {
        return res;
    }
    if (res < encrypted_block_size) {
        return -1;
    }
    // clock_gettime(CLOCK_MONOTONIC, &tend);
    // gettimeofday(&tend, NULL);

    // store(&sfuse_write_list, tstart, tend);
    return size;
}

static int sfuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    // struct timespec tstart={0,0}, tend={0,0};
    // clock_gettime(CLOCK_MONOTONIC, &tstart);
    // struct timeval tstart, tend;
    // gettimeofday(&tstart, NULL);

    DEBUG_MSG("sfuse_read: Going to read offset %ld with size %lu\n", offset, size);

    int cblock_size = enc_driver.get_cyphered_block_size(size);
    uint64_t cblock_offset = enc_driver.get_cyphered_block_offset(offset);

    // DEBUG_MSG("Going to read path %s cblock_offset %ld with cblock_size %lu\n", path, cblock_offset, cblock_size);

    char aux_cyphered_buf[cblock_size];

    int res = originalfs_oper->read(path, aux_cyphered_buf, cblock_size, cblock_offset, fi);
    if (res <= 0) {
        return res;
    }
    // DEBUG_MSG("READ path %s cblock_offset %ld with cblock_size %lu\n", path, cblock_offset, cblock_size);

    struct key_info info;
    info.path = path;
    info.offset = cblock_offset;

    res = enc_driver.decode((unsigned char *)buf, (unsigned char *)aux_cyphered_buf, res, &info);
    // DEBUG_MSG("Read path %s cblock_offset %ld with cblock_size %lu return size%d\n", path, cblock_offset, cblock_size, res);

    // gettimeofday(&tend, NULL);

    // clock_gettime(CLOCK_MONOTONIC, &tend);
    // store(&sfuse_read_list, tstart, tend);
    return res;
}

static int sfuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    // struct timeval tstart, tend;
    // gettimeofday(&tstart, NULL);

    DEBUG_MSG("Going to write path %s offset %ld with size %lu\n", path, offset, size);

    int res;

    if(cache == 1){
        update_cache_filesize((char*) path, offset+size);
    }

    int cblock_size = enc_driver.get_cyphered_block_size(size);
    uint64_t cblock_offset = enc_driver.get_cyphered_block_offset(offset);

    // DEBUG_MSG("Going to write path %s cblock_offset %ld with cblock_size %lu\n", path, cblock_offset, cblock_size);

    char aux_cyphered_buf[cblock_size];
    bzero(aux_cyphered_buf, cblock_size);
    struct key_info info;
    info.path = path;
    info.offset = cblock_offset;

    res = enc_driver.encode((unsigned char *)aux_cyphered_buf, (unsigned char *)buf, size, &info);
    if (res < cblock_size) {
        ERROR_MSG("RES < cblock for encode Going to write path %s cblock_offset %ld with cblock_size %lu\n", path,
                cblock_offset, cblock_size);

        return -1;
    }

    res = originalfs_oper->write(path, aux_cyphered_buf, cblock_size, cblock_offset, fi);
    if (res < 0) {
        return res;
    }
    if (res < cblock_size) {
        return -1;
    }
    // clock_gettime(CLOCK_MONOTONIC, &tend);
    // gettimeofday(&tend, NULL);

    // store(&sfuse_write_list, tstart, tend);
    return size;
}


static int sfuse_getattr(const char *path, struct stat *stbuf) {    
    int res;

    DEBUG_MSG("(sfuse.c) - Going to gettattr to the file-system Path %s\n", path);

    res = originalfs_oper->getattr(path, stbuf);
    // DEBUG_MSG("path checking if is reg file%s\n", path);

    if (res >= 0 && S_ISREG(stbuf->st_mode)) {
        // DEBUG_MSG("path is reg file%s\n", path);
        uint64_t returned_size=0;
        if(cache==1){
            returned_size = get_cache_filesize((char*)path);
        }
        if(returned_size<=0){
            stbuf->st_size=enc_driver.get_file_size(path, stbuf->st_size, NULL, *originalfs_oper);
        }else{
            stbuf->st_size=returned_size;
        }
        if (stbuf->st_size < 0) {
            return -1;
        }
    }
    return res;
}

static int sfuse_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {    
    int res;

    (void)path;

    DEBUG_MSG("(sfuse.c) - Going to fgettattr to the file-system Path %s\n", path);        

    res = originalfs_oper->fgetattr(path, stbuf, fi);

    if (res == 0 && S_ISREG(stbuf->st_mode)) {
        // DEBUG_MSG("path is reg file%s\n", path);

        uint64_t returned_size=0;
        if(cache==1){
            returned_size = get_cache_filesize((char*)path);
        }
        if(returned_size<=0){
            stbuf->st_size=enc_driver.get_file_size(path, stbuf->st_size, fi, *originalfs_oper);
        }else{
            stbuf->st_size=returned_size;
        }
        // DEBUG_MSG("sfuse_fgetattr_ stbuf->st_size = %d\n", stbuf->st_size);
        if (stbuf->st_size < 0) {
            return -1;
        }
    }
    return res;
}

static int sfuse_truncate(const char *path, off_t size) {
    DEBUG_MSG("SFUSE CALL: sfuse_truncate call Path %s Size %lu\n", path, size);
    // Check if it is working
    off_t truncate_size = enc_driver.get_truncate_size(size);

    // int res=originalfs_oper->truncate(path,size);
    int res = originalfs_oper->truncate(path, truncate_size);
    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int sfuse_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) {
    DEBUG_MSG("SFUSE CALL: sfuse_ftruncate call Path %s Size %lu\n", path, size);
    off_t truncate_size = enc_driver.get_truncate_size(size);

    int res = originalfs_oper->ftruncate(path, truncate_size, fi);
    if (res == -1) {
        return -errno;
    }

    return 0;
}


// TODO: IVS should also be deleted for unlinked (removed) files.

int init_sfuse_driver(struct fuse_operations **originop, configuration data) {
    originalfs_oper = *originop;

    BLOCK_SIZE = data.block_config.block_size;
    DEBUG_MSG("init_sfuse_driver - BLOCK_SIZE = %d\n", BLOCK_SIZE);

    // TODO:
    // Maybe this could be initialized with the sfuse_oper struct
    sfuse_oper.init = originalfs_oper->init;
    sfuse_oper.destroy = originalfs_oper->destroy;
    sfuse_oper.getattr = sfuse_getattr;
    sfuse_oper.fgetattr = sfuse_fgetattr;
    sfuse_oper.access = originalfs_oper->access;
    sfuse_oper.readlink = originalfs_oper->readlink;
    sfuse_oper.opendir = originalfs_oper->opendir;
    sfuse_oper.readdir = originalfs_oper->readdir;
    sfuse_oper.releasedir = originalfs_oper->releasedir;
    sfuse_oper.mknod = originalfs_oper->mknod;
    sfuse_oper.mkdir = originalfs_oper->mkdir;
    sfuse_oper.symlink = originalfs_oper->symlink;
    sfuse_oper.unlink = originalfs_oper->unlink;
    sfuse_oper.rmdir = originalfs_oper->rmdir;
    sfuse_oper.rename = originalfs_oper->rename;
    sfuse_oper.link = originalfs_oper->link;
    sfuse_oper.create = originalfs_oper->create;
    sfuse_oper.open = originalfs_oper->open;

    DEBUG_MSG("init_sfuse_driver - config_mode - %d\n", data.block_config.mode);
    if (data.block_config.mode == 1) {
        sfuse_oper.read = sfuse_read;
        sfuse_oper.write = sfuse_write;
    } else if (data.block_config.mode == 2) {
        sfuse_oper.read = sfuse_read_batch;
        sfuse_oper.write = sfuse_write_batch;
    }

    sfuse_oper.statfs = originalfs_oper->statfs;
    sfuse_oper.flush = originalfs_oper->flush;
    sfuse_oper.release = originalfs_oper->release;
    sfuse_oper.fsync = originalfs_oper->fsync;
    sfuse_oper.truncate = sfuse_truncate;
    sfuse_oper.ftruncate = sfuse_ftruncate;
    sfuse_oper.chown = originalfs_oper->chown;
    sfuse_oper.chmod = originalfs_oper->chmod;
    // sfuse_oper.setxattr    = originalfs_oper->setxattr;
    // sfuse_oper.getxattr    = originalfs_oper->getxattr;
    // sfuse_oper.listxattr   = originalfs_oper->listxattr;
    // sfuse_oper.removexattr = originalfs_oper->removexattr;


    if(data.enc_config.cache == 1){
        init_hash(&filesize_cache);
        g_mutex_init(&filesize_mutex);
        cache=1;
    }

    switch (data.enc_config.mode) {
        case NOPCRYPT:
            enc_driver.encode = nop_encode;
            enc_driver.decode = nop_decode;
            enc_driver.get_file_size = nop_get_file_size;
            enc_driver.get_cyphered_block_size = nop_get_cyphered_block_size;
            enc_driver.get_cyphered_block_offset = nop_get_cyphered_block_offset;
            enc_driver.get_truncate_size = nop_get_truncate_size;
            break;
        case NOPCRYPT_PAD:
            nop_padded_init(data.block_config);
            enc_driver.encode = nop_encode_padded;
            enc_driver.decode = nop_decode_padded;
            enc_driver.get_file_size = nop_get_file_size_padded;
            enc_driver.get_cyphered_block_size = nop_get_cyphered_block_size_padded;
            enc_driver.get_cyphered_block_offset = nop_get_cyphered_block_offset_padded;
            enc_driver.get_truncate_size = nop_get_truncate_size_padded;
            break;
        case STANDARD:
	    DEBUG_MSG("inside standard encryption scheme\n");
            rand_init(data.enc_config.key, (unsigned char *)data.enc_config.key_size, data.enc_config.operation_mode, data.block_config);
            enc_driver.encode = rand_encode;
            enc_driver.decode = rand_decode;
            enc_driver.get_file_size = rand_get_file_size;
            enc_driver.get_cyphered_block_size = rand_get_cyphered_block_size;
            enc_driver.get_cyphered_block_offset = rand_get_cyphered_block_offset;
            enc_driver.get_truncate_size = rand_get_truncate_size;

            enc_driver.get_cycle_block_size = rand_get_cycle_block_size;
            enc_driver.get_cycle_block_offset = rand_get_cycle_block_offset;
            enc_driver.get_total_decoding_cycles = rand_get_total_decoding_cycles;
            enc_driver.get_encrypted_chunk_size = rand_get_encrypted_chunk_size;
            enc_driver.get_plaintext_block_offset = rand_get_plaintext_block_offset;

            // TODO: temporary
            enc_driver.get_cyphered_chunk_size = rand_get_cyphered_chunk_size;
            break;
        case DETERMINISTIC:
            det_init(data.enc_config.key, (unsigned char *)data.enc_config.iv, 16, data.enc_config.operation_mode, data.block_config);
            enc_driver.encode = det_encode;
            enc_driver.decode = det_decode;
            enc_driver.get_file_size = det_get_file_size;
            enc_driver.get_cyphered_block_size = det_get_cyphered_block_size;
            enc_driver.get_cyphered_block_offset = det_get_cyphered_block_offset;
            enc_driver.get_truncate_size = det_get_truncate_size;

            enc_driver.get_cycle_block_size = det_get_cycle_block_size;
            enc_driver.get_cycle_block_offset = det_get_cycle_block_offset;
            enc_driver.get_total_decoding_cycles = det_get_total_decoding_cycles;
            enc_driver.get_encrypted_chunk_size = det_get_encrypted_chunk_size;
            enc_driver.get_plaintext_block_offset = det_get_plaintext_block_offset;

            // TODO: temporary
            enc_driver.get_cyphered_chunk_size = det_get_cyphered_chunk_size;
            break;
        case AUTH_RAND:
            rand_auth_init(data.enc_config.key, data.enc_config.key_size, data.enc_config.iv_size, 16, data.enc_config.operation_mode, data.block_config);
            enc_driver.encode = rand_auth_encode;
            enc_driver.decode = rand_auth_decode;
            enc_driver.get_file_size = rand_auth_get_file_size;
            enc_driver.get_cyphered_block_size = rand_auth_get_cyphered_block_size;
            enc_driver.get_cyphered_block_offset = rand_auth_get_cyphered_block_offset;
            enc_driver.get_truncate_size = rand_auth_get_truncate_size;

            enc_driver.get_cycle_block_size = rand_auth_get_cycle_block_size;
            enc_driver.get_cycle_block_offset = rand_auth_get_cycle_block_offset;
            enc_driver.get_total_decoding_cycles = rand_auth_get_total_decoding_cycles;
            enc_driver.get_encrypted_chunk_size = rand_auth_get_encrypted_chunk_size;
            enc_driver.get_plaintext_block_offset = rand_auth_get_plaintext_block_offset;

            // TODO: temporary
            enc_driver.get_cyphered_chunk_size = rand_auth_get_cyphered_chunk_size;
            break;
        case AUTH_DET:
            det_auth_init(data.enc_config.key, data.enc_config.key_size, (unsigned char *)data.enc_config.iv, data.enc_config.iv_size, 16, data.enc_config.operation_mode, data.block_config);
            enc_driver.encode = det_auth_encode;
            enc_driver.decode = det_auth_decode;
            enc_driver.get_file_size = det_auth_get_file_size;
            enc_driver.get_cyphered_block_size = det_auth_get_cyphered_block_size;
            enc_driver.get_cyphered_block_offset = det_auth_get_cyphered_block_offset;
            enc_driver.get_truncate_size = det_auth_get_truncate_size;

            enc_driver.get_cycle_block_size = det_auth_get_cycle_block_size;
            enc_driver.get_cycle_block_offset = det_auth_get_cycle_block_offset;
            enc_driver.get_total_decoding_cycles = det_auth_get_total_decoding_cycles;
            enc_driver.get_encrypted_chunk_size = det_auth_get_encrypted_chunk_size;
            enc_driver.get_plaintext_block_offset = det_auth_get_plaintext_block_offset;

            // TODO: temporary
            enc_driver.get_cyphered_chunk_size = det_auth_get_cyphered_chunk_size;
            break;
        default:
            return -1;
    }

    // Copy original filesystem opers to a struct
    // TODO: try to avoid originalfs_oper being a global variable
    *originop = &sfuse_oper;

    return 0;
}

int clean_sfuse_driver(configuration data) {
    // DEBUG_MSG("Going to clean sfuse drivers\n");
    // print_latencies(sfuse_write_list, "sfuse", "write");
    // print_latencies(sfuse_read_list, "sfuse", "read");

    switch (data.enc_config.mode) {
        case STANDARD:
            return rand_clean();
        case DETERMINISTIC:
            return det_clean();
        case AUTH_RAND:
            return rand_auth_clean();
        case AUTH_DET:
            return det_auth_clean();
        default:
            return 0;
    }
}
