/* <This program implements the Kite-Attack Framework, a GPU-tailored implementation of the Cube Attack.>
 * Copyright (C) <2015-2021> <Massimo Bernaschi> <massimo[DOT]bernaschi[AT]gmail[DOT]com>
 * Copyright (C) <2015-2021> <Marco Cianfriglia> <marco[DOT]cianfriglia[AT]gmail[DOT]com>    
 * Copyright (C) <2015-2021> <Stefano Guarino> <ste[DOT]guarino[AT]gmail[DOT]com>
 * Copyright (C) <2015-2021> <Flavio Lombardi> <flavio[DOT]lombardi[AT]cnr[DOT]it>
 * Copyright (C) <2015-2021> <Marco Pedicini> <m[DOT]pedicini[AT]gmail[DOT]com>
 *
 * This file is part of Kite-Attack Framework.
 *
 * Kite-Attack Framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Kite-Attack Framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Kite-Attack Framework.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "auxiliary_functions.h"
#include "Trivium_auxiliary.h"
#include "Grain128_auxiliary.h"
#include "twiddle.h"


void* Calloc(size_t n_items, size_t size, const char *msg) {
    void *ptr;

    ptr = calloc(n_items, size);
    if (ptr == NULL) {
        fprintf(stderr, "Cannot allocate %zu items of size %zu for %s\n\n", n_items, size, msg);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void* Malloc(size_t size, const char *msg) {
    void *ptr;

    ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Cannot allocate %zu bytes for %s\n\n", size, msg);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void* Realloc(void *ptr, size_t size, const char *msg){
    void *lp;

    lp = (void *)realloc(ptr, size);
    if (lp == NULL && size) {
        fprintf(stderr, "Cannot reallocate to %zu bytes for %s\n\n", size, msg);
        exit(EXIT_FAILURE);
    }
    return lp;
}

void Free( void *ptr ){

    if ( ptr != NULL ){
        free(ptr);
    }
}

FILE *Fopen(const char *path, const char *mode, const char *msg){
    FILE *fp = NULL;
    fp = fopen(path, mode);
    if (fp == NULL) {
        fprintf(stderr, "Cannot open file %s - %s\n\n", path, msg);
        exit(EXIT_FAILURE);
    }
    return fp;
}

char * Strdup(const char * s, const char *msg){
    char *out = NULL;
    out = strdup(s);
    if( NULL == out){
        fprintf(stderr,"Cannot duplicate string %s - %s\n", s, msg);
        exit(EXIT_FAILURE);
    }

    return out;
}

void Mkdir(char *pathname, mode_t mode){
    int status = 0;
    status = mkdir(pathname,mode);
    if( status != 0 && errno != EEXIST){
        fprintf(stderr,"Cannot create dir %s\n",pathname);
        exit(EXIT_FAILURE);
    }

}

FILE* createFile(char *pathname, char *filename, const char *mode){
    if(NULL == pathname || NULL == filename || NULL == mode){
        fprintf(stderr,"Application error\n");
        exit(EXIT_FAILURE);
    }
    
    char buf[MAX_BUFFER];
    snprintf(buf, MAX_BUFFER, "%s/%s", pathname, filename);
    FILE *f = Fopen(buf, mode, "createFile");
    return f;
}

char* checkStart(char *s){
    char *tmp;
    int i;

    tmp = NULL;
    i = 0;
    if( NULL == s){
        return s;
    }

    while(isspace(s[i])){ 
        i++;
    }
    tmp = &s[i];
    return tmp;
}

int getCommentIdx(char * s){

    int i;
    int flag;

    i = flag = 0;
    if( NULL == s){
        fprintf(stderr,"[ERROR]: invalid argument\n");
        exit(EXIT_FAILURE);
    }

    while(s[i] != '\0'){
        if('#' == s[i]){
            flag =1;
        }
        if( '\n' == s[i] && flag){
            do{	
                if( isspace(s[i]) ){
                    i++;
                }
                else{
                    return i;
                }
            }while(s[i] != '\0');

            return i;
        }

        i++;
    }
    if( flag ){
        return i;
    }
    return -1;	
}

int configurationFileParser(const char * pathname, char *** key_vector, char *** value_vector){

    struct stat st;
    FILE *f; 
    size_t bytes_readed;
    char * file_contents;
    char * pch;
    char * tmp;
    char ** vector_tmp;
    int fd;
    int ret;
    int index;
    int i;
    int vector_dim;

    f = NULL;
    file_contents = pch = tmp = NULL;
    vector_tmp = NULL;
    fd = ret = index = i = vector_dim = 0;


    if( NULL == pathname){
        return -1;
    }
    fd = open(pathname,O_RDONLY);
    if( -1 == fd){
        return -1;
    }

    f = fdopen(fd, "rb");
    if( NULL == f){
        return -1;
    }

    /* Ensure that the file is a regular file */
    if ((fstat(fd, &st) != 0) || (!S_ISREG(st.st_mode))) {
        return -1;
    }	



    file_contents = (char *) Calloc(st.st_size,sizeof(char),"Calloc file_contents");

    bytes_readed = fread(file_contents, sizeof(char), st.st_size,f);
    if( bytes_readed != st.st_size){
        Free(file_contents);
        fclose(f);
        return -1;
    }

    fclose(f);

    tmp = file_contents;

    vector_dim = DEFAULT_CONFIGURATION_NUMBER;

    *key_vector = (char**)Malloc(sizeof(char*)*vector_dim,"Malloc *key_vector");

    *value_vector = (char**)Malloc(sizeof(char*)*vector_dim, "Malloc *value_vector");

    do{	
        // Check the token delimiter. It should be an '=' and not '\0'
        pch = strtok(tmp, "=");
        if( NULL == pch){
            break;
        }

        ret = strlen(pch) -1;
        if( '\n' == pch[ret]){
            break;
        }
        tmp = pch;	
        tmp = checkStart(tmp);
        ret = getCommentIdx(tmp);

        if( ret != -1){
            //There is a comment line (it starts with #)
            if( '\0' == tmp[ret]){	
                tmp = NULL;	
                pch = strtok(tmp,"\n");
                continue;
            }
            tmp = &(tmp[ret]);
        }

        // Key found, it will be copied to key_vector
        (*key_vector)[index] = Strdup(tmp,"Strdup key_vector");

        pch = strtok(NULL,"\n");
        tmp = pch;
        if( NULL == pch){
            (*value_vector)[index] = Strdup(EMPTY_STRING, "Strdup, value_vector");
        }else{
            tmp = checkStart(tmp);
            ret = getCommentIdx(tmp);
            if( ret != -1){
                tmp = &(tmp[ret]);
            }

            (*value_vector)[index] = Strdup(tmp, "Strdup *value_vector");
        }

        index++;

        if(index >= vector_dim){
            vector_dim = vector_dim *2;
            vector_tmp = (char**) Realloc(*key_vector, vector_dim * sizeof(char*), "Realloc *key_vector");
            *key_vector = vector_tmp;


            vector_tmp = (char**) Realloc(*value_vector, vector_dim * sizeof(char*), "Realloc *value_vector");
            *value_vector = vector_tmp;
        }


        tmp = NULL; // It is needed by strtok 
    } while(pch != NULL);


    if (file_contents !=0) {
        free(file_contents);
        return index;
    }

    for( i = 0 ; i < index; i++){
        free(*key_vector[i]);
    }
    free(*key_vector);

    for(i = 0; i < index ; i++){
        free(*value_vector[i]);
    }
    free(*value_vector);

    *key_vector = *value_vector = NULL;

    return -1;
}

u32* getVettFromStringSet(char * value_string , int dim_vett){

    int string_len;
    int i;
    int start;
    int index;
    u32 * vett;
    char * tmp_value_string; 
    char * tmp;

    if(NULL == value_string || dim_vett <= 0){
        return NULL;
    }

    string_len = strlen(value_string) +1;
    i = 0;
    start = 0;
    index = 0;
    tmp_value_string = (char*)strdup(value_string);
    vett = (u32*) Calloc(dim_vett,sizeof(u32),"Calloc vett");

    tmp = tmp_value_string;
    while ( i < string_len & index < dim_vett){
        if('{' == tmp_value_string[i]){	
            i++;
            start = i;
        }else if( ',' == tmp_value_string[i]){
            tmp_value_string[i] = 0;
            tmp = &(tmp_value_string[start]);
            vett[index] = atoi(tmp);
            i++;
            start = i;
            index++;
        }else if( isdigit(tmp_value_string[i])){
            i++;
        }else if( '}' == tmp_value_string[i]){
            tmp_value_string[i] = 0;
            tmp = &(tmp_value_string[start]);
            vett[index] = atoi(tmp);
            i++;
            start = i;
            index++;
            if( index != dim_vett){
                free(vett);
                fprintf(stderr, "[ERROR]: invalid stringSet\n");
                return NULL;
            }
            return vett;
        }else{
            fprintf(stderr, "{ERROR]: in parsing stringSet\n");
            free(vett);
            return NULL;
        }
    }

    fprintf(stderr, "[ERROR]: invalid stringSet\n");
    return NULL;
}



u32* genPaperKeys(){

#ifdef TRIVIUM_CIPHER
    u32 old[] ={ 
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF0000,
        0x5D21660E, 0x3DFAC89E, 0x78BD0000,
        0x3C1EFF45, 0x3E248AED, 0x33BE0000,
        0x5AF8E81D, 0x7DD8FA99, 0x6E530000,
        0x7A2B633B, 0x3E55E10A, 0x69BA0000,
        0x19195F9F, 0x3E1D7CC4, 0x649D0000,
        0x37F6596C, 0x3DE1D50E, 0x5F280000,
        0x16E0616D, 0x7DCC7118, 0x59FF0000,
        0x3611A973, 0x3E21371D, 0x153D0000,
        0x5576DE05, 0x7E79E854, 0x508A0000
    };
#elif defined GRAIN128_CIPHER
    u32 old[] ={
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0x6B8B4567, 0x327B23C6, 0x643C9869, 0x66334873,
        0x59B997FA, 0x67A3797F, 0x0B5DA644, 0x0F8CA14F,
        0x47DB4E3A, 0x1CCC40D1, 0x3250D4D8, 0x38D2F928,
        0x754E7DDD, 0x11265233, 0x18799942, 0x214A541E,
        0x232ADD1B, 0x05F2A7DD, 0x7F129A6A, 0x0A3E7008,
        0x11560EBD, 0x7B33BFB9, 0x665D7618, 0x3395CE31,
        0x3E52DFF5, 0x6F19E243, 0x4BDA073B, 0x1B7B9CAF,
        0x2D274378, 0x65114598, 0x73F21A22, 0x059E1A7D,
        0x1A7DD803, 0x5989B872, 0x1A0A04A5, 0x2DEFBF57
    };
#else
    u32 old[10*KEY_ELEM];
    int i = 0;
    for(i = 0; i < 10 * KEY_ELEM; i++){
        old[i] = rand();
        //old[i] = rand48();
    }
#endif
    u32 *key_vett=(u32*)Calloc(10*KEY_ELEM, sizeof(u32),"Calloc key");
    memcpy(key_vett, old, sizeof(u32)*10*KEY_ELEM);

    return key_vett; 
}

u32* genRandKeys(int num_keys, int seed){
    u32 *randkeys;
    int i, j;

    i = j = 0;
    randkeys = NULL;

    if( num_keys <= 0){
        fprintf(stderr,"[ERROR]: invalid argument num_keys\n");
        exit(EXIT_FAILURE);
    }
    randkeys = (u32*) Malloc( (num_keys * KEY_ELEM) * sizeof(u32), "Malloc randkeys");

    srand48(seed);

    // The first key is the special key with all bit setted
    // In this way we can guarantee that all the key variable are tested during 
    // the linearity tests
    for( j = 0; j < KEY_ELEM; j++){
        randkeys[j] = 0xFFFFFFFF;
    }

    for(i = 1; i < num_keys; i++){
        for(j = 0; j < KEY_ELEM; j++){
            randkeys[ (i * KEY_ELEM) + j ] = rand();
        }
    }

#ifdef TRIVIUM_CIPHER 
    for(i = 1; i <= num_keys; i++){
        randkeys[(i*KEY_ELEM) - 1] &= 0xFFFF0000; 
    }
#endif

    return randkeys;
}


u32* genAttackKeys(int seed, int paper_keys){
    int i, j, index, count;
    u32 *random_keys;
    u32 * key_vett;


    i = j = count = index = 0;
    random_keys = key_vett = NULL;
    if(paper_keys){
        random_keys = genPaperKeys();
    } else {
        random_keys = genRandKeys(NUM_RAND_KEY, seed);
    }
    key_vett = (u32*) Calloc(KEYS*KEY_ELEM, sizeof(u32), "Calloc key_vett");

    // The first key is the special key 0x0, that is needed for the linearity tests
    index = KEY_ELEM;
    //// The random keys are stored in positions in the range 1 to 10
    memcpy(&(key_vett[index]), random_keys, sizeof(u32) * KEY_ELEM * NUM_RAND_KEY);
    index += KEY_ELEM * NUM_RAND_KEY ;

    // We store the keys k_{i,j} where i < j and 0 <= i,j < 9 in positions in the range (11,55) 
    for( i = 0; i < NUM_RAND_KEY ; i++){
        for( j = i+1; j < NUM_RAND_KEY ; j++, index += KEY_ELEM){
            sumKeys(&(key_vett[index]), &(random_keys[i*KEY_ELEM]), &(random_keys[j*KEY_ELEM]));
        }
    }

    // We store the keys k_{i,j,l} where i < j < l and 0 <= i,j,l < 9 in positions in the range 56-63
    sumKeys(&(key_vett[index]), &(random_keys[0]), &(random_keys[1*KEY_ELEM])); // 
    sumKeys(&(key_vett[index]), &(key_vett[index]), &(random_keys[2*KEY_ELEM])); // aka K_(0,1,2)

    index = index + KEY_ELEM;

    sumKeys(&(key_vett[index]), &(random_keys[3*KEY_ELEM]), &(random_keys[4*KEY_ELEM])); // 
    sumKeys(&(key_vett[index]), &(key_vett[index]), &(random_keys[5*KEY_ELEM])); // aka K_(3,4,5)

    index = index + KEY_ELEM;

    sumKeys(&(key_vett[index]), &(random_keys[6*KEY_ELEM]), &(random_keys[7*KEY_ELEM])); // 
    sumKeys(&(key_vett[index]), &(key_vett[index]), &(random_keys[8*KEY_ELEM])); // aka K_(6,7,8)

    index = index + KEY_ELEM;

    sumKeys(&(key_vett[index]), &(random_keys[9*KEY_ELEM]), &(random_keys[0])); // 
    sumKeys(&(key_vett[index]), &(key_vett[index]), &(random_keys[1*KEY_ELEM])); // aka K_{,0,1)

    index = index + KEY_ELEM;

    sumKeys(&(key_vett[index]), &(random_keys[2*KEY_ELEM]), &(random_keys[3*KEY_ELEM])); // 
    sumKeys(&(key_vett[index]), &(key_vett[index]), &(random_keys[4*KEY_ELEM])); // aka K_(2,3,4)

    index = index + KEY_ELEM;

    sumKeys(&(key_vett[index]), &(random_keys[5*KEY_ELEM]), &(random_keys[6*KEY_ELEM])); // 
    sumKeys(&(key_vett[index]), &(key_vett[index]), &(random_keys[7*KEY_ELEM])); // aka K_(5,6,7)

    index = index + KEY_ELEM;

    sumKeys(&(key_vett[index]), &(random_keys[8*KEY_ELEM]), &(random_keys[9*KEY_ELEM])); //
    sumKeys(&(key_vett[index]), &(key_vett[index]), &(random_keys[0])); // aka K_(8,9,0)

    index = index + KEY_ELEM;

    sumKeys(&(key_vett[index]), &(random_keys[1*KEY_ELEM]), &(random_keys[2*KEY_ELEM])); // 
    sumKeys(&(key_vett[index]), &(key_vett[index]), &(random_keys[3*KEY_ELEM])); // aka K_(1,2,3)
    index = index + KEY_ELEM;

    free(random_keys);
    return key_vett;
}


void sumKeys(u32 * out, u32 * first, u32 * second){
    int i = 0;
    for(i = 0; i < KEY_ELEM; i++){
        out[i] = first[i] ^ second[i];
    }
}


void arrangeKeysForGPU(u32* keys, u32 num_of_keys, u32 key_size){
    u32 *keys_reordered;
    u32 i;
    u32 j;
    u32 idx_src;
    u32 idx_dst;
    if( NULL == keys){
        fprintf(stderr,"[ERROR]: Invalid parameter keys\n");
        exit(EXIT_FAILURE);
    }
    if( num_of_keys == 0){
        fprintf(stderr,"[ERROR]: Invalid parameter num_of_keys = 0\n");
        exit(EXIT_FAILURE);
    }
    if( num_of_keys % WARPSIZE){
        fprintf(stderr,"[ERROR]: Invalid parameter num_of_keys\n");
        exit(EXIT_FAILURE);
    }

    i = j = idx_src = idx_dst = 0;
    keys_reordered = NULL;


    keys_reordered = (u32*)Malloc(sizeof(u32) * key_size * num_of_keys, "Malloc keys_reordered");

    for( i = 0; i < num_of_keys; i++){
        for( j = 0; j < key_size; j++){
            idx_src = (i * key_size) + j;
            idx_dst = i + (j * num_of_keys);
            keys_reordered[idx_dst] = keys[idx_src];
        }
    }

    memcpy(keys, keys_reordered, (sizeof(u32) * key_size * num_of_keys) );
}


unsigned long long getMaxNumMask(u32 alpha){
    u32 i;
    unsigned long long total;

    i = 0;
    total = 0;

    if( 1 == alpha ){
        return (unsigned long long) 2*alpha;
    }
    for(i =0 ; i <= (alpha-2)/3 ;i++ ){
        ; // It is not an error, we need the value of i after this loop
    }
    total = (unsigned long long)(1 << (alpha-i) ) * coeffBin(alpha,i);
    if( 0 == total){
        total = 1;
    }
    return total;
}


u32 * setBitunsupported(u32* base, u8 bit, u8 state){
	
	fprintf(stderr,"[ERROR]: unsupported cipher\n");
	exit(EXIT_FAILURE);
}
//#define SET_BITR(cipher,base,beta,v) setBit## cipher(base,beta,v)
//#define SET_BIT(cipher,base,beta,v) SET_BITR(cipher,base,beta,v)
u32* generateCubeCorners(u32 * beta_indices, u32 beta){
    u32 *base;
    u32 index;
    u32 i;
    u32 j;
    u32 local_var;

    base = NULL;
    index = 1 << beta;
    i = j = local_var = 0;

    base = (u32*)Calloc(IV_ELEM,sizeof(u32), "[generateCubeCorners]: Calloc base");
    for(i = 0; i < index; i++){
	    j =0;
	    local_var  = i;
	    while( local_var > 0 && j < beta){
		    if( local_var & 0x1){
		SET_BIT(CIPHER,base,beta_indices[j],i);
		    }
		    j++;
		    local_var = local_var >> 1;
	    }
    }
    return base;
}


unsigned long long coeffBin(int n, int k){
	unsigned long long num;
	unsigned long long den;
	int i;
	int num_loop;
	int den_loop;


	num = den = 1;
	i = num_loop = den_loop = 0;
	if(n < k ){
		return 0;
	}

	if(n == k ){
		return 1;
	}

	if( k == 1){
		return n;
	}

	i = n-k;

	num_loop = MAX(k, (n-k));
	den_loop = MIN(k, (n-k));

	for(i = 1; i <= den_loop ; i++){
		den = den * i;
	}

	for(i = num_loop +1 ; i <= n; i++ ){
		num = num * i;
	}

	return num/den;
}


cubesPtr readBinaryOutput(char * pathname, int num_cubes, int cube_sizes, int init_cipher_round){
	int i;
	int j;
	int idx_c;
	int last_size;
	u32 idx_b;
	u32 idx_e;
	u32 *ptr;
	cubesPtr cubes;
	size_t ptr_elems;
	int readed_elem;
	FILE *fin;

	if(NULL == pathname || cube_sizes <= 0){
		fprintf(stderr, "[ERROR]: Invalid parameter\n");
		return NULL;
	}

	if( num_cubes <= 0 ){
		return NULL;
	}

	i = j = idx_c = last_size = 0;
	idx_b = idx_e = 0;
	ptr = NULL;
	cubes = NULL;
	ptr_elems = 0;
	readed_elem = 0;
	fin = NULL;


	cubes = (cubesPtr)Malloc(sizeof(struct cubes),"Malloc cubes");
	cubes->ccm_vett = (u32*)Malloc(sizeof(u32) * IV_ELEM * num_cubes, "Malloc cubes->ccm_vett");
	cubes->cem_vett = (u32*)Malloc(sizeof(u32) * IV_ELEM * num_cubes, "Malloc cubes->cem_vett");
	cubes->dim_cubes = (u32*) Malloc(sizeof(u32) * num_cubes, "Malloc cubes->dim_cubes");
	cubes->output_round = (u32*) Malloc(sizeof(u32) * num_cubes, "Malloc cubes->output_round");
	cubes->num_cubes = (u32*) Calloc(1 + cube_sizes, sizeof(u32) , "Calloc cubes->num_cubes");
	cubes->tot_num_cubes = num_cubes;

	fin = Fopen(pathname, "rb", "Fopen fin");

	ptr_elems=(2 * IV_ELEM) + 2;
	ptr=(u32*)Malloc(sizeof(u32)*ptr_elems, "Malloc ptr");

	for(i = 0, idx_b = 0, idx_c = 1, idx_e = 0, last_size = 0; i < num_cubes; i++){
		readed_elem = fread(ptr, sizeof(u32), ptr_elems,fin);
		if((size_t)readed_elem != ptr_elems){
			fprintf(stderr,"Malformed binary output file");
			exit(EXIT_FAILURE);
		}
		for(j = 0; j < IV_ELEM; j++, idx_b++){
			cubes->ccm_vett[idx_b] = ptr[j]; 
		}
		for(j = 0; j < IV_ELEM; j++, idx_e++){
			cubes->cem_vett[idx_e] = ptr[IV_ELEM + j]; 
		}
		cubes->output_round[i] = ptr[ (2 * IV_ELEM)] - init_cipher_round;
		cubes->dim_cubes[i] = ptr[ (2 * IV_ELEM) + 1];
		if( last_size == 0){
			last_size = ptr[ (2 * IV_ELEM) + 1];
		}

		if( last_size == ptr[ (2 * IV_ELEM) + 1] ){
			cubes->num_cubes[idx_c]++;
		} else {
			idx_c++;
			last_size = ptr[ (2 * IV_ELEM) + 1];
		}
	}

	// Prefix-sum
	for(i = 1; i <= cube_sizes; i++){
		cubes->num_cubes[i] = cubes->num_cubes[i] + cubes->num_cubes[i-1];
	}

	fclose(fin);
	free(ptr);
	return cubes;
}


u32 dumpBinaryOutput(u32 * host_k2out,u32 num_mask, u32 dim_cube_imask, u32 alpha, u32 beta, u32 *mask_vett, u32* host_cdbms, u32* host_icdb, FILE* fout, int cipher_round){
	u32 i;
	u32 count;
	u32 local_val;
	u32 local_count;
	u32 mask_shift;
	u32 index_mask;
	u32 new_mask;

	i = count = local_val = local_count = mask_shift = index_mask = new_mask = 0;

	if( NULL == host_k2out || 0 == num_mask || NULL == mask_vett || NULL == host_cdbms){
		fprintf(stderr, "[ERROR]: Invalid parameter\n");
		return 0;
	}

	if( fout == NULL){
		fout=stderr;
	}
	size_t ptr_elems=(2 * IV_ELEM) + 2;
	u32 *ptr=(u32*)Malloc(sizeof(u32)*ptr_elems, "Malloc ptr");
	for( i = 0 ; i < num_mask; i++){
		if( host_k2out[i] > 0 ){
			local_val = host_k2out[i];
			local_count = 0;
			while(local_val > 0){
				if( local_val & 0x1){
					mask_shift = 1 << (alpha - dim_cube_imask);
					index_mask = i / ( mask_shift);
					new_mask = getExaustiveMask( (i % mask_shift),mask_vett[index_mask]);

					int j =0;
					for(j=0;j < IV_ELEM;j++){
						ptr[j] = host_cdbms[(mask_vett[index_mask]*IV_ELEM) + j] ^ host_icdb[j];
					}

					for(j=0;j < IV_ELEM;j++){
						ptr[(IV_ELEM) + j] = host_cdbms[(mask_vett[index_mask]*IV_ELEM) + j] ^ host_cdbms[(new_mask * IV_ELEM) + j];
					}

					ptr[(2*IV_ELEM)] = 31 - local_count + cipher_round;
					ptr[(2*IV_ELEM) + 1] = dim_cube_imask + beta;

					fwrite(ptr,sizeof(u32), ptr_elems,fout);
					count++;
				}

				local_count++;
				local_val = local_val >> 1;
			}
		}	
	}
	return count;
}

u32 getExaustiveMask(u32 idx, u32 starting_mask){

	u32 local_imask;
	u32 k;
	u32 mask_idx;
	u32 one_count;
	u32 base_addr;
	u32 local_value;


	local_value  = idx;
	local_imask = starting_mask;
	k = mask_idx = one_count = base_addr = 0;

	while( local_value > 0){
		if(local_value & 0x1){
			if(1 == k){	
				for( k = 0; k < one_count; k++){
					while( ( ((local_imask)>> mask_idx) & 0x1) ){
						mask_idx++;
					}

					mask_idx++;
				}
				k=0;
				one_count = 0;
			}
			while( ( ((local_imask)>> mask_idx) & 0x1) ){
				mask_idx++;
			}

			base_addr  ^= (1 << mask_idx);	
			mask_idx++;
		}else{	
			one_count++;
			k = 1;
		}
		local_value = local_value >> 1;
	}
	return (base_addr ^ local_imask);
}




void setBit(u32 index, u32 value, u32* base){
	if(NULL == base){
		return;
	}
	u32 tmp = value << index;

	*base ^= tmp;
}


u32* generateIvMask(u32 M , u32 N, u32 num_mask){
	int i;
	int x;
	int y;
	int z;
	int bit_count;
	int *p;
	u32 *b;
	u32 *out;
	u32 count;
	u32 tmp;

	i = x = y = z = bit_count = 0;
	p = NULL;
	b = out = NULL;
	count = tmp = 0;

	if ( N > U32SIZE ){
		fprintf(stderr, "ERROR generateIvMask: invalid parameter\n");
		return NULL;
	}
	p = (int*)Malloc( (N+2) * sizeof(int),"Malloc p");
	b = (u32*)Malloc( N * sizeof(u32),"Malloc b");
	out = (u32*) Malloc(num_mask * sizeof(u32), "Malloc out");
	count = 0,tmp =0;

	inittwiddle(M,N,p);
	for(i = 0; i != N-M; i++){
		b[i] = 0;
		setBit(i,0,&tmp);
	}
	while(i != N){
		b[i] = 1;
		setBit(i,1,&tmp);
		i++;
	}
	out[count] = tmp;
	count++;

	while(!twiddle(&x, &y, &z, p))    {
		bit_count = 0;
		tmp =0;
		b[x] = 1;
		b[y] = 0;
		for(i = 0; i != N; i++){ 
			if(1 == b[i]){
				bit_count++;
			}
			setBit(i,b[i],&tmp);
		}
		if( bit_count != M){
			fprintf(stderr, "WARN : skypped\n");

		}
		else {
			out[count] = tmp;
			count++;
			if(count >= num_mask){
				break;
			}
		}
	}

	free(p);
	free(b);
	return out;
}

void freeCubes(cubesPtr c){
	if (NULL == c){
		return;
	}

	if(c->ccm_vett != NULL){
		free(c->ccm_vett);
	}

	if(c->cem_vett != NULL){
		free(c->cem_vett);
	}

	if(c->num_cubes != NULL){
		free(c->num_cubes);
	}

	if(c->dim_cubes != NULL){
		free(c->dim_cubes);
	}

	if(c->output_round != NULL){
		free(c->output_round);
	}
	free(c);
}
