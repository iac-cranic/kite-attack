/* <This program implements the Kite-Attack Framework, a GPU-tailored implementation of the Cube Attack.>
 * Copyright (C) <2015-2020> <Massimo Bernaschi> <massimo[DOT]bernaschi[AT]gmail[DOT]com>
 * Copyright (C) <2015-2020>  <Marco Cianfriglia> <marco[DOT]cianfriglia[AT]gmail[DOT]com>    
 * Copyright (C) <2015-2020> <Stefano Guarino> <ste[DOT]guarino[AT]gmail[DOT]com>
 * Copyright (C) <2015-2020><Flavio Lombardi> <flavio[DOT]lombardi[AT]cnr[DOT]it>
 * Copyright (C) <2015-2020> <Marco Pedicini> <m[DOT]pedicini[AT]gmail[DOT]com>
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

#include "cubeCuda.h"
#include "key_table.h"

#ifdef TRIVIUM_CIPHER
#include "Trivium.cu" //It is needed as the cipher function is defined as inline
#elif defined GRAIN128_CIPHER 
#include "Grain128.cu"
#endif

#define FULL_MASK 0xffffffff
#define MAX_MASK_SIZE_PER_WARP 20
#define MIN_CUDA_CAPABILITY 3
#define NTHREADS 1024

#define INFO(...) fprintf(log_file,__VA_ARGS__)

#define ERROR(...) fprintf(log_file,__VA_ARGS__); \
	fprintf(stderr, __VA_ARGS__); \
exit(EXIT_FAILURE);


#define ARGC 5
int DEBUG=0;
FILE *log_file = NULL;
char *output_dir = NULL;


u32 *device_k1_output   = NULL;
u32 *device_k2_output   = NULL;
u32 *device_key_table1  = NULL;
u32 *device_key_table2  = NULL;
u32 *device_key         = NULL;
u32 *device_icdb        = NULL;
u32 *device_cdbms       = NULL;
u32 *device_imask       = NULL;
u32 *device_bit_table   = NULL;
u32 *device_ccm         = NULL;
u32 *device_cem         = NULL;
u32 *device_cfbm        = NULL;


/*
 * Function: kernel1
 * ------------------------------------
 * It is responsible to compute the (2^(alpha - beta) * NUM_KEY) sums over cubes of dimension beta
 *
 * - k1o: (kernel1 output) it will store all the sums 
 * - k1o_dim: (kernel1 output dim) the size of table
 * - key_vett: a vector containing the keys (they are ordered to be efficiently accessed)
 * - cdbms:(Cubes of Dimension Beta MaskS) it contains the masks representing (2^(alfa-beta)) combinations, one for each warp
 * - icdb: (Indexes Cubes Dimension Beta) it represents the indexes of I_min (they are the same for all warps)
 * - icdb_size: it is the size of I_min (=beta)
 * - num_round: the number of round of the target cipher
 * - offset: it is used when (2^(alfa-beta)) is greaten than the maximum number of warps per kernel launch 
 */
__global__ void kernel1(u32 * k1o, u32 k1o_dim, u32 * key_vett, u32 * cdbms, u32*icdb, u32 icdb_size, u32 num_round, u32 offset){

    extern __shared__ u32 position[]; // each warp has access to icdb_size elements 

    u32 myindex = (blockIdx.x * blockDim.x) + threadIdx.x + offset; 

    if( myindex >= k1o_dim){
        return;
    }



    // First every thread in a warp computes the indexes of the cube I_min
    // The indexes are stored in shared memory that is faster than global
    u32 iv_base0 = icdb[0];
    u32 iv_base1 = icdb[1];
    u32 iv_base2 = icdb[2];

    u32 myindex_iv = (threadIdx.x  / WARPSIZE) * icdb_size ;

    u32 i = 0 ;
    u32 count_shared = 0;
    if( 0 == (myindex %WARPSIZE)){
        for( i = 0 ; i < U32SIZE && count_shared < icdb_size; i++){
            if( (iv_base0 >> i ) & 0x1){
                position[count_shared + myindex_iv] = i;
                count_shared++;
            }
        }
        for( i = 0 ; i < U32SIZE  && count_shared < icdb_size; i++){
            if( (iv_base1 >> i ) & 0x1){
                position[count_shared + myindex_iv] = i + U32SIZE;
                count_shared++;
            }
        }
#ifdef TRIVIUM_CIPHER
        i = (U32SIZE/2);
#elif defined GRAIN128_CIPHER
        i = 0; 
#else
        i = 0; 
#endif
           for( ; i < U32SIZE  && count_shared < icdb_size; i++){
               if( (iv_base2 >> i ) & 0x1){
                   position[count_shared + myindex_iv] = i + U32SIZE + U32SIZE;
                   count_shared++;
               }
           }
    }
    __syncthreads();

    myindex_iv = (myindex / WARPSIZE ) * IV_ELEM;
    iv_base0 = cdbms[myindex_iv];
    iv_base1 = cdbms[myindex_iv+1];
    iv_base2 = cdbms[myindex_iv+2];

    myindex_iv = (threadIdx.x  / WARPSIZE) * icdb_size ;

    // Now the real cube computation can start
    count_shared =  1 << icdb_size;
    u32 iv_curr0 = 0 , iv_curr1 = 0, iv_curr2 = 0;
    u32 j = 0, local_count = 0;
    u32 tmp = 0;
    j = myindex % WARPSIZE; 

#ifdef TRIVIUM_CIPHER 
    u32 key0 = key_vett[ j ];
    u32 key3 = key_vett[ j + WARPSIZE ];
    u32 key1 = key_vett[ j + (2 * WARPSIZE) ];
    u32 key4 = key_vett[ j + (3 * WARPSIZE) ];
    u32 key2 = key_vett[ j + (4 * WARPSIZE) ];
    u32 key5 = key_vett[ j + (5 * WARPSIZE) ];
#elif defined GRAIN128_CIPHER 
    u32 key0 = key_vett[ j ];
    u32 key4 = key_vett[ j + WARPSIZE ];
    u32 key1 = key_vett[ j + (2 * WARPSIZE) ];
    u32 key5 = key_vett[ j + (3 * WARPSIZE) ];
    u32 key2 = key_vett[ j + (4 * WARPSIZE) ];
    u32 key6 = key_vett[ j + (5 * WARPSIZE) ];
    u32 key3 = key_vett[ j + (6 * WARPSIZE) ];
    u32 key7 = key_vett[ j + (7 * WARPSIZE) ];
#else
    //ERROR: you must specify a supported cipher
#endif

    u32 sumA = 0 , sumB = 0;

    for(i = 0 ; i < count_shared ; i++){
        local_count = i;
        j = 0;
        iv_curr0 = iv_base0; 
        iv_curr1 = iv_base1;
        iv_curr2 = iv_base2;

        // Computing IV value (a cube corner) 
        while(local_count > 0){
            if( local_count & 0x1){
                if(position[myindex_iv+j] < U32SIZE){
                    tmp = 1 << position[myindex_iv +j];
                    iv_curr0 += tmp;
                }
                else if(position[myindex_iv+j] < (2*U32SIZE)){
                    tmp = 1 << ( position[myindex_iv +j] - U32SIZE);
                    iv_curr1 += tmp;
                }
                else{
                    tmp = 1 << ( position[myindex_iv +j] - (2*U32SIZE));
                    iv_curr2 += tmp;
                }

            }
            j++;
            local_count = local_count >> 1;
        }
        // We compute together the sum over a cube for different keys 
        // TRIVIUM : (K1 = (key0 || key1 || key2), K2 = (key3 || key4 || key5) )
        // GRAIN18 : (K1 = (key0 || key1 || key2 || key3), K2 = (key4 || key5 || key6 || key7) )
        u32 a = 0;
        u32 b = 0;
#ifdef TRIVIUM_CIPHER
        a =  k_trivium(key0, key1, key2, iv_curr0, iv_curr1, iv_curr2, num_round);
        b =  k_trivium(key3, key4, key5, iv_curr0, iv_curr1, iv_curr2, num_round);
#elif defined GRAIN128_CIPHER
        a =  k_grain128(key0, key1, key2, key3, iv_curr0, iv_curr1, iv_curr2, num_round);
        b =  k_grain128(key4, key5, key6, key7, iv_curr0, iv_curr1, iv_curr2, num_round);
#endif
        sumA = sumA ^ a;
        sumB = sumB ^ b;

    }


    // We store the results of cube of size Beta 
    myindex_iv = myindex / WARPSIZE;
    k1o[myindex + (myindex_iv*WARPSIZE)] = sumA;
    k1o[myindex+ (myindex_iv*WARPSIZE)+WARPSIZE] = sumB;

}

/*
 *  Function: kernel2
 * ------------------------------------
 * It combines the cubes computed by kernel1 to obtain cube of dimension > Beta and < alpha.
 * On each cube it performs linearity tests and it outputs the cube mask and the output bit of cube that
 * passes all the tests and that are not costant to 0 or 1.

 * - bcubes_table: the table containing the cubes of dimension Beta computed by kernel1 
 * - bcubes_table_len: the size of bcubes_table [DEPRECATED]
 * - cube_mask_vect: a vector containing masks representing which cube corners the threads should combine 
 * - cube_mask_vect_len: the number of masks that are tested. It represents the len of cube_mask_vect 
 * - active_bits_masks: it represents how many active bits of the mask contains. 
 * - key_table_idx1: the first vector of keys indexes used for the linearity tests
 * - key_table_id2: the second vector of keys indexes used for the linearity tests
 * - k2out: is the output vector of kernel2. It contains the results of the linearity tests
 * - offset: it represents the number of masks already checked
 * - alpha: it represents the max size of a mask
 */

__global__ void kernel2(u32 * bcubes_table,u32 bcubes_table_len,u32 * cube_mask_vect, u32 cube_mask_vect_len, u32 active_bits_masks, u32* key_table_idx1, u32* key_table_idx2, u32* k2out, u32 offset, u32 alpha){
    int myindex = ( (blockIdx.x * blockDim.x) + threadIdx.x ) ; 

    int warpId = myindex / (WARPSIZE );

    myindex = myindex % WARPSIZE; 

    if(warpId >= cube_mask_vect_len){
        return;
    }

    u32 my_imask = cube_mask_vect[warpId+offset]; // offset is needed to handle multiple invocations of kernel2

    u32 index = 0;
    u32 ext_count = 1 << ( alpha- active_bits_masks);
    u32 l = 0, base_addr = 0;
    u32 sumA = 0 ;
    u32 sumB = 0;
    for( l = 0; l < ext_count ; l++){
        u32 k = 0;

        u32 mask_idx = 0, one_count = 0;
        sumA = sumB = 0;
        base_addr = 0;
        u32 local_value  = l;

        while( local_value > 0){
            if(local_value & 0x1){
                if(1 == k){	
                    for( k = 0; k < one_count; k++){
                        while( ( ((my_imask)>> mask_idx) & 0x1) ){
                            mask_idx++;
                        }
                        mask_idx++;
                    }
                    k=0;
                    one_count = 0;
                }
                while( ( ((my_imask)>> mask_idx) & 0x1) ){
                    mask_idx++;
                }
                base_addr  ^= (1 << mask_idx);	
                mask_idx++;
            }
            else{	
                one_count++;
                k = 1;
            }
            local_value = local_value >> 1;
        }


        u32 i = 0, count = 1 << active_bits_masks;

        for( i =0 ; i < count; i++, k = 1){
            index = base_addr;
            local_value  = i;
            mask_idx = 0, one_count = 0, k =0;
            while( local_value > 0){
                if(local_value & 0x1){
                    if(1 == k){	
                        for( k = 0; k < one_count; k++){
                            while( ! ( ((my_imask)>> mask_idx) & 0x1) ){
                                mask_idx++;
                            }
                            mask_idx++;
                        }
                        k=0;
                        one_count = 0;
                    }
                    while( ! ( ((my_imask)>> mask_idx) & 0x1) ){
                        mask_idx++;
                    }
                    index  ^= (1 << mask_idx);	
                    mask_idx++;
                }
                else {	
                    one_count++;
                    k = 1;
                }
                local_value = local_value >> 1;
            }

            index  = (index  * KEYS ) + myindex;

            sumA = sumA ^ bcubes_table[ index ];
            sumB = sumB ^ bcubes_table[index  + WARPSIZE ];
        }

        __syncthreads();
        u32 input_index = myindex * KEY_TABLE_COLUMN;
        u32 tmp = 0, a  = 0, b =0, c = 0, d = 0, e = 0, f = 0, g = 0;

        // Computing the linearity tests for the current cubes
        // key_table_idx1 and key_table_idx2 contain the indexes of 
        // the keys that should be combined for the tests

        // Linearity tests sumA
        a = key_table_idx1[input_index];
        b = key_table_idx1[input_index + 1];
        c = key_table_idx1[input_index + 2];


        d = __shfl_sync(FULL_MASK, sumA,a); 
        f = __shfl_sync(FULL_MASK, sumA,b); 
        d ^= f;
        f = __shfl_sync(FULL_MASK,sumA,c);
        d ^= f;
        d = d ^ sumA;


        // Linearity tests sumB
        a = key_table_idx2[input_index];
        b = key_table_idx2[input_index + 1];
        c = key_table_idx2[input_index + 2];

        e = __shfl_sync(FULL_MASK,sumA,a);
        g = __shfl_sync(FULL_MASK,sumA,b);
        e ^= g;
        g = __shfl_sync(FULL_MASK,sumA,c);
        e ^= g;
        e = e ^ sumB;

        a = 0;
        for(i = START_IDX_LIN_TEST; i < U32SIZE; i++){
            g = __shfl_sync(FULL_MASK,d,i);
            a |= g;	
        }
        for(i = 0; i < NUM_TESTS; i++){
            g = __shfl_sync(FULL_MASK,e,i);
            a |= g;	
        }

        u32 h = 0;
        // We check if there is at least one polynomial that passes all the linearity test
        // (i.e. if there is a bit 0)
        if( a != FULL_MASK){
            // There exists (at least) one candidate linear polynomial
            // We now check that the polynomial is not constant 
            b = FULL_MASK;
            c = 0;
            for(i = 0; i < U32SIZE; i++){
                f = __shfl_sync(FULL_MASK,sumA,i);
                b &=f;

                c |= f;

                f = __shfl_sync(FULL_MASK,sumB,i);
                b &= f;

                c |= f;

            }

            // a: tests results
            // b: & keys 
            // c: | keys

            h = 0;
            for(i = (U32SIZE -1); ; i--){
                // We check if the i-th poly passes all the tests
                tmp = (a >> i) & 0x1; 
                if(tmp == 0){
                    d = ( b >> i) & 0x1; // Is it constant 1?
                    e = ( ( c >> i) & 0x1); // Is it constant 0?

                    if(d != 1 && e != 0 && myindex == 0){
#ifdef DEBUG
                        printf("warp : %d : imask: %08X- bit: %d - LINEAR\n",warpId, my_imask^base_addr,  U32SIZE - i);
#endif

#ifdef TRIVIUM_CIPHER
                        h^=(1 << (U32SIZE - 1 -i));
#else
                        h ^= (1 << i);
#endif
                    }					

                }
                if(i == 0){
                    break;
                }
            }
        }

        // Only the thread with ID 0 (in the warp) store the result.
        // The result provides information about all the 32 polynomial tested for the current cube
        if(myindex == 0){
            k2out[ (warpId*ext_count)+l ] = h;
        }
        __syncthreads();
    }
    return;
}



/*
 * Function: kernel1_superpoly
 * ------------------------------------
 * It is responsible to compute the (2^(alpha - beta) * NUM_KEY) sums over cubes of dimension beta
 * It is essentially the same as kernel1 except that it manages more keys. It is better to have
 * a dedicated kernel to allow compier to better optimize the code w.r.t the number of key
 * - k1o: (kernel1 output) it will store all the sums 
 * - k1o_dim: (kernel1 output dim) the size of table
 * - key_vett: a vector containing the keys (they are ordered to be efficiently accessed)
 * - cdbms:(Cubes of Dimension Beta MaskS) it contains the masks representing (2^(alfa-beta)) combinations, one for each warp
 * - icdb: (Indexes Cubes Dimension Beta) it represents the indexes of I_min (they are the same for all warps)
 * - icdb_size: it is the size of I_min (=beta)
 * - num_round: the number of round of the target cipher
 * - offset: it is used when (2^(alfa-beta)) is greaten than the maximum number of warps per kernel launch 
 */
__global__ void kernel1_superpoly(u32 * k1o, u32 k1o_dim, u32 * key_vett, u32 * cdbms, u32*icdb, u32 icdb_size, u32 num_round, u32 offset){

    extern __shared__ u32 position[]; // each warp has access to icdb_size elements 

    u32 myindex = (blockIdx.x * blockDim.x) + threadIdx.x + offset; 

    if( myindex >= k1o_dim){
        return;
    }



    // First every thread in a warp computes the indexes of the cube I_min
    // The indexes are stored in shared memory that is faster than global
    u32 iv_base0 = icdb[0];
    u32 iv_base1 = icdb[1];
    u32 iv_base2 = icdb[2];

    u32 myindex_iv = (threadIdx.x  / WARPSIZE) * icdb_size ;

    u32 i = 0 ;
    u32 count_shared = 0;
    if( 0 == (myindex %WARPSIZE)){
        for( i = 0 ; i < U32SIZE && count_shared < icdb_size; i++){
            if( (iv_base0 >> i ) & 0x1){
                position[count_shared + myindex_iv] = i;
                count_shared++;
            }
        }
        for( i = 0 ; i < U32SIZE  && count_shared < icdb_size; i++){
            if( (iv_base1 >> i ) & 0x1){
                position[count_shared + myindex_iv] = i + U32SIZE;
                count_shared++;
            }
        }
#ifdef TRIVIUM_CIPHER
        i=(U32SIZE/2);
#elif defined GRAIN128_CIPHER
        i = 0;
#else
        i=0;
#endif
        for(  ; i < U32SIZE  && count_shared < icdb_size; i++){
            if( (iv_base2 >> i ) & 0x1){
                position[count_shared + myindex_iv] = i + U32SIZE + U32SIZE;
                count_shared++;
            }
        }
    }
    __syncthreads();

    myindex_iv = (myindex / WARPSIZE ) * IV_ELEM;
    iv_base0 = cdbms[myindex_iv];
    iv_base1 = cdbms[myindex_iv+1];
    iv_base2 = cdbms[myindex_iv+2];

    myindex_iv = (threadIdx.x  / WARPSIZE) * icdb_size ;

    // Now the real cube computation can start
    count_shared =  1 << icdb_size;
    u32 iv_curr0 = 0 , iv_curr1 = 0, iv_curr2 = 0;
    u32 j = 0, local_count = 0;

    j = myindex % WARPSIZE; 

    u32 tmp = 0;
    u32 sumA = 0 , sumB = 0, sumC = 0;
#ifdef TRIVIUM_CIPHER 
    u32 key0 = key_vett[ j ];
    u32 key3 = key_vett[ j + WARPSIZE ];
    u32 key6 = key_vett[ j + (2 * WARPSIZE) ];

    u32 key1 = key_vett[ j + (3 * WARPSIZE) ];
    u32 key4 = key_vett[ j + (4 * WARPSIZE) ];
    u32 key7 = key_vett[ j + (5 * WARPSIZE) ];

    u32 key2 = key_vett[ j + (6 * WARPSIZE) ];
    u32 key5 = key_vett[ j + (7 * WARPSIZE) ];
    u32 key8 = key_vett[ j + (8 * WARPSIZE) ];

#elif defined GRAIN128_CIPHER 
    u32 key0  = key_vett[ j ];
    u32 key4  = key_vett[ j + WARPSIZE ];
    u32 key8  = key_vett[ j + (2 * WARPSIZE) ];
    u32 key12 = key_vett[ j + (3 * WARPSIZE) ];
    u32 key16 = key_vett[ j + (4 * WARPSIZE) ];

    u32 key1  = key_vett[ j + (5 * WARPSIZE) ];
    u32 key5  = key_vett[ j + (6 * WARPSIZE) ];
    u32 key9  = key_vett[ j + (7 * WARPSIZE) ];
    u32 key13 = key_vett[ j + (8 * WARPSIZE) ];
    u32 key17 = key_vett[ j + (9 * WARPSIZE) ];


    u32 key2  = key_vett[ j + (10* WARPSIZE) ];
    u32 key6  = key_vett[ j + (11* WARPSIZE) ];
    u32 key10 = key_vett[ j + (12* WARPSIZE) ];
    u32 key14 = key_vett[ j + (13* WARPSIZE) ];
    u32 key18 = key_vett[ j + (14* WARPSIZE) ];

    u32 key3  = key_vett[ j + (15* WARPSIZE) ];
    u32 key7  = key_vett[ j + (16* WARPSIZE) ];
    u32 key11 = key_vett[ j + (17* WARPSIZE) ];
    u32 key15 = key_vett[ j + (18* WARPSIZE) ];
    u32 key19 = key_vett[ j + (19* WARPSIZE) ];

    u32  sumD = 0, sumE = 0;
#endif


    for(i = 0 ; i < count_shared ; i++){
        local_count = i;
        j = 0;
        iv_curr0 = iv_base0; 
        iv_curr1 = iv_base1;
        iv_curr2 = iv_base2;

        // Computing IV value (a cube corner) 
        while(local_count > 0){
            if( local_count & 0x1){
                if(position[myindex_iv+j] < U32SIZE){
                    tmp = 1 << position[myindex_iv +j];
                    iv_curr0 += tmp;
                }
                else if(position[myindex_iv+j] < (2*U32SIZE)){
                    tmp = 1 << ( position[myindex_iv +j] - U32SIZE);
                    iv_curr1 += tmp;
                }
                else{
                    tmp = 1 << ( position[myindex_iv +j] - (2*U32SIZE));
                    iv_curr2 += tmp;
                }

            }
            j++;
            local_count = local_count >> 1;
        }
        // We compute together the sum over a cube for different keys 
        // TRIVIUM : (K1 = (key0 || key1 || key2), K2 = (key3 || key4 || key5) )
        // GRAIN18 : (K1 = (key0 || key1 || key2 || key3), K2 = (key4 || key5 || key6 || key7) )
        u32 a = 0;
#ifdef TRIVIUM_CIPHER
        a =  k_trivium(key0, key1, key2, iv_curr0, iv_curr1, iv_curr2, num_round);
        sumA = sumA ^ a;
        a =  k_trivium(key3, key4, key5, iv_curr0, iv_curr1, iv_curr2, num_round);
        sumB = sumB ^ a;
        a =  k_trivium(key6, key7, key8, iv_curr0, iv_curr1, iv_curr2, num_round);
        sumC = sumC ^ a;

#elif defined GRAIN128_CIPHER
        a =  k_grain128(key0, key1, key2, key3, iv_curr0, iv_curr1, iv_curr2, num_round);
        sumA = sumA ^ a;
        a =  k_grain128(key4, key5, key6, key7, iv_curr0, iv_curr1, iv_curr2, num_round);
        sumB = sumB ^ a;
        a =  k_grain128(key8, key9, key10, key11, iv_curr0, iv_curr1, iv_curr2, num_round);
        sumC = sumC ^ a;
        a =  k_grain128(key12, key13, key14, key15, iv_curr0, iv_curr1, iv_curr2, num_round);
        sumD = sumD ^ a;
        a =  k_grain128(key16, key17, key18, key19, iv_curr0, iv_curr1, iv_curr2, num_round);
        sumE = sumE ^ a;
#else
        //ERROR: you must specify a supported cipher
#endif
    }


    // We store the results of cube of size Beta 
    myindex_iv = myindex / WARPSIZE;
    myindex = myindex % WARPSIZE;
    k1o[myindex + (myindex_iv*KEYS_SUPERPOLY)] = sumA;
    k1o[myindex+ (myindex_iv*KEYS_SUPERPOLY)+WARPSIZE] = sumB;
    k1o[myindex+ (myindex_iv*KEYS_SUPERPOLY)+ (2 * WARPSIZE)] = sumC;
#ifdef GRAIN128_CIPHER
    k1o[myindex+ (myindex_iv*KEYS_SUPERPOLY)+ (3 * WARPSIZE)] = sumD;
    k1o[myindex+ (myindex_iv*KEYS_SUPERPOLY)+ (4 * WARPSIZE)] = sumE;
#endif
}

/*
 *  Function: kernel2_superpoly
 * ------------------------------------
 * It combines the cubes computed by kernel1_superpoly to obtain the cubes that pass the linearity tests.
 * For each cube computes the linear coefficients representing the superpoly.
 *

 * - bcubes_table: the table containing the cubes of dimension Beta computed by kernel1_superpoly 
 * - bcubes_table_len: the size of bcubes_table [DEPRECATED]

 * - ccm (cube_complete_mask) : contains the mask representing all the indexes of the cubes founded
 * - cfbm (cube_fixed_bit_mask) : the bit-mask represents the Beta indexes
 * - cem (cube_exhaust_mask) : contains the bit masks representing which bits are set to constant 1 . It is needed to compute the position in the bcubes_table
 * - cfbm_size : it represents the size of the variable part of the cubes (i.e. how many bits are setted) 
 * - cube_dim: the dimension of the cubes
 * - bit_table : it contains the bits of the variable part used for the cube. For each bit, it contains 0 if not used, the power of 2 w.r.t. its position in the bcubes_table otherwise.
 * - bit_table_dim: the dimension of the bit_table 
 * - offset: it represents the number of masks already checked
 * - k2sout : the output array 


 */
__global__ void kernel2_superpoly(u32 * bcubes_table, u32 bcubes_table_len, u32 * ccm, u32*cfbm, u32 *cem, u32 cfbm_size, u32 cube_dim, u32*bit_table, u32 bit_table_dim, u32 offset, u32* k2sout){

    extern __shared__ u32 position[]; // each warp has access to cfbm_size elements
    u32 myindex = (blockIdx.x * blockDim.x) + threadIdx.x + offset; 

    if( myindex >= bcubes_table_len){
        return;
    }	
    u32 myindex_iv = myindex / WARPSIZE;
    myindex_iv = myindex_iv * IV_ELEM;

    // Compute the position in the bcubes_table w.r.t. the exhaustive mask
    u32 iv_base0 = cem[myindex_iv];
    u32 iv_base1 = cem[myindex_iv+1];
    u32 iv_base2 = cem[myindex_iv+2];

    u32 i = 0 ;
    u32 base_addr_exaust=0;

    for( i = 0 ; i < U32SIZE; i++){
        if( (iv_base0 >> i ) & 0x1){
            base_addr_exaust += bit_table[31-i];
        }
    }
    for( i = 0 ; i < U32SIZE  ; i++){
        if( (iv_base1 >> i ) & 0x1){
            base_addr_exaust += bit_table[63-i];
        }
    }
#ifdef TRIVIUM_CIPHER
    i=(U32SIZE/2);
#elif defined GRAIN128_CIPHER
    i=0;
#endif
    for( ; i < U32SIZE ; i++){
        if( (iv_base2 >> i ) & 0x1){
            base_addr_exaust += bit_table[95-i];
        }
    }

    // Subtract the fixed part from the mask
    iv_base0 = cfbm[0] ^ ccm[myindex_iv];
    iv_base1 = cfbm[1] ^ ccm[myindex_iv+1];
    iv_base2 = cfbm[2] ^ ccm[myindex_iv+2];

    myindex_iv = (threadIdx.x  / WARPSIZE) * (cube_dim - cfbm_size) ;
    u32 count_shared = 0;
    if( 0 == (myindex %WARPSIZE)){
        for( i = 0 ; i < U32SIZE && count_shared < (cube_dim-cfbm_size); i++){
            if( (iv_base0 >> i ) & 0x1){
                position[count_shared + myindex_iv] = 31 -i;
                count_shared++;
            }
        }
        for( i = 0 ; i < U32SIZE  && count_shared < (cube_dim-cfbm_size); i++){
            if( (iv_base1 >> i ) & 0x1){
                position[count_shared + myindex_iv] = 63 -i ;
                count_shared++;
            }
        }
#ifdef TRIVIUM_CIPHER
        i = (U32SIZE/2);
#elif defined GRAIN128_CIPHER
        i =0;
#endif
        for(  ; i < U32SIZE && count_shared < (cube_dim-cfbm_size); i++){
            if( (iv_base2 >> i ) & 0x1)	{
                position[count_shared + myindex_iv] = 95 - i ;
                count_shared++;
            }
        }
    }
    __syncthreads();




    myindex_iv = (threadIdx.x  / WARPSIZE) * (cube_dim - cfbm_size) ;
    count_shared =  1 << (cube_dim - cfbm_size);
    u32 j = 0, local_count = 0;




    u32 sumA = 0 , sumB = 0, sumC = 0;
#ifdef GRAIN128_CIPHER
    u32 sumD = 0, sumE = 0;
#endif
    u32 tmp = 0;
    // This loop computes the vertices of the cubes and sums them
    for(i = 0 ; i < count_shared ; i++){
        local_count = i;
        j = 0;
        u32 index = 0;
        tmp = myindex % WARPSIZE;

        // Compute one vertex (IV value) 
        while(local_count > 0){
            if( local_count & 0x1){
                index += bit_table[position[myindex_iv+j]];
            }
            j++;
            local_count = local_count >> 1;
        }

        index += base_addr_exaust;
        index = index * KEYS_SUPERPOLY;

        sumA = sumA ^ bcubes_table[index+tmp];
        tmp +=WARPSIZE;
        sumB = sumB ^ bcubes_table[index+tmp];
        tmp += WARPSIZE;
        sumC = sumC ^ bcubes_table[index+tmp];
#ifdef GRAIN128_CIPHER
        tmp += WARPSIZE;
        sumD = sumD ^ bcubes_table[index+tmp];
        tmp += WARPSIZE;
        sumE = sumE ^ bcubes_table[index+tmp];
#endif  
    }

    __syncthreads();
    j = __shfl_sync(FULL_MASK,sumA,0); //Read the coefficient when the key is 0..0


    sumB ^= j;
    tmp = (myindex % WARPSIZE) < RESIDUAL_KEYS;
#ifdef TRIVIUM_CIPHER
    sumC ^= (j * tmp);// j must be added only to the sums for the coefficients of the first grade terms of the superpoly
#elif defined GRAIN128_CIPHER
    sumC ^=j;
    sumD ^=j;
    sumE ^= (j * tmp);// j must be added only to the sums for the coefficients of the first grade terms of the superpoly
#endif
    tmp = (myindex % WARPSIZE) > 0;
    sumA ^= ( j * tmp); // il thread somma 0



    myindex = (blockIdx.x * blockDim.x) + threadIdx.x + offset; 

    myindex_iv = myindex / WARPSIZE;

    myindex_iv = myindex_iv * KEYS_SUPERPOLY;
    myindex = myindex % WARPSIZE;

    k2sout[myindex_iv + myindex] = sumA;
    k2sout[myindex_iv + myindex + WARPSIZE] = sumB;
    k2sout[myindex_iv + myindex + ( 2 * WARPSIZE)] = sumC;
#ifdef GRAIN128_CIPHER
    k2sout[myindex_iv + myindex + ( 3 * WARPSIZE)] = sumD;
    k2sout[myindex_iv + myindex + ( 4 * WARPSIZE)] = sumE;
#endif

}

void cudaKernelCheck(char *msg){
    cudaError_t error = cudaGetLastError();
    if ( cudaSuccess != error ){
        fprintf(stderr, "%s: last error is %s\n", msg, cudaGetErrorString(error) );
        exit(EXIT_FAILURE);
    }
}


void cudaErrorCheck(cudaError_t error, const char * msg){
    if ( error != cudaSuccess){
        fprintf(stderr, "%s:%s\n ", msg, cudaGetErrorString(error));
        exit(EXIT_FAILURE);
    }
}

u32 * generateAlphaMask(u32* indices_array, u32 indices_array_len,  u32 num_cube){

    u32 i;
    u32 j;
    u32 index;
    u32 local_var;
    u32 *iv_vett;

    i = j = index = local_var = 0;
    iv_vett = NULL;

    if(NULL == indices_array || 0 == indices_array_len ){
        fprintf(stderr, "[ERROR]: Invalid parameter\n");
        return NULL;
    }

    iv_vett = (u32*)Calloc(IV_ELEM * num_cube , sizeof(u32),"[generateAlphaMask]: Calloc iv_vett");

    for(i = 0; i < num_cube; i++, index+=IV_ELEM){
        j = 0;
        local_var  = i ; 
        while( local_var > 0 && j < indices_array_len){
            if( local_var & 0x1){
#ifdef TRIVIUM_CIPHER
                setBitTrivium(&(iv_vett[index]), indices_array[j], 1);
#elif defined GRAIN128_CIPHER
                setBitGrain128(&(iv_vett[index]), indices_array[j], 1);
#else
                ERROR("Unsupported cipher");
#endif
            }
            j++;
            local_var = local_var >> 1;
        }
    }

    return iv_vett;
}


void freeConfig(config_ptr conf){
    if(NULL == conf){
        return;
    }
    Free(conf->alpha_indices);
    Free(conf->beta_indices);
    Free(conf->constant_indices);
    Free(conf->run_identifier);
    Free(conf->target_cipher);

    Free(conf);
}

config_ptr parseConfigFile(char * pathname){

    config_ptr conf;
    int ret;
    int i;
    char **key_vector, **value_vector;

    conf = NULL;
    ret = i = 0;
    key_vector = value_vector = NULL;

    if (NULL == pathname){
        return NULL;
    }
    conf = (config_ptr)Calloc(1,sizeof(config),"Calloc conf");

    ret = configurationFileParser(pathname, &key_vector, &value_vector);
    if( ret <= 0 ){
        ERROR("Invalid config_file\n");
    }

    for ( i = 0 ; i < ret ; i++){
        if ( 0 == strcmp(key_vector[i], TARGET_CIPHER_STRING)){
            conf->target_cipher = strdup(value_vector[i]); 
        }else if( 0 == strcmp (key_vector[i],NUM_ROUND_STRING)){
            conf->num_round = atoi(value_vector[i]);
            conf->loop_cipher_round = conf->num_round / U32SIZE; 
        }else if( 0 == strcmp (key_vector[i],ALPHA_STRING)){
            conf->alpha = atoi(value_vector[i]);
        }else if( 0 == strcmp (key_vector[i],BETA_STRING)){
            conf->beta = atoi(value_vector[i]);
        }else if( 0 == strcmp (key_vector[i],CONSTANT_STRING)){
            conf->constant = atoi(value_vector[i]);
        }else if(0 == strcmp(key_vector[i],CONSTANT_SET_STRING)){
            conf->constant_indices = getVettFromStringSet(value_vector[i],conf->constant);
        }else if(0 == strcmp(key_vector[i],ALPHA_SET_STRING)){
            conf->alpha_indices  = getVettFromStringSet(value_vector[i],conf->alpha);
        }else if(0 == strcmp(key_vector[i],BETA_SET_STRING)){
            conf->beta_indices = getVettFromStringSet(value_vector[i],conf->beta);
        }else if(0 == strcmp(key_vector[i],RUN_ID_STRING)){
            conf->run_identifier = strdup(value_vector[i]);
        }else if(0 == strcmp(key_vector[i],CUBE_MIN_SIZE_STRING)){
            conf->cube_min_size = atoi(value_vector[i]);
        }else if(0 == strcmp(key_vector[i],DEBUG_STRING)){
            DEBUG=1;
        }else{
            INFO("WARN : Unrecognized key in config_file : %s\n", key_vector[i] );
        }
    }
    for(i = 0 ; i < ret ; i++){
        free(key_vector[i]);
        free(value_vector[i]);
    }
    free(key_vector);
    free(value_vector);

    if( NULL == conf->beta_indices || NULL == conf->alpha_indices){
        ERROR("invalid config_file\n");
    }

    conf->execution_mode = NORMAL_MODE;
    return conf;
}
#define USAGE "[INFO] Usage: <device_id> <log_file> <conf_file> <output_dir>" 
int main(int argc, char ** argv){

    CranicBanner();
    fprintf(stdout,"\n%s\n",banner);
    if ( argc != ARGC){
        fprintf(stderr,"%s\n",USAGE);
        return EXIT_FAILURE;
    }

    int device = 0;
    device = atoi(argv[1]);
    log_file = Fopen(argv[2],"w+", "[main]: Fopen log_file");
    FILE *cnf_file = Fopen(argv[3],"r", "[main]: Fopen cnf_file");
    output_dir = strdup(argv[4]);
    Mkdir(output_dir, DIRPERM);

    config_ptr conf = parseConfigFile(argv[3]);
    conf->device = device;
    int num_passed_test = 0;
    num_passed_test = runAttack(conf);
    fprintf(stdout,"[INFO]: The attack founds %d cubes that pass all the linearity tests\n", num_passed_test);
    if( num_passed_test > 0){
        computeSuperpoly(conf, num_passed_test);
    }
    freeConfig(conf);
    fclose(log_file);


    return EXIT_SUCCESS;
}

void deviceSetup(int device){
    struct cudaDeviceProp device_properties;
    size_t free_mem, total_mem;

    // Get (and check) CUDA device properties 
    cudaErrorCheck(cudaGetDevice(&device),(const char*)"cudaGetDevice");

    cudaDeviceReset();
    cudaErrorCheck(cudaGetDeviceProperties(&device_properties, device), "cudaGetDeviceProperties");

    if( device_properties.major < MIN_CUDA_CAPABILITY){
        ERROR("[ERROR]: This software requires CUDA device with Compute Capability at least %d.%d\n"\
                "[ERROR]: Found this CUDA device: %s\t Compute Capability: %d.%d\n", \
                MIN_CUDA_CAPABILITY, 0, device_properties.name, device_properties.major, device_properties.minor);
    }


    cudaErrorCheck(cudaMemGetInfo(&free_mem, &total_mem),(char*)"cudaMemGetInfo ");
    INFO("CUDA Device: %s\ttotal memory available: %zu\n", device_properties.name, total_mem );
    INFO("CUDA Device: %s\tfree memory available: %zu\n", device_properties.name, free_mem );

    cudaErrorCheck(cudaSetDevice(device),"cudaSetDevice");
    cudaDeviceSynchronize();
}

int runAttack(config_ptr conf){

    u32 i, j;
    u32 * key_vett;
    u32 *host_cdbms; // Cubes of Dimension Beta MaskS
    u32 * host_icdb; // Indexes Cubes Dimension Beta
    size_t k1_out_dim;
    u32 nblocks, nthreads;
    u32 *host_k2out;
    u32 offset;
    u32 max_iv_per_launch;
    u32 tmp_num_iv;
    u32 launch_loop;
    u32 shared_size;
    u32 *host_k1_output; //only for debug
    u32 k1o_dim; // kernel1 Output Dim
    FILE *fout;
    unsigned long long max_num_linear_tests; /*The max number of linear tests by kernel2 for a given cube size */
    u32 max_mask_per_launch;
    u32 max_num_cubes;          /* The max number of cubes of same dimension tested (i.e. BinCoeff( (alpha-beta), ((alpha-beta)/2)) )*/
    u64 num_mask;
    u32 tmp_num_mask;
    u32 * mask_vett;
    u64 curr_num_mask;
    u32 num_test_passed;
    u32 num_tot_test_passed;
    int seed;
    u32 num_of_cubes;
    TIMER_DEF;


    i = 0, j = 0 ; 
    seed = 0;

    num_of_cubes = 0;
    num_tot_test_passed = 0;
    nthreads = NTHREADS;

    // Get CUDA device properties and check if it is able to run the test
    deviceSetup(conf->device);


    // Check if the attack settings are valid on the selected device
    INFO("Kite Attack(%d,%d) against %s-%d\n",conf->alpha, conf->beta, conf->target_cipher, conf->num_round); 
    fflush(log_file);

    // Generate the random keys for the attack
    key_vett = genAttackKeys(seed, paper_keys);


    num_of_cubes = 1 << conf->alpha;
    host_cdbms = generateAlphaMask(conf->alpha_indices, conf->alpha, num_of_cubes);
    if(NULL == host_cdbms){	
        ERROR("ERROR: unable to calculate host_cdbms");
    }

    host_icdb = generateCubeCorners(conf->beta_indices, conf->beta);
    if(NULL == host_icdb){
        free(host_cdbms);
        free(key_vett);
        ERROR("ERROR: unable to calculate host_icdb");
    }

    fflush(log_file);

    k1_out_dim = (1 << conf->alpha) * NUM_KEY * sizeof(u32);
    max_num_linear_tests = getMaxNumMask(conf->alpha);	// i > (m-2)/3
    max_num_cubes = coeffBin(conf->alpha,conf->alpha/2);

    // Allocate memory arrays on GPU device
    cudaErrorCheck(
            cudaMalloc( (u32**)&device_k1_output,        k1_out_dim), (char*)"cudaMalloc device_k1_output");
    cudaErrorCheck(
            cudaMalloc( (u32**)&device_key_table1,       key_table_size), (char*)"cudaMalloc device_key_table1");
    cudaErrorCheck(
            cudaMalloc( (u32**)&device_key_table2,       key_table_size), (char*)"cudaMalloc device_key_table2");
    cudaErrorCheck(
            cudaMalloc( (u32**)&device_key,              (KEYS * KEY_ELEM * sizeof(u32)) ), (char*)"cudaMalloc device_key");
    cudaErrorCheck(
            cudaMalloc( (u32**)&device_icdb,               (IV_ELEM * sizeof(u32)) ), (char*)"cudaMalloc device_icdb");
    cudaErrorCheck(
            cudaMalloc( (u32**)&device_cdbms,          (num_of_cubes * IV_ELEM * sizeof(u32)) ), (char*)"cudaMalloc device_cdbms");
    cudaErrorCheck(
            cudaMalloc( (u32**)&device_k2_output,         (max_num_linear_tests * sizeof(u32)) ), (char*)"cudaMalloc device_k2_output");
    cudaErrorCheck(
            cudaMalloc( (u32**)&device_imask,            (max_num_cubes * sizeof(u32)) ), (char*)"cudaMalloc device_imask");


    cudaErrorCheck(
            cudaMemcpy(device_key_table1,KEY_TABLE_1, key_table_size, cudaMemcpyHostToDevice), (char*)"cudaMemcpy key_table1");
    cudaErrorCheck(
            cudaMemcpy(device_key_table2,KEY_TABLE_2, key_table_size, cudaMemcpyHostToDevice), (char*)"cudaMemcpy key_table2");


    INFO("\n%s\n", LINE_BREAK_STRING );
    INFO("KEYS :%d ",KEYS );
    //
    int index=0;
    INFO("\n%s\n", LINE_BREAK_STRING );

    for(i = 0 , index = 0; i < KEYS ; i++)
    {
#ifdef TRIVIUM_CIPHER
        INFO("%08X %08X %08X\n",key_vett[index], key_vett[index+1],key_vett[index+2]);
#elif defined GRAIN128_CIPHER
        INFO("%08X %08X %08X %08X\n",key_vett[index], key_vett[index+1],key_vett[index+2],key_vett[index+3] );
#endif
        index+=KEY_ELEM;
    }
    INFO("\n%s\n", LINE_BREAK_STRING );
    fflush(log_file);

#ifdef TRIVIUM_CIPHER
    // Arrange input arrays to provide coalescing memory access
    for( i = 0; i < KEYS; i++){
        setTriviumOrder(&(key_vett[i*KEY_ELEM]));
    }

    for(i = 0; i < num_of_cubes ; i++){	
        setTriviumOrder(&(host_cdbms[i*IV_ELEM]));
    }

    setTriviumOrder(&(host_icdb[0]));
#endif

    //    INFO("\n%s\n", LINE_BREAK_STRING );
    INFO("IV %s : ", CIPHER_NAME);
    INFO("\n%s\n", LINE_BREAK_STRING );

    for(i = 0 , index = 0 ; i < num_of_cubes ; i++) {
        INFO("%08X %08X %08X\n",host_cdbms[index], host_cdbms[index+1],host_cdbms[index+2] );
        index+=IV_ELEM;
    }

    INFO("\n%s\n", LINE_BREAK_STRING );
    INFO("CUBE %s: ", CIPHER_NAME);
    INFO("\n%s\n", LINE_BREAK_STRING );
    INFO("%08X %08X %08X\n",host_icdb[0], host_icdb[1],host_icdb[2] );
    fflush(log_file);

    //It will operate inplace (i.e. key_vett will be modified)
    arrangeKeysForGPU(key_vett, KEYS, KEY_ELEM );

    cudaErrorCheck(cudaMemcpy(device_key,key_vett, KEYS*KEY_ELEM*sizeof(u32), cudaMemcpyHostToDevice),(char*)"cudaMemcpy key");

    cudaErrorCheck(cudaMemcpy(device_icdb,host_icdb, IV_ELEM*sizeof(u32), cudaMemcpyHostToDevice),(char*)"cudaMemcpy icdb");

    cudaErrorCheck(cudaMemcpy(device_cdbms,host_cdbms, num_of_cubes*IV_ELEM*sizeof(u32), cudaMemcpyHostToDevice),(char*)"cudaMemcpy cdbms");


    offset = 0; // Indices Cubes Dimension Beta;
    max_iv_per_launch = MAXNUMBLOCKS * (nthreads/WARPSIZE);
    TIMER_START;
    tmp_num_iv = num_of_cubes;
    launch_loop = (tmp_num_iv / max_iv_per_launch)+1;
    for( j = 0, offset = 0; j < launch_loop; j++, offset+= max_iv_per_launch){

        nblocks = MIN( MAXNUMBLOCKS,  ( (tmp_num_iv / (nthreads / WARPSIZE) ) +1)  );
        shared_size = conf->beta * ( ( nthreads + WARPSIZE -1) / WARPSIZE) * sizeof(u32);
        k1o_dim = num_of_cubes * WARPSIZE;
        kernel1<<<nblocks,nthreads, shared_size>>>(device_k1_output,k1o_dim, device_key, device_cdbms, device_icdb, conf->beta, conf->loop_cipher_round ,offset);
        cudaKernelCheck((char*)"[ERROR][kernel1]:");
        cudaDeviceSynchronize();
        if(tmp_num_iv > max_iv_per_launch){
            tmp_num_iv = tmp_num_iv - max_iv_per_launch;
        }
    }
    TIMER_STOP;
    INFO("time Kernel1: %f\n",TIMER_ELAPSED );

    if(DEBUG){
        host_k1_output = (u32*)Malloc(k1_out_dim,"Malloc host_k1_output");
        cudaErrorCheck(cudaMemcpy(host_k1_output,device_k1_output, k1_out_dim, cudaMemcpyDeviceToHost),(char*)"cudaMemcpy device_k1_output");

        for(j = 0 ; j < num_of_cubes; j++){
            for(i = 0; i < KEYS; i++){
                INFO("%08X\n",host_k1_output[(j*KEYS)+i] );
            }
        }
        free(host_k1_output);
    }
    fprintf(log_file, "\n%s\n", LINE_BREAK_STRING );

    cudaErrorCheck(cudaFree(device_key),(char*)"cudaFree device_key");

    cudaErrorCheck(cudaFree(device_cdbms),(char*)"cudaFree device_cdbms");
    cudaErrorCheck(cudaFree(device_icdb),(char*)"cudaFree device_icdb");


    INFO("max_num_linear_tests : %llu\n",max_num_linear_tests );

    host_k2out = (u32*)Calloc(sizeof(u32),max_num_linear_tests, "Calloc host_k2out");

    max_mask_per_launch = MAXNUMBLOCKS * (nthreads/WARPSIZE);

    fout=createFile(output_dir, conf->run_identifier, "wb");

    for( i = conf->cube_min_size; i <= conf->alpha; i++)
    {
        num_mask = coeffBin(conf->alpha,i);
        tmp_num_mask = num_mask;
        mask_vett = generateIvMask(i,conf->alpha,num_mask);
        if(NULL == mask_vett){
            fprintf(stderr, "[ERROR]: unable to allocate memory for mask_vett\n");
            return EXIT_FAILURE;
        }

        if(DEBUG){
            for (j=0; j < num_mask;j++){
                fprintf(stderr,"[DEBUG]: %08X\n",mask_vett[j]); 
            }
        }
        cudaErrorCheck(cudaMemcpy(device_imask,mask_vett, num_mask*sizeof(u32), cudaMemcpyHostToDevice),(char*)"cudaMemcpy device_imask");

        launch_loop = (tmp_num_mask / max_mask_per_launch)+1;

        TIMER_START;

        for(j = 0, offset = 0; j < launch_loop; j++, offset+=max_mask_per_launch){
            nblocks = MIN( MAXNUMBLOCKS,  ( ( ( tmp_num_mask) / (nthreads / WARPSIZE) ) +1)  );

            kernel2 <<< nblocks,nthreads>>>(device_k1_output,num_of_cubes,device_imask, num_mask, i, device_key_table1, device_key_table2, device_k2_output,offset,conf->alpha);

            cudaKernelCheck((char*)"[ERROR][kernel2]:");
            cudaDeviceSynchronize();
            if(tmp_num_mask > max_mask_per_launch){
                tmp_num_mask = tmp_num_mask - max_mask_per_launch;
            }


            TIMER_STOP;
            INFO("time Kernel_2: %f\n",TIMER_ELAPSED );

            curr_num_mask = (1 << (conf->alpha - i) ) * coeffBin(conf->alpha, i); // 2^(M-i) * coeffBin(M,i)
            INFO("curr_num_mask : %llu\n",curr_num_mask );

            cudaErrorCheck(cudaMemcpy(host_k2out,device_k2_output, curr_num_mask*sizeof(u32), cudaMemcpyDeviceToHost),(char*)"cudaMemcpy device_k2_output");


            INFO("\n%s\n", LINE_BREAK_STRING );
            INFO("Linearity tests on cubes of dimension: %d", conf->beta+i );

            INFO("\n%s\n", LINE_BREAK_STRING );

            num_test_passed = dumpBinaryOutput(host_k2out,curr_num_mask, i, conf->alpha,conf->beta, mask_vett,host_cdbms,host_icdb,fout, conf->num_round);
            num_tot_test_passed += num_test_passed;

            INFO("Num_test_passed per dimension %u(%u+%u) : %u \n",conf->beta + i, conf->beta,i,num_test_passed );

            free(mask_vett);
        }
    }
    fwrite(&num_tot_test_passed,sizeof(u32),1,fout);
    fclose(fout);
    free(host_icdb);


    cudaErrorCheck( cudaFree(device_key_table1),     (char*)"cudaFree device_key_table1");
    cudaErrorCheck( cudaFree(device_key_table2),     (char*)"cudaFree device_key_table2");
    cudaErrorCheck( cudaFree(device_k1_output),      (char*)"cudaFree device_k1_output");
    cudaErrorCheck( cudaFree(device_k2_output),      (char*)"cudaFree device_k2_output");
    cudaErrorCheck( cudaFree(device_imask),          (char*)"cudaFree device_imask");

    free(key_vett);
    free(host_cdbms);
    free(host_k2out);
    return num_tot_test_passed;

}


int computeSuperpoly(config_ptr conf, int passed_test){
    u32 j;
    u32 i;
    u32 index;
    u32 nblocks, nthreads;
    u32 num_of_cubes;
    u32 cur_num_cubes;
    u32 tmp_num_mask;
    u32 offset;
    u32 max_iv_per_launch;
    u32 max_mask_per_launch;
    u32 tmp_num_iv;
    u32 launch_loop;
    u32 workload;
    u32 shared_size;
    u32 k1o_dim;
    u32 *host_cdbms;
    u32 *host_icdb;
    u32 *host_k1_output;
    u32 *host_k2_output;
    u32 *tmp_k;
    u32 *key_vett;
    u32 *host_bit_table;
    int seed;
    int cube_sizes;
    size_t size_k2_output;
    size_t size_iv_vett;
    size_t size_key_vett;
    size_t size_k1_output;
    cubesPtr cubes;
    char *path;
    FILE *fout;

    if( passed_test <= 0 || NULL == conf){
        ERROR("Invalid argument");
    }

    j = i = index = cur_num_cubes = tmp_num_mask = offset = max_iv_per_launch = launch_loop = workload = shared_size = k1o_dim = 0; 

    host_cdbms = host_icdb = host_k2_output = tmp_k = key_vett = host_bit_table = NULL;
    seed = cube_sizes = 0;
    cubes = NULL;
    fout = NULL;

    nthreads = NTHREADS;
    num_of_cubes = 1 << conf->alpha;

    size_key_vett = KEYS_SUPERPOLY * KEY_ELEM * sizeof(u32);
    size_k1_output = KEYS_SUPERPOLY * num_of_cubes * sizeof(u32);

    cudaErrorCheck(cudaMalloc( (u32**)&device_key,size_key_vett),(char*)"cudaMalloc device_key");
    cudaErrorCheck(cudaMalloc( (u32**)&device_icdb, (IV_ELEM * sizeof(u32))) ,(char*)"cudaMalloc device_icdb");
    cudaErrorCheck(cudaMalloc( (u32**)&device_cdbms, (num_of_cubes * IV_ELEM * sizeof(u32)) ),(char*)"cudaMalloc device_cdbms");
    cudaErrorCheck(cudaMalloc( (u32**)&device_bit_table, KEY_SIZE*sizeof(u32)),(char*)"cudaMalloc device_bit_table");
    cudaErrorCheck(cudaMalloc( (u32**)&device_k1_output, size_k1_output),(char*)"cudaMalloc device_k1_output");

    key_vett = (u32*)Malloc(size_key_vett,"Malloc key_vett");
    memset(key_vett,0,size_key_vett);


    // The key_vett contains:
    // - the key 0..0
    // - 1 <= i <= KEY_SIZE, k[i] is the key where only the  i-th bit is set to 1
    // - the remaining keys are random and used only for further checks
    for( i = 0 , index = KEY_ELEM; i < KEY_SIZE ; i++, index+= KEY_ELEM){
#ifdef TRIVIUM_CIPHER
        setBitTrivium(&(key_vett[index]),i,1);
#elif defined GRAIN128_CIPHER
        setBitGrain128(&(key_vett[index]),i,1);
#endif

    }
    seed = 0;
    tmp_k = genRandKeys( (KEYS_SUPERPOLY - KEYS_COEFFICIENT) ,seed);
    memcpy(&(key_vett[index]), tmp_k, (sizeof(u32) * KEY_ELEM * (KEYS_SUPERPOLY - KEYS_COEFFICIENT) ));
    free(tmp_k);


    host_cdbms = generateAlphaMask(conf->alpha_indices, conf->alpha, num_of_cubes);
    if(NULL == host_cdbms){	
        ERROR("ERROR: unable to calculate host_cdbms");
    }

    host_icdb = generateCubeCorners(conf->beta_indices, conf->beta);
    if(NULL == host_icdb){
        free(host_cdbms);
        free(key_vett);
        ERROR("ERROR: unable to calculate host_icdb");
    }

#ifdef TRIVIUM_CIPHER
    // Arrange input arrays to provide coalescing memory access
    for( i = 0; i < KEYS_SUPERPOLY; i++){
        setTriviumOrder(&(key_vett[i*KEY_ELEM]));
    }

    for(i = 0; i < num_of_cubes ; i++){	
        setTriviumOrder(&(host_cdbms[i*IV_ELEM]));
    }

    setTriviumOrder(&(host_icdb[0]));
#endif

    //It will operate inplace (i.e. key_vett will be modified)
    arrangeKeysForGPU(key_vett, KEYS_SUPERPOLY, KEY_ELEM );

    cudaErrorCheck(cudaMemcpy(device_key,key_vett, KEYS_SUPERPOLY*KEY_ELEM*sizeof(u32), cudaMemcpyHostToDevice),(char*)"cudaMemcpy key");

    cudaErrorCheck(cudaMemcpy(device_icdb,host_icdb, IV_ELEM*sizeof(u32), cudaMemcpyHostToDevice),(char*)"cudaMemcpy icdb");

    cudaErrorCheck(cudaMemcpy(device_cdbms,host_cdbms, num_of_cubes*IV_ELEM*sizeof(u32), cudaMemcpyHostToDevice),(char*)"cudaMemcpy cdbms");

    free(host_cdbms);
    free(host_icdb);
    free(key_vett);


    offset = 0; // Indices Cubes Dimension Beta;
    max_iv_per_launch = MAXNUMBLOCKS * (nthreads/WARPSIZE);
    TIMER_DEF;
    TIMER_START;
    tmp_num_iv = num_of_cubes;
    launch_loop = (tmp_num_iv / max_iv_per_launch)+1;
    for( j = 0, offset = 0; j < launch_loop; j++, offset+= max_iv_per_launch)
    {
        workload = ( tmp_num_iv + ( (nthreads / WARPSIZE) -1 )) / (nthreads / WARPSIZE);
        nblocks = MIN( MAXNUMBLOCKS,  workload );

        shared_size = conf->beta * ( ( nthreads + WARPSIZE - 1)  / WARPSIZE) * sizeof(u32);
        k1o_dim = num_of_cubes * WARPSIZE;
        kernel1_superpoly<<<nblocks,nthreads, shared_size>>>(device_k1_output, k1o_dim, device_key, device_cdbms, device_icdb,conf->beta, conf->loop_cipher_round ,offset);
        cudaKernelCheck((char*)"kernel1_superpoly");
        if(tmp_num_iv > max_iv_per_launch)
            tmp_num_iv = tmp_num_iv - max_iv_per_launch;
    }
    TIMER_STOP;
    INFO("time kernel1_superpoly: %f\n",TIMER_ELAPSED );


    host_k1_output = (u32*)Malloc(size_k1_output,"Malloc host_k1_output");
    cudaErrorCheck(cudaMemcpy(host_k1_output,device_k1_output, size_k1_output, cudaMemcpyDeviceToHost),(char*)"cudaMemcpy device_k1_output");

    if(DEBUG){
        for(j = 0 ; j < num_of_cubes; j++){
            for(i = 0; i < KEYS_SUPERPOLY; i++){
                INFO("%08X\n",host_k1_output[(j*KEYS)+i] );
            }
        }
    }

    free(host_k1_output);
    fprintf(log_file, "\n%s\n", LINE_BREAK_STRING );

    cudaDeviceSynchronize();
    cudaErrorCheck(cudaFree(device_key),(char*)"cudaFree device_key");
    cudaErrorCheck(cudaFree(device_cdbms),(char*)"cudaFree device_cdbms");

    host_bit_table = (u32*)Calloc(KEY_SIZE,sizeof(u32),"Calloc host_bit_table");
    for (j = 0; j < conf->alpha; j++){
        host_bit_table[conf->alpha_indices[j]] = ( 1 << j);
    }
    cudaErrorCheck(cudaMalloc( (u32**)&device_bit_table, KEY_SIZE*sizeof(u32)),(char*)"cudaMalloc device_bit_table");
    cudaErrorCheck(cudaMemcpy(device_bit_table, host_bit_table, KEY_SIZE*sizeof(u32), cudaMemcpyHostToDevice),(char*)"cudaMemcpy device_bit_table");
    free(host_bit_table);

    cube_sizes = conf->alpha - conf->cube_min_size;
    path =(char*) Malloc(sizeof(char) * MAX_PATHNAME, "Malloc path");
    snprintf(path,MAX_PATHNAME,"%s/%s",output_dir, conf->run_identifier);
    cubes = readBinaryOutput(path, passed_test,cube_sizes, conf->num_round ); 
    free(path);
    if( NULL == cubes){
        ERROR("Application error");
    }



    fout=createFile(output_dir, ( char *)OUTPUT_RESULT_FILE, "w+");
    printResultsHeader(fout);
    printResultsHeader(NULL);
    // FOR LOOP 
    max_mask_per_launch = MAXNUMBLOCKS * (nthreads/WARPSIZE);
    for(i = 0; i < cube_sizes; i++){
        cur_num_cubes = cubes->num_cubes[i+1] - cubes->num_cubes[i];
        if(cur_num_cubes == 0) {
            continue;
        }
        size_k2_output = cur_num_cubes * KEYS_SUPERPOLY * sizeof(u32);
        size_iv_vett = cur_num_cubes * IV_ELEM * sizeof(u32);

        cudaErrorCheck(cudaMalloc( (u32**)&device_k2_output, size_k2_output),(char*)"cudaMalloc device_k2_output");
        cudaErrorCheck(cudaMalloc( (u32**)&device_ccm, size_iv_vett),(char*)"cudaMalloc device_ccm");
        cudaErrorCheck(cudaMalloc( (u32**)&device_cem, size_iv_vett),(char*)"cudaMalloc device_cem");

        cudaErrorCheck(cudaMemcpy(device_ccm, &(cubes->ccm_vett[cubes->num_cubes[i]]), size_iv_vett, cudaMemcpyHostToDevice),(char*)"cudaMemcpy device_ccm");
        cudaErrorCheck(cudaMemcpy(device_cem, &(cubes->cem_vett[cubes->num_cubes[i]]), size_iv_vett, cudaMemcpyHostToDevice),(char*)"cudaMemcpy device_cem");

        tmp_num_mask = cur_num_cubes;
        launch_loop = (tmp_num_mask / max_mask_per_launch)+1;

        TIMER_START;

        for(j = 0, offset = 0; j < launch_loop; j++, offset+=max_mask_per_launch)
        {
            workload = (tmp_num_mask + (nthreads/WARPSIZE) - 1) / ( nthreads / WARPSIZE);
            nblocks = MIN( MAXNUMBLOCKS,  workload  );

            shared_size = (cubes->dim_cubes[i] - conf->beta) * ( ( nthreads + WARPSIZE -1) / WARPSIZE) * sizeof(u32);	

            if(0 == shared_size){
                shared_size = sizeof(u32) * 4;
            }

            kernel2_superpoly<<<nblocks,nthreads,shared_size >>>(device_k1_output, (cur_num_cubes * WARPSIZE), device_ccm, device_icdb, device_cem, conf->beta, cubes->dim_cubes[i], device_bit_table, KEY_SIZE, offset, device_k2_output);

            cudaKernelCheck((char*)"kernel2_superpoly");

            if(tmp_num_mask > max_mask_per_launch){
                tmp_num_mask = tmp_num_mask - max_mask_per_launch;
            }
        }

        TIMER_STOP;
        INFO("time kernel2_superpoly: %f\n",TIMER_ELAPSED );
        host_k2_output = (u32*)Malloc(size_k2_output, "Malloc host_k2_output"); 
        cudaErrorCheck(cudaMemcpy(host_k2_output ,device_k2_output, size_k2_output, cudaMemcpyDeviceToHost),(char*)"cudaMemcpy device_k2_output");
        printResults(cubes, fout, host_k2_output, i, conf->num_round);
        printResults(cubes, NULL, host_k2_output, i, conf->num_round);
        cudaErrorCheck( cudaFree(device_k2_output), (char*)"cudaFree device_k2_output");
        cudaErrorCheck( cudaFree(device_ccm),       (char*)"cudaFree device_ccm");
        cudaErrorCheck( cudaFree(device_cem),      (char*)"cudaFree device_cem");
        free(host_k2_output);
    }
    fclose(fout);


    freeCubes(cubes);
    cudaErrorCheck( cudaFree(device_k1_output),      (char*)"cudaFree device_k1_output");
    cudaErrorCheck(cudaFree(device_icdb),(char*)"cudaFree device_icdb");
    cudaErrorCheck( cudaFree(device_bit_table),      (char*)"cudaFree device_bit_table");

    return 0;

}

void printResultsHeader(FILE *fout){
    if(NULL == fout){
        fout = stdout;
    }

    fprintf(fout,"Cube-Indexes\tConstant-Indexes\tSuperpoly\tOutput-bit\n");
}
int printResults(cubesPtr cubes, FILE * fout, u32 *host_k2_output, int cube_size_idx, int init_round_cipher){

    u32 i;
    u32 j;
    u32 k;
    u32 out;
    u32 index_out;
    u32 cob;
    u32 index_cube;

    if( NULL == cubes || NULL == host_k2_output || cube_size_idx <0){
        ERROR("Invalid parameters");
    }
    if( NULL == fout){
        fout=stdout;
    }

    for( i =0, j = cubes->num_cubes[cube_size_idx]; j < cubes->num_cubes[cube_size_idx+1] ; i++,j++) {
        cob = cubes->output_round[j];
        index_out = 0;
        index_cube = j * IV_ELEM;

        printCubeIndexesHR( &(cubes->ccm_vett[index_cube]), fout);
        fprintf(fout,"\t");
        printCubeIndexesHR( &(cubes->cem_vett[index_cube]), fout);
        fprintf(fout,"\t");

        for(k = 0 ; k < KEYS_COEFFICIENT; k++) {
            index_out = (i * KEYS_SUPERPOLY ) + k;
#ifdef TRIVIUM_CIPHER
            out = ( (host_k2_output[index_out] >> cob) & 0x1) ;
#elif defined GRAIN128_CIPHER
            out = ( (host_k2_output[index_out] >> (31- cob) ) & 0x1) ;
#endif
            if(out != 0) {
                if(0 == k) {
                    fprintf(fout, "%u +", 1 );
                } else if ( (KEYS_COEFFICIENT -1 ) == k) {
                    fprintf(fout, "x_%u ", k-1 );
                } else {
                    fprintf(fout, "x_%u +", k-1 );
                }
            }
        }
        fprintf(fout,"\t");

        fprintf(fout,"%u\n",cob + init_round_cipher);

    }	
    fflush(fout);
    return EXIT_SUCCESS;
}

void printCubeIndexesHR(u32 * cube, FILE *fout){
    if( NULL == cube){
        return; 
    }

    if( NULL == fout){
        fout = stdout;
    }
    int i, j, k ;

    for(i = 0; i < IV_ELEM; i++){
        for(j = (U32SIZE -1); j >= 0; j--){
            if( (cube[i] >> j) & 0x1) {
                k = (i * U32SIZE) + (U32SIZE - j ) - 1;
                if( k < IV_SIZE){
                    fprintf(fout,"%d,", k);                    
                }
            }
        }
    }
}
