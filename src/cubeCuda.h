/* <This program implements the Kite-Attack Framework, a GPU-tailored implementation of the Cube Attack.>
 * Copyright (C) <2015-2020> <Massimo Bernaschi> <massimo[DOT]bernaschi[AT]gmail[DOT]com>
 * Copyright (C) <2015-2020> <Marco Cianfriglia> <marco[DOT]cianfriglia[AT]gmail[DOT]com>    
 * Copyright (C) <2015-2020> <Stefano Guarino> <ste[DOT]guarino[AT]gmail[DOT]com>
 * Copyright (C) <2015-2020> <Flavio Lombardi> <flavio[DOT]lombardi[AT]cnr[DOT]it>
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

#ifndef __HEADER_CUBE_CUDA_
#define __HEADER_CUBE_CUDA_


#include <cuda.h>
#include <cuda_runtime.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include "key_table.h"

extern "C"{
    #include "twiddle.h"
}
extern "C"{
    #include "auxiliary_functions.h"
}
extern "C"{
    #include "Trivium_auxiliary.h"
}
extern "C"{
    #include "Grain128_auxiliary.h"
}

extern "C"{
    #include "cranic.h"
}

#define MAX_BUFFER 4096



#define MAXNUMBLOCKS 65536
#define MAXNUMELEMS 1024

#define WARPSIZE 32
#define ALL1 0xffffffff
#define NUM_KEY 64 
#define NUM_RAND_KEY 10
#define START_IDX_LIN_TEST 11



#define NUM_ROUND_STRING "INIT_ROUNDS"
#define ALPHA_STRING "ALPHA"
#define ALPHA_SET_STRING "ALPHA_SET"
#define BETA_STRING "BETA"
#define BETA_SET_STRING "BETA_SET"
#define CONSTANT_STRING "CONSTANT"
#define CONSTANT_SET_STRING "CONSTANT_SET"
#define RESULT_FILENAME_STRING "RESULT_FILENAME"
#define LINEARITY_FILENAME_STRING "LINEARITY_FILENAME"
#define RUN_ID_STRING "RUN_IDENTIFIER"
#define CUBE_MIN_SIZE_STRING "CUBE_MIN_SIZE"
#define DEBUG_STRING "DEBUG"
#define LINE_BREAK_STRING "===================================="
#define TARGET_CIPHER_STRING "TARGET_CIPHER"

#define OUTPUT_RESULT_FILE "out.txt"

const char *banner="\
This software is the Kite-Attack framework.\n\
This software is released under the GPLv3 license.\n\
Refer to docs/LICENSE for more information.\n\
This project has been developed in collaboration with National Research Council of Italy (CNR) and Roma Tre University.\n\
Copyright(C) 2015-2020: Massimo Bernaschi (massimo <DOT> bernaschi <AT> gmail <DOT> com)\n\
Copyright(C) 2015-2020: Marco Cianfriglia (marco <DOT> cianfriglia <AT> gmail <DOT> com)\n\
Copyright(C) 2015-2020: Stefano Guarino (stefano <DOT> guarino <AT> gmail <DOT> com)\n\
Copyright(C) 2015-2020: Flavio Lombardi (flavio <DOT> lombardi <AT> gmail <DOT> com)\n\
Copyright(C) 2015-2020: Marco Pedicini (marco <DOT> pedicini <AT> gmail <DOT> com)\n\
This framework is used and maintained for a research project and likely will have many bugs and issues.\n\n\
For any question, please refer to [Marco Cianfriglia](mailto:marco<DOT>cianfriglia<AT>gmail<DOT>com)\n";


#define U32SIZE 32
#define NUM_TESTS 32

//
#define NORMAL_MODE 0



#define DIRPERM S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH

#ifndef PAPER_KEYS
int paper_keys=0;
#else
int paper_keys=1;
#endif


struct configuration{
    int device;
    int num_round;
    int loop_cipher_round;
    int keystream_offset;
    int alpha;
    u32 *alpha_indices;
    int beta;
    u32 *beta_indices;
    int constant;
    u32 *constant_indices;
    char *run_identifier;
    char *target_cipher;
    int execution_mode; // {NORMAL=0 }   
    int cube_min_size;
};
typedef struct configuration config;
typedef config * config_ptr;

/* Kernel definitions */


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
__global__ void kernel1(u32 * k1o, u32 k1o_dim, u32 * key_vett, u32 * cdbms, u32*icdb, u32 icdb_size, u32 num_round, u32 offset);

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
__global__ void kernel2(u32 * bcubes_table,u32 bcubes_table_len,u32 * cube_mask_vect, u32 cube_mask_vect_len, u32 active_bits_masks, u32* key_table_idx1, u32* key_table_idx2, u32* k2out, u32 offset, u32 alpha);


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
__global__ void kernel1_superpoly(u32 * k1o, u32 k1o_dim, u32 * key_vett, u32 * cdbms, u32*icdb, u32 icdb_size, u32 num_round, u32 offset);

/*
	*  Function: kernel2_superpoly
	* ------------------------------------
	* It combines the cubes computed by kernel1_superpoly to obtain the cubes that pass the linearity tests.
	* For each cube computes the linear coefficients representing the superpoly.
	*

	* - bcubes_table: the table containing the cubes of dimension Beta computed by kernel1 
	* - bcubes_table_len: the size of bcubes_table [DEPRECATED]

	* - ccm : contains the mask representing all the indexes of the cubes founded
	* - cube_fixed_bit_mask : the bit-mask represents the Beta indexes
	* - cem: contains the bit masks representing which bits are set to constant 1 . It is needed to compute the position in the bcubes_table
	* - cube_fixed_bit_mask_size : it represents the size of the variable part of the cubes (i.e. how many bits are setted) 
    * - cube_dim: the dimension of the cubes
	* - bit_table : it contains the bits of the variable part used for the cube. For each bit, it contains 0 if not used, the power of 2 w.r.t. its position in the bcubes_table otherwise.
	* - bit_table_dim: the dimension of the bit_table 
    * - offset: it represents the number of masks already checked
	* - k2sout : the output array 


*/
__global__ void kernel2h_superpoly(u32 * bcubes_table, u32 bcubes_table_len, u32 * ccm, u32*cube_fixed_bit_mask, u32 *cem, u32 cube_fixed_bit_mask_size, u32 cube_dim, u32*bit_table, u32 bit_table_dim, u32 offset, u32* k2sout);


/* Function definitions */

/*
 * Function: cudaKernelCheck
 * -----------------------------------------
 * It verifies if the last kernel returns successfully. In case of any error occurs, it will print msg and will call exit( EXIT_FAILURE)
 *
 * - msg: error message
 *
 */
void cudaKernelCheck(char *msg);

/*
 * Function: cudaErrorCheck
 * -----------------------------------------
 * It verifies if the last cuda-functions returns any error occurs, if yes it will print msg and will call exit( EXIT_FAILURE)
 *
 * - msg: error message
 *
 */
void cudaErrorCheck(cudaError_t error, const char * msg);

/*
 * Function: generateAlphaMask
 * -----------------------------------------
 * It returns the u32 array of num_cube elements of size IV_ELEM. The array contains 2^alpha elements   
 *
 * - indices_array: the array of alpha indices
 * - indices_array_len: the len of indices_array
 * - num_cube: 2^alpha
 *
 */
u32 * generateAlphaMask(u32* indices_array, u32 indices_array_len,  u32 num_cube);

/*
 * Function: freeConfig
 * -----------------------------------------
 * It releases the memory allocated of the conf structure
 *
 * - conf: attack configuration
 *
 */
void freeConfig(config_ptr conf);

/*
 * Function: parseConfigFile
 * -----------------------------------------
 * It returns the structure conf as result of the config-file parsing 
 *
 * - pathname: the config-file pathname
 *
 */
config_ptr parseConfigFile(char * pathname);

/*
 * Function: deviceSetup
 * -----------------------------------------
 * It sets the CUDA device and it verifies the selected device fulfills the minimum requirements to run the attack. If not, it will print an error and exit
 *
 * - device: the device id of the target CUDA device
 *
 */
void deviceSetup(int device);

/*
 * Function: runAttack
 * -----------------------------------------
 * It returns the number of passed tested. If any error occurs, it return EXIT_FAILURE
 *
 * - conf: attack configuration
 *
 */
int runAttack(config_ptr conf);

/*
 * Function: computeSuperpoly
 * -----------------------------------------
 * It computes the superpolys for all the cubes that have passed the linearity tests. The cubes are readed from the binary output file produced by runAttack funcion
 *
 * - conf: attack configuration
 * - passed_test: the number of cubes that have passed the linearity tests
 *
 */
int computeSuperpoly(config_ptr conf, int passed_test);

/*
 * Function: printResultsHeader
 * -----------------------------------------
 * It prints the header of the results file. 
 *
 * - fout: the output file (stdout if NULL)
 *
 */
void printResultsHeader(FILE *fout);

/*
 * Function: printResults
 * -----------------------------------------
 * It parses the output produced by kernel2_superpoly and prints the results {maxterm and superpolys) in human readable form. 
 *
 * - cubes: the cubes that have passed the linearity tests
 * - fout: the output file (stdout if NULL)
 * - host_k2_output: the output produced by kernel2_superpoly copied from DeviceToHost
 * - cube_size_idx: the index of cubes->num_cubes, the host_k2_output contains the results of the cubes from cubes->num_cubes[cube_size_idx - 1] to cubes->num_cubes[cube_size_idx] 
 * - init_round_cipher: the number of initialization rounds of the cipher
 *
 */
int printResults(cubesPtr cubes, FILE * fout, u32 *host_k2_output, int cube_size_idx, int init_round_cipher);

/*
 * Function: printCubeIndexesHR
 * -----------------------------------------
 * Auxiliary function, it prints in human readable form the indexes of the input cube
 *
 * - cube: the input cube
 * - fout: the output file (stdout if NULL)
 *
 */
void printCubeIndexesHR(u32 * cube, FILE *fout);


#endif
