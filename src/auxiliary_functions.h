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

#ifndef __HEADER_AUXILIARY_FUNCTIONS__
#define __HEADER_AUXILIARY_FUNCTIONS__

#include <stdlib.h>
#include <errno.h>
#include "def.h"


#define DEFAULT_CONFIGURATION_NUMBER 10
struct cubes
{
	u32 *ccm_vett; //cube_complete_mask
	u32 *cem_vett; //cube_exhaust_mask
	u32 *num_cubes;
	u32 *dim_cubes;
	u32 *output_round;
	u32 tot_num_cubes;
};
typedef struct cubes * cubesPtr;

/*
 * Function: Calloc
 *
 * Wrapper to calloc, it will print the string msg and exit in case of error.
 * - n_items: same as calloc
 * - size: same as calloc
 * - msg: user define message in case of error
 */
void *Calloc(size_t n_items, size_t size, const char *msg) ;

/*
 * Function: Malloc
 *
 * Wrapper to malloc, it will print the string msg and exit in case of error.
 * - size: same as malloc
 * - msg: user define message in case of error
 */
void *Malloc(size_t size, const char *msg);

/*
 * Function: Realloc
 *
 * Wrapper to realloc, it will print the string msg and exit in case of error.
 * - ptr: same as realloc
 * - size: same as realloc
 * - msg: user define message in case of error
 */
void *Realloc(void *ptr, size_t size, const char *msg);

/*
 * Function: Free
 *
 * Wrapper to free, it will check if ptr is NULL before execute free on it.
 * - ptr: same as free
 */
void Free( void *ptr );

/*
 * Function: Fopen 
 *
 * Wrapper to fopen, it will print the string msg and exit in case of error.
 * - path: same as fopen
 * - mode: same as fopen
 * - msg: user define message in case of error
 */
FILE *Fopen(const char *path, const char *mode, const char* msg);

/*
 * Function: Strdup 
 *
 * Wrapper to strdup, it will print the string msg and exit in case of error.
 * - s: same as fopen
 * - msg: user define message in case of error
 */
char * Strdup(const char * s, const char *msg);

/*
 * Function: Mkdir 
 *
 * Wrapper to mkdir, it will exit in case of error.
 * - pathname: same as mkdir
 * - mode: same as mkdir
 */
void Mkdir(char *pathname, mode_t mode);

/*
 * Function: createFile 
 *
 * Utility to create a new file in a target directory.
 * - pathname: target directory (it must exist)
 * - filename: the filename
 * - mode: same as fopen  
 */
FILE* createFile(char *pathname, char *filename, const char *mode);

/*
 * Function: checkStart 
 *
 * It will remove all the whitespaces before the start of s
 * - s: the input string
 */
char* checkStart(char *s);


/*
 * Function: getCommentIdx
 *
 * It will remove all the whitespaces before the start of s
 * It returns the index of the first # if any. Otherwise it returns -1;
 * This function assert that the string s is not NULL.
 * - s: the input string
 */
int getCommentIdx(char * s);

/*
 * Function: configurationFileParser
 *
 * It parses the configuration file and fills the key_vector and value_vector. 
 * It returns the len of the vectors or -1 on error
 *
 * - pathname: the pathname of the configuration file
 * - key_vector: will contain the keys of the config file
 * - value_vector: will contain the values of the keys
 */
int configurationFileParser(const char * pathname, char *** key_vector, char *** value_vector);

/*
 * Function: getVettFromStringSet
 *
 * It parses a StringSet
 *
 * - value_string: the StringSet string
 * - dim_vett: the expected number of elements of the set
 */
u32* getVettFromStringSet(char * value_string , int dim_vett);



/*
 * Function: genPaperKeys
 *
 * It returns the keys used in the paper (they were randomly generated)
 * if the TARGET_CIPHER is TRIVIUM or GRAIN128. Otherwise, it will returns
 * a new set of randomly generated keys
 *
 *   It is useful for reproduce paper results
 */
u32* genPaperKeys();


/*
 * Function: genRandKeys
 *
 * It generates num_keys random keys
 *
 * - num_keys: represents the number of random_keys
 * - seed: represents the seed to initialize the pseudo-random generator routine
 *   It is useful for reproducibility
 */
u32* genRandKeys(int num_keys, int seed);



/*
 * Function: genAttackKeys
 * 
 * It will first generated a set of random keys (by using genRandKeys) and then,
 * it computes 54 combinations of these keys 
 * that are used for the linearity tests
 *
 * - seed: the seed to generate the set of randomly generated keys
 * - paper_keys: if 1 it will return the random keys used in the paper
 */
u32* genAttackKeys(int seed, int paper_keys);

/*
 * Function: sumKeys
 *
 * It generates the key k1^k2 given k1 and k2
 *
 * - out: the key (k1^k2) will be stored here
 * - first: k1
 * - second: k2
 */
void sumKeys(u32 * out, u32 * first, u32 * second);

/*
 * Function: arrangeKeysForGPU
 *
 * It setups the memory layout of the keys suitable for fully exploiting GPUs.
 * keys will be modified
 *
 * - keys: the array contains the keys
 * - num_of_keys: the number of keys
 * - key_size: the length of a key
 */
void arrangeKeysForGPU(u32* keys, u32 num_of_keys, u32 key_size);

/*
 * Function: getMaxNumMask
 *
 * It computes the maximum number of mask given alpha
 *
 * - alpha: the size of ALPHA-SET
 */
unsigned long long getMaxNumMask(u32 alpha);

/*
 * Function: setBitunsupported
 *
 * It is the call back function in the case a non valid cipher is provided
 *
 */
u32 * setBitunsupported(u32* base, u8 bit, u8 state);
/*
 * Function: generateCubeCorners
 *
 * It setups the cubeCorners
 *
 * - beta_indices: the indices belong to BETA_SET
 * - beta: BETA
 *
 */
u32* generateCubeCorners(u32 * beta_indices, u32 beta);

/*
 * Function: coeffBin
 *
 * It computes the binomial coefficient given n and k
 *
 * - n: 
 * - k:
 *
 */
unsigned long long coeffBin(int n, int k);

/*
 * Function: getLinearMaskReverseExaustiveB
 *
 * It extracts the candidates maxterms and their information and prints them in human readable format 
 *
 * - host_k2out: the kernel2 output array containing the results of the linearity tests
 * - num_mask: the number of mask
 * - dim_cube_imask: the dimension of the cubes 
 * - alpha: the size of alpha
 * - beta: the size of beta
 * - mask_vett: the array of cube masks
 * - host_cdbms: the 2^alpha cubes  
 * - host_icdb: the beta indexes
 * - fout: the output file
 * - cube_matrix_statistics_row: the pointer to the array of 32 used for statistics
 * - cipher_round: the number of initialization rounds of the cipher
 *
 */
u32 getLinearMaskReverseExaustiveB(u32 * host_k2out,u32 num_mask, u32 dim_cube_imask, u32 alpha, u32 *mask_vett, u32* host_cdbms, u32* host_icdb, FILE* fout, u32 * cube_matrix_statistics_row, int cipher_round);

/*
 * Function: readBinaryOutput
 *
 * It parses the binary file produced by dumpBinaryOutput and it fills and returns the struct cubes
 *
 * - pathname: the binary file pathname 
 * - num_cubes: the number of cubes contained in the binary file
 * - cubes_sizes: the number of different cube sizes 
 * - init_cipher_round: the number of initialization rounds of the cipher
 *
 */
cubesPtr readBinaryOutput(char * pathname, int num_cubes, int cube_sizes, int init_cipher_round);

/*
 * Function: dumpBinaryOutput
 *
 * It extracts the candidates maxterms and their information and it prints them in binary format
 *
 * - host_k2out: the kernel2 output array containing the results of the linearity tests
 * - num_mask: the number of mask
 * - dim_cube_imask: the dimension of the cubes 
 * - alpha: the size of alpha
 * - beta: the size of beta
 * - mask_vett: the array of cube masks
 * - host_cdbms: the 2^alpha cubes  
 * - host_icdb: the beta indexes
 * - fout: the output file
 * - cipher_round: the number of initialization rounds of the cipher
 *
 */
u32 dumpBinaryOutput(u32 * host_k2out,u32 num_mask, u32 dim_cube_imask, u32 alpha, u32 beta, u32 *mask_vett, u32* host_cdbms, u32* host_icdb, FILE* fout, int cipher_round);

/*
 * Function: getExaustiveMask
 *
 * It computes the idx-th mask given the starting mask
 *
 * - idx: the index of the mask  
 * - starting_mask: the starting mask 
 *
 */
u32 getExaustiveMask(u32 idx, u32 starting_mask);

/*
 * Function: setBit
 *
 * It sets the index bit on base to the specified value
 *
 * - index: the index of the bit to set 
 * - value: the value to set (0,1)
 * - base: the pointer to the first element of the target iv/key 
 *
 */
void setBit(u32 index, u32 value, u32* base);

/*
 * Function: generateIvMask
 *
 * It computes the num_mask masks of size M given N possible choices
 * 
 * - M: the size of the mask to compute 
 * - N: the possible choices
 * - num_mask: the number of mask to compute (binomial coefficient (N,M) )
 */
u32* generateIvMask(u32 M , u32 N, u32 num_mask);

/*
 * Function: freeCubes
 *
 * It releases the memory allocated for c
 * 
 * - c: the pointer to the cubes structure
 */
void freeCubes(cubesPtr c);
#endif
