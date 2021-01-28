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

#ifndef __HEADER_CUBE_DEF_
#define __HEADER_CUBE_DEF_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#define u8 unsigned char
#define u32 unsigned int
#define u64 unsigned long long

#define U8SIZE 8
#define U32SIZE 32
#define U64SIZE 64

#define WARPSIZE 32

#define MAX_BUFFER 4096
#define MAX_PATHNAME 2048
#define EMPTY_STRING ""
#define TRIVIUM_STRING "Trivium"
#define TRIVIUM Trivium
#define GRAIN128_STRING "Grain128"
#define GRAIN128 Grain128
#define MICKEY2_STRING "Mickey2"
#define MICKEY2 Mickey2


#ifdef TRIVIUM_CIPHER
    #define IV_ELEM 3
    #define KEY_ELEM 3
    #define TRIVIUM_KEY_SIZE 80
    #define TRIVIUM_IV_SIZE 80
    #define KEYS_COEFFICIENT 81
    #define RESIDUAL_KEYS 17 // Number of keys in the last block of 32 (80keys + 0..0key = 2 * 32 + 17) (KEYS_COEFFICIENT % U32SIZE)
    #define TOTAL_KEYS 96
    #define CIPHER_NAME TRIVIUM_STRING
    #define CIPHER TRIVIUM
    #define KEY_SIZE TRIVIUM_KEY_SIZE
    #define IV_SIZE TRIVIUM_IV_SIZE
#elif defined GRAIN128_CIPHER
    #define IV_ELEM 3
    #define KEY_ELEM 4
    #define GRAIN128_KEY_SIZE 128
    #define GRAIN128_IV_SIZE 96
    #define KEYS_COEFFICIENT 129 
    #define RESIDUAL_KEYS 1 // Number of keys in the last block of 32 (128 keys + 0..0key = 4 * 32 + 1) (KEYS_COEFFICIENT % U32SIZE)
    #define TOTAL_KEYS 160
    #define CIPHER_NAME GRAIN128_STRING
    #define CIPHER GRAIN128
    #define KEY_SIZE GRAIN128_KEY_SIZE
    #define IV_SIZE GRAIN128_IV_SIZE
#elif defined MICKEY2_CIPHER
    #define IV_ELEM 3
    #define KEY_ELEM 3
    #define MICKEY2_KEY_SIZE 80
    #define MICKEY2_IV_SIZE 80
    #define KEYS_COEFFICIENT 81 
    #define RESIDUAL_KEYS 1 // Number of keys in the last block of 32 (128 keys + 0..0key = 4 * 32 + 1) (KEYS_COEFFICIENT % U32SIZE)
    #define TOTAL_KEYS 96
    #define CIPHER_NAME MICKEY2_STRING
    #define CIPHER MICKEY2
    #define KEY_SIZE MICKEY2_KEY_SIZE
    #define IV_SIZE MICKEY2_IV_SIZE
#else
    //ERROR: you must specify a supported cipher
    #define IV_ELEM 0
    #define KEY_ELEM 0
    #define KEYS_COEFFICIENT 0
    #define RESIDUAL_KEYS 0
    #define TOTAL_KEYS 0
    #define CIPHER_NAME "UNSUPPORTED"
    #define CIPHER unsupported
#endif

#define SET_BITR(cipher,base,beta,v) setBit## cipher(base,beta,v)
#define SET_BIT(cipher,base,beta,v) SET_BITR(cipher,base,beta,v)

#define KEYS 64
#define KEYS_SUPERPOLY TOTAL_KEYS 
#define NUM_RAND_KEY 10



#define MIN(a,b) (a < b) ? a : b
#define MAX(a,b) (a < b) ? b : a

#define TIMER_DEF     struct timeval temp_1, temp_2

#define TIMER_START   gettimeofday(&temp_1, (struct timezone*)0)

#define TIMER_STOP    gettimeofday(&temp_2, (struct timezone*)0)

#define TIMER_ELAPSED ((temp_2.tv_sec-temp_1.tv_sec)*1.e6+(temp_2.tv_usec-temp_1 .tv_usec))
#endif

