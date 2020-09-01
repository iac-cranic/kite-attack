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

#include "def.h"



#define R1MASK 0xFFFFFFF8
#define R2MASK 0xFFFFF000
#define R3MASK 0xFFFE0000
/*
 * Function: k_trivium
 * ------------------------------------
 * A fast CUDA implementation of the Trivium cipher. It will perform 32 rounds for each loop round
 *
 * - key0: contains the keys from k0 to k31 (both included)
 * - key1: contains the keys from k32 to k63 (both included)
 * - key2: contains the keys from k64 to k79 (both included)
 * - iv0: contains the ivs from iv0 to iv31 (both included)
 * - iv1: contains the ivs from iv32 to iv63 (both included)
 * - iv2: contains the ivs from iv64 to iv79 (both included)
 * - num_round: the number of initialization rounds divided by 32
 */
__host__ __device__ __forceinline__ u32 k_trivium(u32 key0, u32 key1, u32 key2, u32 iv0, u32 iv1, u32 iv2, u32 num_round){
	u32 R1a = key0;
	u32 R1b = key1;
	u32 R1c = key2;
	

	u32 R2a = iv0;
	u32 R2b = iv1;
	u32 R2c = iv2;


	u32 R3a = 0;
	u32 R3b = 0;
	u32 R3c = 0;
	u32 R3d = 0xE0000;
 	
	u32 i = 0, t1 = 0, t2 = 0, t3 = 0, tmp0 = 0, tmp1 = 0;
	for(i = 0; i < num_round; i++){ 
	    // INITIALIZATION PHASE	

		tmp0 =  (R1c >> 30) ^ (R1b << 2); // s66
		tmp1 =  (R1c >> 3) ^ (R1b << 29); // s93

		t1 = tmp0 ^ tmp1 ; // s66 + s93

	
		tmp0 = (R1c >> 4) ^ (R1b << 28); // s92
		tmp1 = (R1c >> 5) ^ (R1b << 27); // s91

		t1 ^= (tmp0 & tmp1); // t1 + s91*s92

		tmp0 = (R2c >> 18) ^ ( R2b << 14);

		t1 ^= tmp0; // t1 + s171



		tmp0 = ( R2c >> 27) ^ (R2b << 5); // s162
		tmp1 = ( R2c >> 12) ^ (R2b << 20); // s177

		t2 = tmp0 ^ tmp1 ; // s162 + s177

		tmp0 = ( R2c >> 13) ^ ( R2b << 19); // s175
		tmp1 = ( R2c >> 14) ^ ( R2b << 18); // s176

		t2 ^= (tmp0 & tmp1); // t2 + (s175 * s176)

		tmp0 = ( R3c >> 9) ^ ( R3b << 23); // s264

		t2 ^= tmp0;


		tmp0 = ( R3c >> 30) ^ ( R3b << 2); // s243
		tmp1 = ( R3d >> 17) ^ ( R3c << 15); // s288

		t3 = tmp0 ^ tmp1; // s243+ s288

		tmp0 = ( R3d >> 19) ^ ( R3c << 13); // s286
		tmp1 = ( R3d >> 18) ^ ( R3c << 14); // s287

		t3 ^= (tmp0 & tmp1); // t3 + (s286*287)

		tmp0 = ( R1c >> 27) ^ (R1b << 5); // s69

		t3 ^= tmp0;



		R1c = R1b & R1MASK;
		R1b = R1a;
		R1a = t3;

		R2c = R2b & R2MASK;
		R2b = R2a;
		R2a = t1;

		R3d = R3c & R3MASK;
		R3c = R3b;
		R3b = R3a;
		R3a = t2;


 	}

    // KEYSTREAM GENERATION
 	u32 z = 0;

	tmp0 =  (R1c >> 30) ^ (R1b << 2); // s66
	tmp1 =  (R1c >> 3) ^ (R1b << 29); // s93

	t1 = tmp0 ^ tmp1 ; // s66 + s93

	tmp0 = ( R2c >> 27) ^ (R2b << 5); // s162
	tmp1 = ( R2c >> 12) ^ (R2b << 20); // s177

	t2 = tmp0 ^ tmp1 ; // s162 + s177

	tmp0 = ( R3c >> 30) ^ ( R3b << 2); // s243
	tmp1 = ( R3d >> 17) ^ ( R3c << 15); // s288

	t3 = tmp0 ^ tmp1; // s243+ s288

	z = t1 ^ t2 ^ t3;
	return z;
}
