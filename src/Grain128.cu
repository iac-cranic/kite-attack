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


/*
 * Function: k_grain128
 * ------------------------------------
 * A fast CUDA implementation of the Grain128 cipher. It will perform 32 rounds for each loop round
 *
 * - key0: contains the keys from k0 to k31 (both included)
 * - key1: contains the keys from k32 to k63 (both included)
 * - key2: contains the keys from k64 to k79 (both included)
 * - key2: contains the keys from k64 to k95 (both included)
 * - key3: contains the keys from k96 to k127 (both included)
 * - iv0: contains the ivs from iv0 to iv31 (both included)
 * - iv1: contains the ivs from iv32 to iv63 (both included)
 * - iv2: contains the ivs from iv64 to iv95 (both included)
 * - num_round: the number of initialization rounds divided by 32
 */
__host__ __device__ __forceinline__ u32 k_grain128(u32 key0, u32 key1, u32 key2, u32 key3, u32 iv0, u32 iv1, u32 iv2, u32 num_round){

	u32 NFSR0 = key0; // b_0  -> b_31
	u32 NFSR1 = key1; // b_32 -> b_63
	u32 NFSR2 = key2; // b_64 -> b_95
	u32 NFSR3 = key3; // b_96 -> b_127  
	
	u32 LFSR0 = iv0; //  s_0  -> s_31
	u32 LFSR1 = iv1; //  s_32 -> s_63
	u32 LFSR2 = iv2; //  s_64 -> s_95
	u32 LFSR3 = 0xFFFFFFFF; // s_96 -> s_127

	// h(x) := x0x1 + x2x3 +x4x5 + x6x7 + x0x4x8
	// x0 = b_i+12; x1 = s_i+8; x2 = s_i+13 ; x3 = s_i+20
	// x4 = b_i+95; x5 = s_i+42; x6= s_i+60; x7= s_i+79; x8 = s_i+95
	u32 i = 0, outbit = 0;
	u32 tmp0 = 0, tmp1 = 0, tmp2 = 0;

	// INITIALIZATION PHASE 
	for( i = 0 ; i < num_round ; i++){

		
		// Computing output
		tmp0 = ( NFSR0 << 12 ) ^ ( NFSR1 >> 20 ); // b_i+12
		tmp1 = ( LFSR0 << 8  ) ^ ( LFSR1 >> 24 ); // s_i+8
		outbit = ( tmp0 & tmp1 );

		tmp2 = tmp0;

		tmp0 = ( LFSR0 << 13 ) ^ ( LFSR1 >> 19 ); // s_i+13
		tmp1 = ( LFSR0 << 20 ) ^ ( LFSR1 >> 12 ); // s_i+20
		outbit ^= (tmp0 & tmp1 );
		
		tmp0 = ( NFSR2 << 31 ) ^ ( NFSR3 >> 1 ); // b_i+95
		tmp1 = ( LFSR1 << 10 ) ^ ( LFSR2 >> 22 ); // s_i+42
		outbit ^= ( tmp0 & tmp1 );

		tmp2 &= tmp0; // x0x4

		tmp0 = ( LFSR1 << 28 ) ^ ( LFSR2 >> 4 ); // s_i+60
		tmp1 = ( LFSR2 << 15 ) ^ ( LFSR3 >> 17 ); // s_i+79
		outbit ^= ( tmp0 & tmp1 );

		tmp0 = ( LFSR2 << 31 ) ^ ( LFSR3 >> 1 ); // s_i+95
		outbit ^= (tmp0 & tmp2);

		tmp0 = ( LFSR2 << 29 ) ^ ( LFSR3 >> 3 ); // s_i+93
		tmp1 = ( NFSR0 << 2  ) ^ ( NFSR1 >> 30); // b_2
		tmp2 = ( NFSR0 << 15 ) ^ ( NFSR1 >> 17); // b_15

		outbit ^= tmp0 ^ tmp1 ^ tmp2 ; 

		tmp0 = ( NFSR1 << 4  ) ^ ( NFSR2 >> 28 ); // b_i+36
		tmp1 = ( NFSR1 << 13 ) ^ ( NFSR2 >> 19 ); // b_i+45
		
		outbit ^= tmp0 ^ tmp1 ^ NFSR2; // NFSR=b_i+64

		tmp0 = ( NFSR2 << 9  ) ^ ( NFSR3 >> 23 ); // b_i+73
		tmp1 = ( NFSR2 << 25 ) ^ ( NFSR3 >> 7  ); // b_i+89	

		outbit ^= (tmp0 ^ tmp1);

		// Updating NFSR
		u32 tmp_FSR = LFSR0 ^ NFSR0 ^ NFSR3; // s_i + b_i + b_i+96

		tmp0 = ( NFSR0 << 26 ) ^ ( NFSR1 >> 6 ); // b_i+26
		tmp1 = ( NFSR1 << 24 ) ^ ( NFSR2 >> 8 ); // b_i+56
		tmp2 = ( NFSR2 << 27 ) ^ ( NFSR3 >> 5 ); // b_i+91

		tmp_FSR ^= tmp0 ^ tmp1 ^ tmp2;

		tmp0 = ( NFSR0 << 3 )  ^ ( NFSR1 >> 29 ); // b_i+3
		tmp1 = ( NFSR2 << 3 )  ^ ( NFSR3 >> 29 ); // b_i+67
		tmp_FSR ^= ( tmp0 & tmp1);

		tmp0 = ( NFSR0 << 11 )  ^ ( NFSR1 >> 21 ); // b_i+11
		tmp1 = ( NFSR0 << 13 )  ^ ( NFSR1 >> 19 ); // b_i+13
		tmp_FSR ^= ( tmp0 & tmp1);

		tmp0 = ( NFSR0 << 17 )  ^ ( NFSR1 >> 15 ); // b_i+17
		tmp1 = ( NFSR0 << 18 )  ^ ( NFSR1 >> 14 ); // b_i+18
		tmp_FSR ^= ( tmp0 & tmp1);

		tmp0 = ( NFSR0 << 27 )  ^ ( NFSR1 >> 5 ); // b_i+27
		tmp1 = ( NFSR1 << 27 )  ^ ( NFSR2 >> 5 ); // b_i+59
		tmp_FSR ^= ( tmp0 & tmp1);

		tmp0 = ( NFSR1 << 8 )   ^ ( NFSR2 >> 24 ); // b_i+40
		tmp1 = ( NFSR1 << 16 )  ^ ( NFSR2 >> 16 ); // b_i+48
		tmp_FSR ^= ( tmp0 & tmp1);

		tmp0 = ( NFSR1 << 29 )  ^ ( NFSR2 >> 3 ); // b_i+61
		tmp1 = ( NFSR2 << 1 )   ^ ( NFSR3 >> 31 ); // b_i+65
		tmp_FSR ^= ( tmp0 & tmp1);


		tmp0 = ( NFSR2 << 4  )  ^ ( NFSR3 >> 28 ); // b_i+68
		tmp1 = ( NFSR2 << 20 )  ^ ( NFSR3 >> 12 ); // b_i+84
		tmp_FSR ^= ( tmp0 & tmp1);


		NFSR0 = NFSR1;
		NFSR1 = NFSR2;
		NFSR2 = NFSR3;
		NFSR3 = tmp_FSR ^ outbit;

		// Updating LFSR
		tmp_FSR = LFSR0 ^ LFSR3; // s_i ^ s_i+96
		
		tmp0 = ( LFSR0 << 7  ) ^ ( LFSR1 >> 25 ); // s_i+7
		tmp1 = ( LFSR1 << 6  ) ^ ( LFSR2 >> 26 ); // s_i+38
		tmp_FSR ^= tmp0 ^ tmp1;

		tmp0 = ( LFSR2 << 6  ) ^ ( LFSR3 >> 26 ); // s_i+70
		tmp1 = ( LFSR2 << 17 ) ^ ( LFSR3 >> 15  ); // s_i+81
		tmp_FSR ^= tmp0 ^ tmp1;


		LFSR0 = LFSR1;
		LFSR1 = LFSR2;
		LFSR2 = LFSR3;
		LFSR3 = tmp_FSR ^ outbit;
	}

	// KEYSTREAM GENERATION

	// Computing OUTPUT
	tmp0 = ( NFSR0 << 12 ) ^ ( NFSR1 >> 20 ); // b_i+12
	tmp1 = ( LFSR0 << 8  ) ^ ( LFSR1 >> 24 ); // s_i+8
	outbit = ( tmp0 & tmp1 );

	tmp2 = tmp0;

	tmp0 = ( LFSR0 << 13 ) ^ ( LFSR1 >> 19 ); // s_i+13
	tmp1 = ( LFSR0 << 20 ) ^ ( LFSR1 >> 12 ); // s_i+20
	outbit ^= (tmp0 & tmp1 );
	
	tmp0 = ( NFSR2 << 31 ) ^ ( NFSR3 >> 1 ); // b_i+95
	tmp1 = ( LFSR1 << 10 ) ^ ( LFSR2 >> 22 ); // s_i+42
	outbit ^= ( tmp0 & tmp1 );

	tmp2 &= tmp0; // x0x4

	tmp0 = ( LFSR1 << 28 ) ^ ( LFSR2 >> 4 ); // s_i+60
	tmp1 = ( LFSR2 << 15 ) ^ ( LFSR3 >> 17 ); // s_i+79
	outbit ^= ( tmp0 & tmp1 );

	tmp0 = ( LFSR2 << 31 ) ^ ( LFSR3 >> 1 ); // s_i+95
	outbit ^= (tmp0 & tmp2);

	tmp0 = ( LFSR2 << 29 ) ^ ( LFSR3 >> 3 ); // s_i+93
	tmp1 = ( NFSR0 << 2  ) ^ ( NFSR1 >> 30 ); // b_2
	tmp2 = ( NFSR0 << 15 ) ^ ( NFSR1 >> 17 ); // b_15

	outbit ^= tmp0 ^ tmp1 ^ tmp2 ; 

	tmp0 = ( NFSR1 << 4  ) ^ ( NFSR2 >> 28 ); // b_i+36
	tmp1 = ( NFSR1 << 13 ) ^ ( NFSR2 >> 19 ); // b_i+45
	
	outbit ^= tmp0 ^ tmp1 ^ NFSR2; // NFSR=b_i+64

	tmp0 = ( NFSR2 << 9  ) ^ ( NFSR3 >> 23 ); // b_i+73
	tmp1 = ( NFSR2 << 25 ) ^ ( NFSR3 >> 7  ); // b_i+89	

	outbit ^= (tmp0 ^ tmp1);

	return outbit;
}
