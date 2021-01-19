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

#define R_MASK0 0xde4c9e48
#define R_MASK1 0x06662aad
#define R_MASK2 0xf181e1fb
#define R_MASK3 0xc0000000

#define COMP0_0 0x0c5e9556
#define COMP0_1 0x9015429e
#define COMP0_2 0x57fd7ea0
#define COMP0_3 0x60000000

#define COMP1_0 0x597946bb
#define COMP1_1 0xc6b845c7
#define COMP1_2 0xebbc4389
#define COMP1_3 0x80000000

#define S_MASK0_0 0xf5fe5ff9
#define S_MASK0_1 0x81c952f5
#define S_MASK0_2 0x401a3739
#define S_MASK0_3 0x80000000

#define S_MASK1_0 0xee1d3132
#define S_MASK1_1 0xc60d8892
#define S_MASK1_2 0xd4a3df02
#define S_MASK1_3 0x10000000

#define KEY_LEN 80

#define R3i  ((R3 >> 1) ^ ((R2 & 0x1) << 31))
#define R2i  ((R2 >> 1) ^ ((R1 & 0x1) << 31))
#define R1i  ((R1 >> 1) ^ ((R0 & 0x1) << 31))
#define R0i  ((R0>>1) & 0x7fffffff)

/*
 * Function: k_mickey2
 * ------------------------------------
 * A fast CUDA implementation of the Mickey2.0-128 cipher. 
 * This is a based on the 'faster' implementation provided by the authors 
 * and available on "https://www.ecrypt.eu.org/stream/e2-mickey.html"
 * This version has been adapted to better exploit GPUs
 *
 * - key0: contains the keys from k0 to k31 (both included)
 * - key1: contains the keys from k32 to k63 (both included)
 * - key2: contains the keys from k64 to k79 (both included)
 * - iv0: contains the ivs from iv0 to iv31 (both included)
 * - iv1: contains the ivs from iv32 to iv63 (both included)
 * - iv2: contains the ivs from iv64 to iv79 (both included)
 * - num_round: the number of initialization rounds divided by 32
 */
//__host__ __device__ u32 k_mickey2(u32 key0, u32 key1, u32 key2, u32 iv0, u32 iv1, u32 iv2, u32 round, u32 iv_len){
__host__ __device__ __forceinline__ u32 k_mickey2(u32 key0, u32 key1, u32 key2, u32 iv0, u32 iv1, u32 iv2, u32 round, u32 iv_len){
   
   u32 R0;
   u32 R1;
   u32 R2;
   u32 R3;

   u32 S0;
   u32 S1;
   u32 S2;
   u32 S3;

   u32 inp_bit=(iv0 >> 31)&1;
   u32 contr_r=0;
   u32 contr_s=0;
   u32 feedback=0;

   R0=R1=R2=R3=0;
   S0=S1=S2=S3=0;
   
   u32 i;
   // IV LOAD
   // 0 <= iv_len <= 31
   for(i=0; i < iv_len && i < 32; i++){
        
        // compute input bit
        inp_bit=(iv0 >> (31- (i%32))) & 0x1; //da cambiare
        // compute control bits
        contr_r=((R2>>28)^(S1>>29)) & 0x1;
        contr_s=((S2>>28)^(R1>>30)) & 0x1;
        //clock_R
        feedback=((R3>>28) ^ inp_bit ^(S1>>13)) & 0x1; //r99 ^ input_bit_r ^ s50
        R3 = R3i ^ ( R_MASK3 * feedback) ^ (R3 *contr_r);
        R2 = R2i ^ ( R_MASK2 * feedback) ^ (R2 *contr_r);
        R1 = R1i ^ ( R_MASK1 * feedback) ^ (R1 *contr_r);
        R0 = R0i ^ ( R_MASK0 * feedback) ^ (R0 * contr_r);


        //clock_S
        feedback=((S3>>28) ^ inp_bit) & 0x1;
        contr_r = ( (S0 & 0x1) << 31) ^ ((S1 & 0x1) << 30) ^ ((S2 & 0x1) << 29);
        S0 = (S0 >> 1) ^ ( (S0 ^ COMP0_0) & ( ((S0 << 1) ^ (S1 >>31)) ^ COMP1_0) & 0x7fffffff);
        S1 = ( (S1 >> 1) ^(contr_r & 0x80000000)) ^ ( (S1 ^ COMP0_1) & ( ((S1<< 1) ^ (S2 >> 31)) ^ COMP1_1));
        contr_r = contr_r << 1;
        S2 = ( (S2 >> 1) ^(contr_r & 0x80000000)) ^ ( (S2 ^ COMP0_2) & ( ((S2<< 1) ^ (S3 >> 31)) ^ COMP1_2));
        contr_r = contr_r << 1;
        S3 = ( (S3 >>1) ^ (contr_r & 0x80000000)) ^ ( (S3 ^ COMP0_3) & ( ((S3 << 1) ^ COMP1_3)) & 0xe0000000);

        S0 ^= ( (!contr_s & 0x1) * (S_MASK0_0 * feedback)) ^ (contr_s * (S_MASK1_0 * feedback));
        S1 ^= ( (!contr_s & 0x1) * (S_MASK0_1 * feedback)) ^ (contr_s * (S_MASK1_1 * feedback));
        S2 ^= ( (!contr_s & 0x1) * (S_MASK0_2 * feedback)) ^ (contr_s * (S_MASK1_2 * feedback));
        S3 ^= ( (!contr_s & 0x1) * (S_MASK0_3 * feedback)) ^ (contr_s * (S_MASK1_3 * feedback));
	
	
   }
   // 32 <= iv_len <= 63
   for(; i < iv_len && i < 64; i++){
        
        // compute input bit
        inp_bit=(iv1 >> (31- (i%32))) & 0x1; //da cambiare
        // compute control bits
        contr_r=((R2>>28)^(S1>>29)) & 0x1;
        contr_s=((S2>>28)^(R1>>30)) & 0x1;
	
        
        //clock_R
        feedback=((R3>>28) ^ inp_bit ^(S1>>13)) & 0x1; //r99 ^ input_bit_r ^ s50
        
        R3 = R3i ^ ( R_MASK3 * feedback) ^ (R3 *contr_r);
        R2 = R2i ^ ( R_MASK2 * feedback) ^ (R2 *contr_r);
        R1 = R1i ^ ( R_MASK1 * feedback) ^ (R1 *contr_r);
        R0 = R0i ^ ( R_MASK0 * feedback) ^ (R0 * contr_r);


        //clock_S
        feedback=((S3>>28) ^ inp_bit) & 0x1;
        
        contr_r = ( (S0 & 0x1) << 31) ^ ((S1 & 0x1) << 30) ^ ((S2 & 0x1) << 29);
        S0 = (S0 >> 1) ^ ( (S0 ^ COMP0_0) & ( ((S0 << 1) ^ (S1 >>31)) ^ COMP1_0) & 0x7fffffff);
        S1 = ( (S1 >> 1) ^(contr_r & 0x80000000)) ^ ( (S1 ^ COMP0_1) & ( ((S1<< 1) ^ (S2 >> 31)) ^ COMP1_1));
        contr_r = contr_r << 1;
        S2 = ( (S2 >> 1) ^(contr_r & 0x80000000)) ^ ( (S2 ^ COMP0_2) & ( ((S2<< 1) ^ (S3 >> 31)) ^ COMP1_2));
        contr_r = contr_r << 1;
        S3 = ( (S3 >>1) ^ (contr_r & 0x80000000)) ^ ( (S3 ^ COMP0_3) & ( ((S3 << 1) ^ COMP1_3)) & 0xe0000000);

        S0 ^= ( (!contr_s & 0x1) * (S_MASK0_0 * feedback)) ^ (contr_s * (S_MASK1_0 * feedback));
        S1 ^= ( (!contr_s & 0x1) * (S_MASK0_1 * feedback)) ^ (contr_s * (S_MASK1_1 * feedback));
        S2 ^= ( (!contr_s & 0x1) * (S_MASK0_2 * feedback)) ^ (contr_s * (S_MASK1_2 * feedback));
        S3 ^= ( (!contr_s & 0x1) * (S_MASK0_3 * feedback)) ^ (contr_s * (S_MASK1_3 * feedback));

	
	

   }

   // 64<= iv_len <=79
   for(; i < iv_len; i++){
        
        // compute control bits
        contr_r=((R2>>28)^(S1>>29)) & 0x1;
        contr_s=((S2>>28)^(R1>>30)) & 0x1;

	
        
        // compute input bit
        inp_bit=(iv2 >> (31- (i%32))) & 0x1; //da cambiare
        //clock_R
        feedback=((R3>>28) ^ inp_bit ^(S1>>13)) & 0x1; //r99 ^ input_bit_r ^ s50
        
        R3 = R3i ^ ( R_MASK3 * feedback) ^ (R3 *contr_r);
        R2 = R2i ^ ( R_MASK2 * feedback) ^ (R2 *contr_r);
        R1 = R1i ^ ( R_MASK1 * feedback) ^ (R1 *contr_r);
        R0 = R0i ^ ( R_MASK0 * feedback) ^ (R0 * contr_r);


        //clock_S
        feedback=((S3>>28) ^ inp_bit) & 0x1;
        
        contr_r = ( (S0 & 0x1) << 31) ^ ((S1 & 0x1) << 30) ^ ((S2 & 0x1) << 29);
        S0 = (S0 >> 1) ^ ( (S0 ^ COMP0_0) & ( ((S0 << 1) ^ (S1 >>31)) ^ COMP1_0) & 0x7fffffff);
        S1 = ( (S1 >> 1) ^(contr_r & 0x80000000)) ^ ( (S1 ^ COMP0_1) & ( ((S1<< 1) ^ (S2 >> 31)) ^ COMP1_1));
        contr_r = contr_r << 1;
        S2 = ( (S2 >> 1) ^(contr_r & 0x80000000)) ^ ( (S2 ^ COMP0_2) & ( ((S2<< 1) ^ (S3 >> 31)) ^ COMP1_2));
        contr_r = contr_r << 1;
        S3 = ( (S3 >>1) ^ (contr_r & 0x80000000)) ^ ( (S3 ^ COMP0_3) & ( ((S3 << 1) ^ COMP1_3)) & 0xe0000000);

        S0 ^= ( (!contr_s & 0x1) * (S_MASK0_0 * feedback)) ^ (contr_s * (S_MASK1_0 * feedback));
        S1 ^= ( (!contr_s & 0x1) * (S_MASK0_1 * feedback)) ^ (contr_s * (S_MASK1_1 * feedback));
        S2 ^= ( (!contr_s & 0x1) * (S_MASK0_2 * feedback)) ^ (contr_s * (S_MASK1_2 * feedback));
        S3 ^= ( (!contr_s & 0x1) * (S_MASK0_3 * feedback)) ^ (contr_s * (S_MASK1_3 * feedback));
        
	
	

   }

   
   // Load Key
   // 0 <= key <= 31
   for(i=0; i < 32; i++){
        
        // compute control bits
        contr_r=((R2>>28)^(S1>>29)) & 0x1;
        contr_s=((S2>>28)^(R1>>30)) & 0x1;

	
        
        // compute input bit
        inp_bit=(key0 >> (31- (i%32))) & 0x1; //da cambiare

        //clock_R
        feedback=((R3>>28) ^ inp_bit ^(S1>>13)) & 0x1; //r99 ^ input_bit_r ^ s50
        
        R3 = R3i ^ ( R_MASK3 * feedback) ^ (R3 *contr_r);
        R2 = R2i ^ ( R_MASK2 * feedback) ^ (R2 *contr_r);
        R1 = R1i ^ ( R_MASK1 * feedback) ^ (R1 *contr_r);
        R0 = R0i ^ ( R_MASK0 * feedback) ^ (R0 * contr_r);


        //clock_S
        feedback=((S3>>28) ^ inp_bit) & 0x1;
        
        contr_r = ( (S0 & 0x1) << 31) ^ ((S1 & 0x1) << 30) ^ ((S2 & 0x1) << 29);
        S0 = (S0 >> 1) ^ ( (S0 ^ COMP0_0) & ( ((S0 << 1) ^ (S1 >>31)) ^ COMP1_0) & 0x7fffffff);
        S1 = ( (S1 >> 1) ^(contr_r & 0x80000000)) ^ ( (S1 ^ COMP0_1) & ( ((S1<< 1) ^ (S2 >> 31)) ^ COMP1_1));
        contr_r = contr_r << 1;
        S2 = ( (S2 >> 1) ^(contr_r & 0x80000000)) ^ ( (S2 ^ COMP0_2) & ( ((S2<< 1) ^ (S3 >> 31)) ^ COMP1_2));
        contr_r = contr_r << 1;
        S3 = ( (S3 >>1) ^ (contr_r & 0x80000000)) ^ ( (S3 ^ COMP0_3) & ( ((S3 << 1) ^ COMP1_3)) & 0xe0000000);

        S0 ^= ( (!contr_s & 0x1) * (S_MASK0_0 * feedback)) ^ (contr_s * (S_MASK1_0 * feedback));
        S1 ^= ( (!contr_s & 0x1) * (S_MASK0_1 * feedback)) ^ (contr_s * (S_MASK1_1 * feedback));
        S2 ^= ( (!contr_s & 0x1) * (S_MASK0_2 * feedback)) ^ (contr_s * (S_MASK1_2 * feedback));
        S3 ^= ( (!contr_s & 0x1) * (S_MASK0_3 * feedback)) ^ (contr_s * (S_MASK1_3 * feedback));
	
	
   }

   for(i=32; i < 64; i++){
        
        // compute control bits
        contr_r=((R2>>28)^(S1>>29)) & 0x1;
        contr_s=((S2>>28)^(R1>>30)) & 0x1;

	
        
        // compute input bit
        inp_bit=(key1 >> (31- (i%32))) & 0x1; //da cambiare

        //clock_R
        feedback=((R3>>28) ^ inp_bit ^(S1>>13)) & 0x1; //r99 ^ input_bit_r ^ s50
        
        R3 = R3i ^ ( R_MASK3 * feedback) ^ (R3 *contr_r);
        R2 = R2i ^ ( R_MASK2 * feedback) ^ (R2 *contr_r);
        R1 = R1i ^ ( R_MASK1 * feedback) ^ (R1 *contr_r);
        R0 = R0i ^ ( R_MASK0 * feedback) ^ (R0 * contr_r);


        //clock_S
        feedback=((S3>>28) ^ inp_bit) & 0x1;
        
        contr_r = ( (S0 & 0x1) << 31) ^ ((S1 & 0x1) << 30) ^ ((S2 & 0x1) << 29);
        S0 = (S0 >> 1) ^ ( (S0 ^ COMP0_0) & ( ((S0 << 1) ^ (S1 >>31)) ^ COMP1_0) & 0x7fffffff);
        S1 = ( (S1 >> 1) ^(contr_r & 0x80000000)) ^ ( (S1 ^ COMP0_1) & ( ((S1<< 1) ^ (S2 >> 31)) ^ COMP1_1));
        contr_r = contr_r << 1;
        S2 = ( (S2 >> 1) ^(contr_r & 0x80000000)) ^ ( (S2 ^ COMP0_2) & ( ((S2<< 1) ^ (S3 >> 31)) ^ COMP1_2));
        contr_r = contr_r << 1;
        S3 = ( (S3 >>1) ^ (contr_r & 0x80000000)) ^ ( (S3 ^ COMP0_3) & ( ((S3 << 1) ^ COMP1_3)) & 0xe0000000);

        S0 ^= ( (!contr_s & 0x1) * (S_MASK0_0 * feedback)) ^ (contr_s * (S_MASK1_0 * feedback));
        S1 ^= ( (!contr_s & 0x1) * (S_MASK0_1 * feedback)) ^ (contr_s * (S_MASK1_1 * feedback));
        S2 ^= ( (!contr_s & 0x1) * (S_MASK0_2 * feedback)) ^ (contr_s * (S_MASK1_2 * feedback));
        S3 ^= ( (!contr_s & 0x1) * (S_MASK0_3 * feedback)) ^ (contr_s * (S_MASK1_3 * feedback));
	
	
   }
   
   for(i=64; i < KEY_LEN; i++){
        
        // compute control bits
        contr_r=((R2>>28)^(S1>>29)) & 0x1;
        contr_s=((S2>>28)^(R1>>30)) & 0x1;
	
        

        // compute input bit
        inp_bit=(key2 >> (31- (i%32))) & 0x1; //da cambiare

        //clock_R
        feedback=((R3>>28) ^ inp_bit ^(S1>>13)) & 0x1; //r99 ^ input_bit_r ^ s50
        
        R3 = R3i ^ ( R_MASK3 * feedback) ^ (R3 *contr_r);
        R2 = R2i ^ ( R_MASK2 * feedback) ^ (R2 *contr_r);
        R1 = R1i ^ ( R_MASK1 * feedback) ^ (R1 *contr_r);
        R0 = R0i ^ ( R_MASK0 * feedback) ^ (R0 * contr_r);


        //clock_S
        feedback=((S3>>28) ^ inp_bit) & 0x1;
        
        contr_r = ( (S0 & 0x1) << 31) ^ ((S1 & 0x1) << 30) ^ ((S2 & 0x1) << 29);
        S0 = (S0 >> 1) ^ ( (S0 ^ COMP0_0) & ( ((S0 << 1) ^ (S1 >>31)) ^ COMP1_0) & 0x7fffffff);
        S1 = ( (S1 >> 1) ^(contr_r & 0x80000000)) ^ ( (S1 ^ COMP0_1) & ( ((S1<< 1) ^ (S2 >> 31)) ^ COMP1_1));
        contr_r = contr_r << 1;
        S2 = ( (S2 >> 1) ^(contr_r & 0x80000000)) ^ ( (S2 ^ COMP0_2) & ( ((S2<< 1) ^ (S3 >> 31)) ^ COMP1_2));
        contr_r = contr_r << 1;
        S3 = ( (S3 >>1) ^ (contr_r & 0x80000000)) ^ ( (S3 ^ COMP0_3) & ( ((S3 << 1) ^ COMP1_3)) & 0xe0000000);

        S0 ^= ( (!contr_s & 0x1) * (S_MASK0_0 * feedback)) ^ (contr_s * (S_MASK1_0 * feedback));
        S1 ^= ( (!contr_s & 0x1) * (S_MASK0_1 * feedback)) ^ (contr_s * (S_MASK1_1 * feedback));
        S2 ^= ( (!contr_s & 0x1) * (S_MASK0_2 * feedback)) ^ (contr_s * (S_MASK1_2 * feedback));
        S3 ^= ( (!contr_s & 0x1) * (S_MASK0_3 * feedback)) ^ (contr_s * (S_MASK1_3 * feedback));
	
	
   }
   
   //Preclock
   inp_bit=0;
   for(i=0; i < round; i++){
        
        // compute control bits
        contr_r=((R2>>28)^(S1>>29)) & 0x1;
        contr_s=((S2>>28)^(R1>>30)) & 0x1;

	
        

        //clock_R
        feedback=((R3>>28) ^ inp_bit ^(S1>>13)) & 0x1; //r99 ^ input_bit_r ^ s50
        
        R3 = R3i ^ ( R_MASK3 * feedback) ^ (R3 *contr_r);
        R2 = R2i ^ ( R_MASK2 * feedback) ^ (R2 *contr_r);
        R1 = R1i ^ ( R_MASK1 * feedback) ^ (R1 *contr_r);
        R0 = R0i ^ ( R_MASK0 * feedback) ^ (R0 * contr_r);


        //clock_S
        feedback=((S3>>28) ^ inp_bit) & 0x1;
        
        contr_r = ( (S0 & 0x1) << 31) ^ ((S1 & 0x1) << 30) ^ ((S2 & 0x1) << 29);
        S0 = (S0 >> 1) ^ ( (S0 ^ COMP0_0) & ( ((S0 << 1) ^ (S1 >>31)) ^ COMP1_0) & 0x7fffffff);
        S1 = ( (S1 >> 1) ^(contr_r & 0x80000000)) ^ ( (S1 ^ COMP0_1) & ( ((S1<< 1) ^ (S2 >> 31)) ^ COMP1_1));
        contr_r = contr_r << 1;
        S2 = ( (S2 >> 1) ^(contr_r & 0x80000000)) ^ ( (S2 ^ COMP0_2) & ( ((S2<< 1) ^ (S3 >> 31)) ^ COMP1_2));
        contr_r = contr_r << 1;
        S3 = ( (S3 >>1) ^ (contr_r & 0x80000000)) ^ ( (S3 ^ COMP0_3) & ( ((S3 << 1) ^ COMP1_3)) & 0xe0000000);

        S0 ^= ( (!contr_s & 0x1) * (S_MASK0_0 * feedback)) ^ (contr_s * (S_MASK1_0 * feedback));
        S1 ^= ( (!contr_s & 0x1) * (S_MASK0_1 * feedback)) ^ (contr_s * (S_MASK1_1 * feedback));
        S2 ^= ( (!contr_s & 0x1) * (S_MASK0_2 * feedback)) ^ (contr_s * (S_MASK1_2 * feedback));
        S3 ^= ( (!contr_s & 0x1) * (S_MASK0_3 * feedback)) ^ (contr_s * (S_MASK1_3 * feedback));
	
	
   }
   
   // Keystream gen
   u32 z=0;
   for(i=0; i < 32; i++){
        
        z = (z << 1) ^ (( (R0 ^ S0) >> 31) & 0x1); 
        // compute control bits
        contr_r=((R2>>28)^(S1>>29)) & 0x1;
        contr_s=((S2>>28)^(R1>>30)) & 0x1;

	
        

        //clock_R
        feedback=((R3>>28) ^ inp_bit ) & 0x1; //r99 ^ input_bit_r
        
        R3 = R3i ^ ( R_MASK3 * feedback) ^ (R3 *contr_r);
        R2 = R2i ^ ( R_MASK2 * feedback) ^ (R2 *contr_r);
        R1 = R1i ^ ( R_MASK1 * feedback) ^ (R1 *contr_r);
        R0 = R0i ^ ( R_MASK0 * feedback) ^ (R0 * contr_r);


        //clock_S
        feedback=((S3>>28) ^ inp_bit) & 0x1;
        
        contr_r = ( (S0 & 0x1) << 31) ^ ((S1 & 0x1) << 30) ^ ((S2 & 0x1) << 29);
        S0 = (S0 >> 1) ^ ( (S0 ^ COMP0_0) & ( ((S0 << 1) ^ (S1 >>31)) ^ COMP1_0) & 0x7fffffff);
        S1 = ( (S1 >> 1) ^(contr_r & 0x80000000)) ^ ( (S1 ^ COMP0_1) & ( ((S1<< 1) ^ (S2 >> 31)) ^ COMP1_1));
        contr_r = contr_r << 1;
        S2 = ( (S2 >> 1) ^(contr_r & 0x80000000)) ^ ( (S2 ^ COMP0_2) & ( ((S2<< 1) ^ (S3 >> 31)) ^ COMP1_2));
        contr_r = contr_r << 1;
        S3 = ( (S3 >>1) ^ (contr_r & 0x80000000)) ^ ( (S3 ^ COMP0_3) & ( ((S3 << 1) ^ COMP1_3)) & 0xe0000000);

        S0 ^= ( (!contr_s & 0x1) * (S_MASK0_0 * feedback)) ^ (contr_s * (S_MASK1_0 * feedback));
        S1 ^= ( (!contr_s & 0x1) * (S_MASK0_1 * feedback)) ^ (contr_s * (S_MASK1_1 * feedback));
        S2 ^= ( (!contr_s & 0x1) * (S_MASK0_2 * feedback)) ^ (contr_s * (S_MASK1_2 * feedback));
        S3 ^= ( (!contr_s & 0x1) * (S_MASK0_3 * feedback)) ^ (contr_s * (S_MASK1_3 * feedback));
	
	
   }
   return z;
}
