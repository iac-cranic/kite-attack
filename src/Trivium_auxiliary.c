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

#include "Trivium_auxiliary.h"

u32 * setBitTrivium(u32* base, u8 bit, u8 state){
	if(NULL == base)
		return base;

	int index = (79 - bit) / (U32SIZE);
	
	u32 tmp = bitTableMap[bit] ;

	base[index] |= tmp;	
	return base;
}

void setTriviumOrder(u32 value[]){
    u32 tmp_value[KEY_ELEM];

    tmp_value[0] = tmp_value[1] = tmp_value[2] = 0 ;
    u8* src_ptr = NULL, *dst_ptr = NULL;

    src_ptr = (u8*) &(value[2]);

    dst_ptr =  (u8*) &(tmp_value[0]);

    dst_ptr[3] = src_ptr[2];
    dst_ptr[2] = src_ptr[3];

    src_ptr = (u8*)&(value[1]);

    dst_ptr[1] = src_ptr[0];
    dst_ptr[0] = src_ptr[1];

    dst_ptr = (u8*)&(tmp_value[1]);

    dst_ptr[3] = src_ptr[2];
    dst_ptr[2] = src_ptr[3];

    src_ptr = (u8*)&(value[0]);

    dst_ptr[1] = src_ptr[0];
    dst_ptr[0] = src_ptr[1];

    dst_ptr = (u8*)&(tmp_value[2]);

    dst_ptr[3] = src_ptr[2];
    dst_ptr[2] = src_ptr[3];

    value[0] = tmp_value[0];
    value[1] = tmp_value[1];
    value[2] = tmp_value[2];
}

