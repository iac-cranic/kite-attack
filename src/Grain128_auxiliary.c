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

#include "Grain128_auxiliary.h"


u32 * setBitGrain128(u32* base, u8 bit, u8 state){
    int index;
    u32 tmp;

	if(NULL == base)
		return base;

	index = bit / (U32SIZE);
	
	tmp = bitTableMapGrain128[bit-(index*U32SIZE)] ;

	base[index] |= tmp;	
	return base;
}
