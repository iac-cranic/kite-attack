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

#ifndef __HEADER_MICKEY2_AUXILIARY_
#define __HEADER_MICKEY2_AUXILIARY_

#include "def.h"

static const u32 bitTableMapMickey2[] ={
	0x80000000,	0x40000000, 0x20000000, 0x10000000,

	0x08000000,	0x04000000,	0x02000000,	0x01000000,

	0x00800000,	0x00400000,	0x00200000,	0x00100000,

	0x00080000,	0x00040000,	0x00020000,	0x00010000,

	0x00008000,	0x00004000,	0x00002000,	0x00001000,

	0x00000800,	0x00000400,	0x00000200,	0x00000100,

	0x00000080,	0x00000040,	0x00000020,	0x00000010,

	0x00000008,	0x00000004, 0x00000002,	0x00000001
};

u32 * setBitMickey2(u32* base, u8 bit, u8 state);
#endif
