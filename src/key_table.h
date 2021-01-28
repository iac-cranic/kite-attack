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

#ifndef __HEADER_KEY_TABLE__
#define __HEADER_KEY_TABLE__

#define KEY_TABLE_COLUMN 3
#define KEY_TABLE_ROW 32
size_t key_table_size = KEY_TABLE_COLUMN * KEY_TABLE_ROW * sizeof(unsigned int);
unsigned int KEY_TABLE_1 [] = {0, 0, 0, 
								1, 1, 0,
								2, 2, 0,
								3, 3, 0,
								4, 4, 0,
								5, 5, 0,
								6, 6, 0,
								7, 7, 0,
								8, 8, 0,
								9, 9, 0,
								10, 10, 0,
								1, 2, 0,
								1, 3, 0,
								1, 4, 0,
								1, 5, 0, 
								1, 6, 0,
								1, 7, 0,
								1, 8, 0, 
								1, 9, 0,
								1, 10, 0,
								2, 3, 0,
								2, 4, 0,
								2, 5, 0,
								2, 6, 0,
								2, 7, 0,
								2, 8, 0,
								2, 9, 0,
								2, 10, 0,
								3, 4, 0,
								3, 5, 0,
								3, 6, 0,
								3, 7, 0
};

unsigned int KEY_TABLE_2 [] = {3, 8, 0,
								3, 9, 0,
								3, 10, 0,
								4, 5, 0,
								4, 6, 0,
								4, 7, 0,
								4, 8, 0,
								4, 9, 0,
								4, 10, 0,
								5, 6, 0,
								5, 7, 0,
								5, 8, 0,
								5, 9, 0,
								5, 10, 0,
								6, 7, 0,
								6, 8, 0,
								6, 9, 0,
								6, 10, 0,
								7, 8, 0,
								7, 9, 0,
								7, 10, 0,
								8, 9, 0,
								8, 10, 0,
								9, 10, 0,
								1, 2, 3,
								4, 5, 6,
								7, 8, 9,
								10, 1, 2,
								3, 4, 5,
								6, 7, 8,
								9, 10, 1,
								2, 3, 4
};
#endif
