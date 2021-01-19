# MAKEFILE FOR CUDA_CUBES 

######## C, C++ VARIABLES #########
CC = gcc
CXX = g++
NVCC= nvcc
LIB = -L/usr/local/lib
SRCDIR=src
BIN=bin
CONFIG=config
OUTPUT_DIR=output
CCLFLAGS = $(LIB) 
CCFLAGS =  $(INCLUDE) 
#CCFLAGS += -O3 -fast
MAXTHREADSPERBLOCK=1024
CUDA_FLAGS =-Xptxas="-v"  -DMAXNUMTHREAD=${MAXTHREADSPERBLOCK}
CUDA_FLAGS += --maxrregcount=64 
#CUDA_FLAGS += -O3
CUDA_FLAGS += -g 
CUDA_FLAGS += -G
#CUDA_FLAGS += -arch=sm_35 
MICKEY_IV_LEN=40
#CUDA_FLAGS += -arch=sm_60
CUDA_FLAGS += -gencode arch=compute_35,code=sm_35
CUDA_FLAGS += -gencode arch=compute_37,code=sm_37
CUDA_FLAGS += -gencode arch=compute_50,code=sm_50
CUDA_FLAGS += -gencode arch=compute_52,code=sm_52
CUDA_FLAGS += -gencode arch=compute_53,code=sm_53
CUDA_FLAGS += -gencode arch=compute_60,code=sm_60
CUDA_FLAGS += -gencode arch=compute_61,code=sm_61
CUDA_FLAGS += -gencode arch=compute_62,code=sm_62
CUDA_FLAGS += -gencode arch=compute_70,code=sm_70
CUDA_FLAGS += -gencode arch=compute_72,code=sm_72


####### TARGET ########

HEADERS=$(SRCDIR)/key_table.h $(SRCDIR)/twiddle.h $(SRCDIR)/cranic.h

all:kite_attack_trivium kite_attack_grain128 kite_attack_mickey2
install:
	mkdir -p ${OUTPUT_DIR}
	mkdir -p ${BIN}
	mkdir -p ${CONFIG}
	make all


TWIDDLE=$(SRCDIR)/twiddle.c
AUXILIARY_TRIVIUM=$(SRCDIR)/auxiliary_functions.c $(SRCDIR)/Trivium_auxiliary.c $(SRCDIR)/cranic.c
AUXILIARY_GRAIN128=$(SRCDIR)/auxiliary_functions.c $(SRCDIR)/Grain128_auxiliary.c $(SRCDIR)/cranic.c
AUXILIARY_MICKEY2=$(SRCDIR)/auxiliary_functions.c $(SRCDIR)/Mickey2_auxiliary.c $(SRCDIR)/cranic.c


kite_attack_trivium: ${SRCDIR}/cubeCuda.cu $(TWIDDLE) $(AUXILIARY_TRIVIUM) $(HEADERS)
	$(NVCC)  ${SRCDIR}/cubeCuda.cu -o $(BIN)/kite_attack_trivium $(TWIDDLE) $(AUXILIARY_TRIVIUM) $(CUDA_FLAGS) -DTRIVIUM_CIPHER 

kite_attack_grain128: ${SRCDIR}/cubeCuda.cu $(TWIDDLE) $(AUXILIARY_GRAIN128) $(HEADERS)
	$(NVCC)  ${SRCDIR}/cubeCuda.cu -o $(BIN)/kite_attack_grain128 $(TWIDDLE) $(AUXILIARY_GRAIN128) $(CUDA_FLAGS) -DGRAIN128_CIPHER 

kite_attack_mickey2: ${SRCDIR}/cubeCuda.cu $(TWIDDLE) $(AUXILIARY_MICKEY2) $(HEADERS)
	$(NVCC)  ${SRCDIR}/cubeCuda.cu -o $(BIN)/kite_attack_mickey2 $(TWIDDLE) $(AUXILIARY_MICKEY2) $(CUDA_FLAGS) -DMICKEY2_CIPHER -DMICKEY_IV_LEN=${MICKEY_IV_LEN} 

####### CLEAN ############
.PHONY: clean
clean:
	-rm -f  $(BIN)/*
	-rm -rf $(SRCDIR)/*.o

