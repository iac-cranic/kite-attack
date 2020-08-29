# [Kite attack: reshaping the cube attack for a flexible GPU-based maxterm search](https://doi.org/10.1007/s13389-019-00217-3)

**This repository contains the framework to launch Kite Attack against the following ciphers**:
 - Trivium
 - Grain128

## Table of contents
- [Installation]
    * [Requisites]
    * [Quick installation]
- [Getting started]
- [Examples]
- [Reproduce paper results]
- [FAQ]
- [Bugs]
- [Cite the paper]
- [Acknowledgment]
- [License]
- [Contact]

## Installation

### Requisites
- CUDA >= 7
- NVIDIA GPU, CUDA CAPABILITY >= 3.5
- gcc >= 4.5.0

### Quick installation
```make install```

## Getting started
In ```scripts``` directory, there is a Bash script that will generate a custom configuration file for your attack.
To test your installation, you can use the test configuration files inside ```config``` directory.
The executables are stored in ```bin``` directory.
## Examples
The following command shows how to run a simple attack against Trivium cipher using the test configuration file stored in ```config``` directory.

```bin/cuda_test_trivium 0 test_trivium.log config/testTrivium_0.conf output_directory_trivium0 ```

It will run the attack on the device 0 on your machine (run ```nvidia-smi``` to see the devices installed on your machine. You may also use ```CUDA_VISIBLE_DEVICES``` if you are running on a multi-user machine.) 

The output of the attack will be stored in the output_directory; it will print the number of cubes that pass all the linearity tests and it will compute and print the corresponding superpoly for each of them.
## Reproduce paper results

## FAQ

## Bugs
This framework is used and maintained for a research project and likely will have many bugs and issues.


## Cite the paper
[Kite attack: reshaping the cube attack for a flexible GPU-based maxterm search](https://doi.org/10.1007/s13389-019-00217-3)
```
@Article{Cianfriglia2019,
author="Cianfriglia, Marco
and Guarino, Stefano
and Bernaschi, Massimo
and Lombardi, Flavio
and Pedicini, Marco",
title="Kite attack: reshaping the cube attack for a flexible GPU-based maxterm search",
journal="Journal of Cryptographic Engineering",
year="2019",
month="May",
day="27",
abstract="Dinur and Shamir's cube attack has attracted significant attention in the literature. Nevertheless, the lack of implementations achieving effective results casts doubts on its practical relevance. On the theoretical side, promising results have been recently achieved leveraging on division trails. The present paper follows a more practical approach and aims at giving new impetus to this line of research by means of a cipher-independent flexible framework that is able to carry out the cube attack on GPU/CPU clusters. We address all issues posed by a GPU implementation, providing evidence in support of parallel variants of the attack and identifying viable directions for solving open problems in the future. We report the results of running our GPU-based cube attack against round-reduced versions of three well-known ciphers: Trivium, Grain-128 and SNOW 3G. Our attack against Trivium improves the state of the art, permitting full key recovery for Trivium reduced to (up to) 781 initialization rounds (out of 1152) and finding the first-ever maxterm after 800 rounds. In this paper, we also present the first standard cube attack (i.e., neither dynamic nor tester) to yield maxterms for Grain-128 up to 160 initialization rounds on non-programmable hardware. We include a thorough evaluation of the impact of system parameters and GPU architecture on the performance. Moreover, we demonstrate the scalability of our solution on multi-GPU systems. We believe that our extensive set of results can be useful for the cryptographic engineering community at large and can pave the way to further results in the area.",
issn="2190-8516",
doi="10.1007/s13389-019-00217-3",
url="https://doi.org/10.1007/s13389-019-00217-3"
}                                  
```

## Acknowledgment

## License
This software is released under the GPLv3 license.
Refer to [docs/LICENSE](docs/LICENSE) for more information.
This project has been developed in collaboration with National Research Council of Italy (CNR) and Roma Tre University.
Copyright(C) 2015-2020 Marco Cianfriglia (marco <DOT> cianfriglia <AT> gmail <DOT> com), Massimo Bernaschi (massimo <DOT> bernaschi <AT> gmail <DOT> com),
Stefano Guarino (stefano <DOT> guarino <AT> gmail <DOT> com), Flavio Lombardi (flavio <DOT> lombardi <AT> gmail <DOT> com), and Marco Pedicini (marco <DOT> pedicini <AT> gmail <DOT> com).
The file ```src/twiddle.c``` has been downloaded from [http://www.netlib.no/netlib/toms/382](http://www.netlib.no/netlib/toms/382). You will 
find the copyright inside it.
## Contact
For any question, please refer to [Marco Cianfriglia](mailto:marco<DOT>cianfriglia<AT>gmail<DOT>com)
If you are interested in contributing, please do it and visit also our [research group website](https://www.cranic.it) for open positions
