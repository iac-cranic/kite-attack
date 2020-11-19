#!/bin/bash

################################################################################################## 
# Author: Marco Cianfriglia                                                                      #
# Email: <m.cianfriglia@iac.cnr.it>                                                              #
# File: genConfigFile.sh                                                                         #
#   It will allow to generate configuration files to run                                         #
#   the KiteAttack on GPU against supported ciphers                                              #
#                                                                                                #
#   See https://doi.org/10.1007/s13389-019-00217-3                                               #
#                                                                                                #
#                                                                                                #
# If you use the Kite Attack framework in a scientific                                           #
# publication, we would appreciate citations to                                                  #
# the following paper:                                                                           #
#                                                                                                #
# bibtex{                                                                                        #
#    @Article{Cianfriglia2019,                                                                   #
#    author="Cianfriglia, Marco                                                                  #
#    and Guarino, Stefano                                                                        #
#    and Bernaschi, Massimo                                                                      #
#    and Lombardi, Flavio                                                                        #
#    and Pedicini, Marco",                                                                       #
#    title="Kite attack: reshaping the cube attack for a flexible GPU-based maxterm search",     #
#    journal="Journal of Cryptographic Engineering",                                             #
#    year="2019",                                                                                #
#    month="May",                                                                                #
#    day="27",                                                                                   #
#    issn="2190-8516",                                                                           #
#    doi="10.1007/s13389-019-00217-3",                                                           #
#    url="https://doi.org/10.1007/s13389-019-00217-3"                                            #
#    }                                                                                           #
# }                                                                                              #
#                                                                                                #
##################################################################################################


TRIVIUM_IV_SIZE=80
GRAIN128_IV_SIZE=96
MICKEY2_IV_SIZE=80
DEFAULT_ROUNDS_GRAIN128=256 #up to 256
DEFAULT_ROUNDS_TRIVIUM=1152 #up to 1152
DEFAULT_ROUNDS_MICKEY2=100 #up to 100


NEW_CONFIG="Generate a new configuration File"
QUIT="Quit"
TRIVIUM_STRING="Trivium"
GRAIN128_STRING="Grain128"
MICKEY2_STRING="Mickey2"
ALPHA_STRING="I_max"
ALPHA_MINUS_BETA_STRING="I_max_minus_I_min"
BETA_STRING="I_min"
ALPHA_SET_STRING="I_MAX_SET"
BETA_SET_STRING="I_MIN_SET"
ALPHA_MINUS_BETA_SET_STRING="I_MAX_minus_I_MIN_SET"
#ALPHA_STRING="ALPHA"
#BETA_STRING="BETA"
#ALPHA_SET_STRING="ALPHA_SET"
#BETA_SET_STRING="BETA_SET"
NUM_ROUNDS_STRING="INIT_ROUNDS"
RUN_IDENTIFIIER_STRING="RUN_IDENTIFIER"
SUPPORTED_CIPHER="${TRIVIUM_STRING} ${GRAIN128_STRING} ${MICKEY2_STRING}" 
DEFAULT_TARGET=0
TARGET_CIPHER=""
ALPHA=0
BETA=0
OUTPUT_FILE=""

NEW_CONFIG="Generate a new configuration File"
QUIT="Quit"

print_configuration_header(){
    echo "NOT IMPLEMENTED YET"
}

test_number(){

    re='^[0-9]+$'
    if ! [[ $1 =~ $re ]] ; 
    then
        echo "[ERROR]: Not a number" >&2; 
        exit 1
    fi

    return 1
}



test_alpha(){

    local a=$1
    local cipher=$2
    local max=0
    case ${cipher} in
        ${TRIVIUM_STRING})
            max=${TRIVIUM_IV_SIZE}
            ;;
        ${GRAIN128_STRING})
            max=${GRAIN128_IV_SIZE}
            ;;
	${MICKEY2_STRING})
	    max=${MICKEY2_IV_SIZE}
	    ;;
    esac
    if [ ${a} -ge ${max} ]
    then
        echo "[ERROR]: Invalid value provided for Alpha (${a}). It cannot be greater than ${cipher} IV size (${max})"
        exit 1
    fi

    if [ ${a} -le 0 ]
    then
        echo "[ERROR]: Invalid value provided for Alpha (${a}). It cannot be less or equal to 0"
        exit 1
    fi


}

test_alpha_beta(){

    local a=$1
    local b=$2

    if [ ${b} -ge ${a} ]
    then
        echo "[ERROR]: The value of I_max  (${a}) must be greaten than I_min  (${b})"
        exit 1
    fi
    if [ ${b} -le 0 ]
    then
        echo "[ERROR]: Invalid value provided for Beta (${b}). It cannot be less or equal to 0"
        exit 1
    fi

}

test_indexes(){

    local a=$1
    local cipher=$2
    local max=0
    case ${cipher} in
        ${TRIVIUM_STRING})
            max=${TRIVIUM_IV_SIZE}
            ;;
        ${GRAIN128_STRING})
            max=${GRAIN128_IV_SIZE}
            ;;
	${MICKEY2_STRING})
	    max=${MICKEY2_IV_SIZE}
	    ;;
    esac


    if [ ! ${a} -lt ${max} ]
    then
        echo "[ERROR]: Invalid value provided (${a}). It cannot be greater than or equal to ${cipher} IV size (${max})"
        exit 1
    fi

    if [ ${a} -lt 0 ]
    then
        echo "[ERROR]: Invalid value provided (${a}). It cannot be less than 0"
        exit 1
    fi


}


# CRANIC BANNER
echo "::::::::::::::::'######::'########:::::'###::::'##::: ##:'####::'######:::::::::::::::::";
echo ":::::::::::::::'##... ##: ##.... ##:::'## ##::: ###:: ##:. ##::'##... ##::::::::::::::::";
echo "::::::::::::::: ##:::..:: ##:::: ##::'##:. ##:: ####: ##:: ##:: ##:::..:::::::::::::::::";
echo "::::::::::::::: ##::::::: ########::'##:::. ##: ## ## ##:: ##:: ##::::::::::::::::::::::";
echo "::::::::::::::: ##::::::: ##.. ##::: #########: ##. ####:: ##:: ##::::::::::::::::::::::";
echo "::::::::::::::: ##::: ##: ##::. ##:: ##.... ##: ##:. ###:: ##:: ##::: ##::::::::::::::::";
echo ":::::::::::::::. ######:: ##:::. ##: ##:::: ##: ##::. ##:'####:. ######:::::::::::::::::";
echo "::::::::::::::::......:::..:::::..::..:::::..::..::::..::....:::......::::::::::::::::::";
echo "'########::'########::'######::'########::::'###::::'########:::'######::'##::::'##:::: ";
echo " ##.... ##: ##.....::'##... ##: ##.....::::'## ##::: ##.... ##:'##... ##: ##:::: ##:::: ";
echo " ##:::: ##: ##::::::: ##:::..:: ##::::::::'##:. ##:: ##:::: ##: ##:::..:: ##:::: ##:::: ";
echo " ########:: ######:::. ######:: ######:::'##:::. ##: ########:: ##::::::: #########:::: ";
echo " ##.. ##::: ##...:::::..... ##: ##...:::: #########: ##.. ##::: ##::::::: ##.... ##:::: ";
echo " ##::. ##:: ##:::::::'##::: ##: ##::::::: ##.... ##: ##::. ##:: ##::: ##: ##:::: ##:::: ";
echo " ##:::. ##: ########:. ######:: ########: ##:::: ##: ##:::. ##:. ######:: ##:::: ##:::: ";
echo "..:::::..::........:::......:::........::..:::::..::..:::::..:::......:::..:::::..::::: ";
echo "::::::::::::::::'######:::'########:::'#######::'##::::'##:'########::::::::::::::::::::";
echo ":::::::::::::::'##... ##:: ##.... ##:'##.... ##: ##:::: ##: ##.... ##:::::::::::::::::::";
echo "::::::::::::::: ##:::..::: ##:::: ##: ##:::: ##: ##:::: ##: ##:::: ##:::::::::::::::::::";
echo "::::::::::::::: ##::'####: ########:: ##:::: ##: ##:::: ##: ########::::::::::::::::::::";
echo "::::::::::::::: ##::: ##:: ##.. ##::: ##:::: ##: ##:::: ##: ##.....:::::::::::::::::::::";
echo "::::::::::::::: ##::: ##:: ##::. ##:: ##:::: ##: ##:::: ##: ##::::::::::::::::::::::::::";
echo ":::::::::::::::. ######::: ##:::. ##:. #######::. #######:: ##::::::::::::::::::::::::::";
echo "::::::::::::::::......::::..:::::..:::.......::::.......:::..:::::::::::::::::::::::::::";

# KITE ATTACK BANNER





TRIVIUM_INFO="[INFO] TRIVIUM: IV_SIZE: 80 (IV_0 .... IV_79) - KEY_SIZE: 80 (K_0 .... K_79) - Number of initialization rounds: 1152"
GRAIN128_INFO="[INFO] GRAIN128: IV_SIZE: 96 (IV_0 .... IV_95) - KEY_SIZE: 128 (K_0 .... K_127) - Number of initialization rounds: 256"
MICKEY2_INFO="[INFO] MICKEY2: IV_SIZE: up to 80 (IV_0 .... IV_79) - KEY_SIZE: 80 (K_0 .... K_79) - Number of initialization rounds: 100"


echo "This script will help you to create the configuration file for the Kite Attack."
echo "To test your installation, please use the configuration files in config directory"
echo "Please follow the instructions and answer the question."

run_id=$(mktemp -u  KITE_XXXXXXXXXX)

            default_output="newKiteAttack.conf"
            read -p "Where do you want to save the configuration? (default ${default_output}): " OUTPUT_FILE 
            : ${OUTPUT_FILE:=${default_output}}
            echo "${OUTPUT_FILE}"

	    echo "Select the target cipher: "
            select target_cipher in ${SUPPORTED_CIPHER};
            do
                echo "Selected ${target_cipher}"
                echo "TARGET_CIPHER=${target_cipher}" > "${OUTPUT_FILE}"
                break
            done

            default_rounds=0
            case ${target_cipher} in
                ${TRIVIUM_STRING})
                    default_rounds=${DEFAULT_ROUNDS_TRIVIUM}
                    echo "${TRIVIUM_INFO}"
                    ;;
                ${GRAIN128_STRING})
                    default_rounds=${DEFAULT_ROUNDS_GRAIN128}
                    echo "${GRAIN128_INFO}"
                    ;;
                ${MICKEY2_STRING})
                    default_rounds=${DEFAULT_ROUNDS_MICKEY2}
                    echo "${MICKEY2_INFO}"
            esac
            
            echo "Choose the number of initialization rounds for the selected cipher. Please note that usually to calibrate the attack its better to start with a number of round less than the default (for example $(( ${default_rounds}/2)) )"
            read -p "Insert the number of initialization rounds for the selected cipher: (default ${default_rounds}): " num_rounds
            : ${num_rounds:=${default_rounds}}
            test_number ${num_rounds}
            echo "${NUM_ROUNDS_STRING}=${num_rounds}" >> "${OUTPUT_FILE}"

            read -p "Insert run Identifier: (automatically generated: ${run_id}): " RUN_IDENTIFIER
            : ${RUN_IDENTIFIER:=${run_id}}
            echo "${RUN_IDENTIFIIER_STRING}=${RUN_IDENTIFIER}" >> "${OUTPUT_FILE}"


            read -p "Insert the value of I_max ": alpha
            #read -p "Insert the value of Alpha ": alpha
            test_number ${alpha} 
            test_alpha ${alpha} ${target_cipher}

            read -p "Insert the value of I_min": beta
            #read -p "Insert the value of Beta": beta
            test_number ${beta} 
            test_alpha_beta ${alpha} ${beta} 
	    alpha_minus_beta=$(( $alpha - $beta ))
            echo "${ALPHA_STRING}=${alpha}" >> "${OUTPUT_FILE}"
            echo "${ALPHA_MINUS_BETA_STRING}=${alpha_minus_beta}" >> "${OUTPUT_FILE}"
            echo "${BETA_STRING}=${beta}" >> "${OUTPUT_FILE}"

            declare -a union_set

            declare -a beta_set

            for (( i = 0 ; i < ${beta}; i++ )) 
            do
                read -p "Insert the ${i}-th value that belongs to I_min (please note that the indexes start from 0): " beta_set[${i}]
                test_number ${beta_set[${i}]} ${target_cipher} 
                union_set[${i}]=${beta_set[${i}]}
            done

            echo "[INFO]: I_min={${beta_set[*]}}"
            #echo "[INFO]: ${BETA_SET_STRING}={${beta_set[*]}}"
            
            declare -a alpha_set

	    alpha_minus_beta=$(( $alpha - $beta ))
	    for (( i = 0, j = ${beta}; i < ${alpha_minus_beta}; i++, j++ )) 
            do
                read -p "Insert the ${i}-th value that belongs to I_max but not to I_min (i.e. (I_max\\ I_min)) (please note that the indexes start from 0): " alpha_set[${i}]
                test_number ${alpha_set[${i}]} ${target_cipher} 
                union_set[${j}]=${alpha_set[${i}]}
            done

            echo "[INFO]: (I_max\\I_min)={${alpha_set[*]}}"
            #echo "[INFO]: ${ALPHA_SET_STRING}={${alpha_set[*]}}"
           
            # Check alpha and beta sets
            # - Duplicates are not allowed
            # - Intersections are not allowed
            count=$( echo "${union_set[*]}" | tr -s " " "\n" | sort -n | uniq | wc -l)

            if [ ${count} -ne $(( $alpha )) ]
            #if [ ${count} -ne $(( $alpha + $beta )) ]
            then
                echo "[ERROR]: Invalid sets provided" 
                echo "[INFO]: The sets cannot contain duplicate values"
                echo "[INFO]: The intersection between I_min and (I_max \\ I_min) must be empty"
                #echo "[INFO]: The intersection between Alpha and Beta sets must be empty"
                echo "I_max\\I_min: ${alpha_set[*]}"
                echo "I_min: ${Beta_set[*]}"
                #echo "${ALPHA_SET_STRING}: ${alpha_set[*]}"
                #echo "${BETA_SET_STRING}: ${Beta_set[*]}"
                exit 1
            fi

            printf "%s={" ${ALPHA_SET_STRING} >> ${OUTPUT_FILE}
            a=$( echo "${union_set[*]}" | xargs -n1 | sort -n | xargs | tr -s " " "," )
            printf "$a}\n" >> ${OUTPUT_FILE}

            printf "%s={" ${ALPHA_MINUS_BETA_SET_STRING} >> ${OUTPUT_FILE}
            a=$( echo "${alpha_set[*]}" | xargs -n1 | sort -n | xargs | tr -s " " "," )
            printf "$a}\n" >> ${OUTPUT_FILE}

            printf "%s={" ${BETA_SET_STRING} >> ${OUTPUT_FILE}
            a=$( echo "${beta_set[*]}" | xargs -n1 | sort -n | xargs | tr -s " " "," )
            printf "$a}\n" >> ${OUTPUT_FILE}


    echo "The configuration file ${OUTPUT_FILE} has been successfully generated"
    echo "================================="
    cat ${OUTPUT_FILE}
    echo "================================="
    echo ""
    echo "Good luck with your attack!!"
   


