home=$(pwd)
correct=0
all=0

function main_compare() {
    local cmp_res=$(cat tmp_out)
    local cmp_res_ref=$(cat tmp_out_ref)
    # Vystupy ref. klienta jsou retardovane, nutne porovnavat bud jako regexy nebo substringy
    if [[ "$cmp_res_ref" =~ "$cmp_res" ]]
    then
        echo "Ok"
        correct=$((correct+1))
        all=$((all+1))
    else 
        echo "ERROR!"
        echo "Tvoje reseni:      $cmp_res"
        echo "Referencni reseni: $cmp_res_ref"
        all=$((all+1))
    fi
    rm tmp_out
    rm tmp_out_ref
}

function compare_1_args() {
    $home/my_client "$1" &> tmp_out
    $home/client "$1" &> tmp_out_ref
    main_compare
}

function compare_2_args() {
    $home/my_client "$1" "$2" &> tmp_out
    $home/client "$1" "$2" &> tmp_out_ref
    main_compare
}

function compare_3_args() {
    $home/my_client "$1" "$2" "$3" &> tmp_out
    $home/client "$1" "$2" "$3" &> tmp_out_ref
    main_compare
}

function compare_4_args() {
    $home/my_client "$1" "$2" "$3" "$4" &> tmp_out
    $home/client "$1" "$2" "$3" "$4" &> tmp_out_ref
    main_compare
}

function compare_5_args() {
    $home/my_client "$1" "$2" "$3" "$4" "$5" &> tmp_out
    $home/client "$1" "$2" "$3" "$4" "$5" &> tmp_out_ref
    main_compare
}

function compare_6_args() {
    $home/my_client "$1" "$2" "$3" "$4" "$5" "$6" &> tmp_out
    $home/client "$1" "$2" "$3" "$4" "$5" "$6" &> tmp_out_ref
    main_compare
}

# Prostor na pridavani testovacich vstupu
# Nekontroluju funkcionalitu ani prioritu -h z obvious duvodu, ze si muzem dat jake chcem
# Pozor u commandu jako logout, register... ze 1. vystup bude jiny od druheho (nejlip pustit 2x)
# Je taky dulezite mit zaply server -- Refrencni vypis neni nutne napodobovat a muze byt vlastni
compare_5_args "-a" "127.0.0.1" "-p" "32323" "list"
compare_5_args "-aa" "127.0.0.1" "-p" "32323" "list"
compare_5_args "-aa" "127.0.0.1" "-pa" "32323" "list"
compare_5_args "-aa" "127.0.0.1" "-ap" "32323" "list"
compare_5_args "--address" "127.0.0.1" "--port" "32323" "list"
compare_4_args "--address" "127.0.0.1" "--port" "32323"
compare_4_args "-a" "127.0.0.1" "--port" "32323"
compare_4_args "--port" "32323" "--address" "127.0.0.1"
compare_5_args "-p" "32323" "--address" "--address" "127.0.0.1"
compare_5_args "-p" "32323" "--port" "32323" "127.0.0.1"
compare_5_args "-pp" "32323" "--port" "32323" "127.0.0.1"
compare_5_args "-p" "32323" "-pa" "32323" "127.0.0.1"
compare_4_args "-a" "127.0.0.1" "-p" "32323"
compare_3_args "-ap" "127.0.0.1" "32323"
compare_3_args "-pa" "32323" "127.0.0.1"
compare_5_args "-aa" "127.0.0.1" "-ap" "69" "list"
compare_4_args "-a" "127.0.0.1" "-p" "69"
compare_4_args "-a" "127.50.50.50" "-p" "69a"
compare_4_args "-a" "420.50.50.50" "-p" "69"
compare_6_args "-a" "420.50.50.50" "-ap" "127.0.0.1" "-p" "69"
compare_2_args "-ap" "420.50.50.50"
compare_2_args "-pa" "420.50.50.50"
compare_2_args "fetch" "-5"
compare_2_args "fetch" "1.5"
compare_2_args "fetch" "a^5"
compare_2_args "fetch" "1*1"
compare_1_args "420.50.50.50"
compare_3_args "list" "-p" "500"
compare_2_args "register" "-p"
compare_3_args "register" "-p" "500"
compare_3_args "login" "-p" "500"
compare_3_args "logout" "idk" "500"
compare_3_args "send" "idk" "500"
compare_1_args "fetch"
compare_1_args "register"
compare_1_args "list"
compare_1_args "unknown"
compare_4_args "send" "-p" "Test\nSubject\t\"idk uz" "Viceradkova\nZprava s escaped\t \"cahrakterama\""
compare_1_args "list"
compare_2_args "fetch" "1"


echo "Proslo: $correct/$all"