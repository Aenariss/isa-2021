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

# Prostor na pridavani testovacich vstupu
# Nekontroluju funkcionalitu ani prioritu -h z obvious duvodu, ze si muzem dat jake chcem
# Pozor u commandu jako logout, register... ze 1. vystup bude jiny od druheho (nejlip pustit 2x)
# Je taky dulezite mit zaply server -- Refrencni vypis neni nutne napodobovat a muze byt vlastni
compare_4_args "-a" "127.50.50.50" "-p" "69"
compare_4_args "-a" "127.50.50.50" "-p" "69a"
compare_4_args "-a" "420.50.50.50" "-p" "69"
compare_2_args "-ap" "420.50.50.50"
compare_2_args "-pa" "420.50.50.50"
compare_2_args "-pah" "420.50.50.50"
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
#compare_3_args "register" "pe\"pa" "he\"slo"
compare_4_args "send" "-p" "Test\nSubject\t\"idk uz" "Viceradkova\nZprava s escaped\t \"cahrakterama\""
compare_1_args "list"
compare_2_args "fetch" "1"


echo "Proslo: $correct/$all"