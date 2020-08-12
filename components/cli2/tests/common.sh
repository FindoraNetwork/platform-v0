FINDORA_STORE_FILE=${FINDORA_HOME:-${HOME}/.findora}/cli2_data.sqlite

setup() {
  # Start from a fresh state
  echo "Deleting $FINDORA_STORE_FILE..."
  rm  -f $FINDORA_STORE_FILE || true
  bash -c '{ echo; echo; } | $CLI2 setup'
}

debug_array() {

  echo "Debugging array..."
  arr=("$@")
  COUNTER=0
  for i in "${arr[@]}";
    do
        echo "[$COUNTER]$i"
        COUNTER=$((COUNTER+1))
    done
}

debug_lines(){
  debug_array "${lines[@]}"
}

check_line() {
  line_number="$1"
  command_str="$2"
  command_str_length=`expr length "$command_str"`
  [ "${lines[$line_number]:0:$command_str_length}" = "$command_str" ]
}

# Similar to check_line above but verifies that either line "i" or line "i+1" has the expected value
# The reason for that is that sometimes the http req fails the first time and thus an error message is written at line i
check_line_err() {
  line_number="$1"
  next_line_number=$line_number+1
  command_str="$2"
  command_str_length=`expr length "$command_str"`
  [[ ("${lines[$line_number]:0:$command_str_length}" = "$command_str" ) ||  ("${lines[$next_line_number]:0:$command_str_length}" = "$command_str") ]]
}

random_string()
{
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1
}

PASSWORD="password"
PASSWORD_PROMPT="echo -e '$PASSWORD\n$PASSWORD'"
SIMPLE_CONFIRM_WITH_PROMPT="echo -e '$PASSWORD\ny'"
SIMPLE_PASSWORD_PROMPT="echo -e '$PASSWORD'"
DOUBLE_CONFIRM_WITH_PROMPT="echo -e 'Y\nY\n'"
MEMO_ALICE_WITH_PROMPT="echo -e '$PASSWORD\nmemo_alice\n'"
ALICE_WITH_SEVERAL_PROMPTS="echo -e '$PASSWORD\n$PASSWORD\nY\nY\n'"
MEMO_ALICE_WITH_SEVERAL_PROMPTS="echo -e '$PASSWORD\nmemo_alice\n$PASSWORD\nY\nY\n'"

get_transfer_prompt_transfer_asset(){
  amount=$1
  utxo_name=$2
  PROMPT_TRANSFER_ASSET="echo -e '$utxo_name \n $amount \n n \n n \n bob \n n \n$PASSWORD\n'"
  echo $PROMPT_TRANSFER_ASSET
}

