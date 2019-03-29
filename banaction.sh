if ! (iptables -nL $2 | grep -q "$1");
  then
       iptables -I $2 1 -s $1 -j REJECT #script de rejet
  fi
