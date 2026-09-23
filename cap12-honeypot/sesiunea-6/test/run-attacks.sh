#!/bin/sh
# Pornește atacatorii simulați, fiecare cu altă adresă IP din 172.30.0.0/24
NET=honeypot_honeypot-net
attack() {
  docker run --rm --network $NET --ip 172.30.0.$1 \
    -v "$PWD/test:/t:ro" hp-attacker sh /t/attack.sh $2
}
attack 101 ftp-brute &
attack 102 ssh-scan &
attack 103 portscan &
attack 104 recon &
attack 105 scanner &
attack 109 telnet-brute &
wait
for ip in 106 107 108; do attack $ip campaign; done
