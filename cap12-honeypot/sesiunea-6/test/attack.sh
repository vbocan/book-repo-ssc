#!/bin/sh
# Trafic de test, rulat din containere cu adrese IP diferite
H=honeypot-server
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

ftp_login() {   # $1 = utilizator, restul = parole încercate pe aceeași conexiune
  user=$1; shift
  ( sleep 1
    for p in "$@"; do
      printf 'USER %s\r\n' "$user"; sleep 0.3
      printf 'PASS %s\r\n' "$p"; sleep 1.3
    done
    printf 'QUIT\r\n'; sleep 1 ) | nc $H 21
}

case "$1" in
ftp-brute)      # 12 parole pe o conexiune, apoi 3 conexiuni cu clientul ftpget
  ftp_login admin 123456 password admin root 1234 12345678 qwerty \
    admin123 changeme default toor 'P@ssw0rd' > /dev/null
  for u in root ftpuser test; do
    ftpget -u $u -p $u $H /tmp/x.txt readme.txt 2>&1 | head -1
  done ;;
ssh-scan)       # 25 de conexiuni cu clientul OpenSSH, la ~1 s una de alta
  for i in $(seq 1 25); do
    sleep 1; ssh $SSH_OPTS root@$H true 2>&1 | head -1
  done | sort | uniq -c ;;
telnet-brute)   # 4 conexiuni x 3 încercări (clientul BusyBox trimite comenzi IAC)
  for c in 1 2 3 4; do
    ( sleep 1
      for pair in root:xc3511 admin:admin root:vizxv; do
        echo "${pair%%:*}"; sleep 0.5; echo "${pair#*:}"; sleep 2.6
      done ) | telnet $H 23 > /dev/null 2>&1
  done ;;
portscan)
  for p in 21 22 23 80 443; do nc -z -w 1 $H $p && echo "open $p"; done ;;
recon)
  curl -s -o /dev/null -w "GET / -> %{http_code}\n" http://$H/
  curl -s -o /dev/null -w "GET /admin -> %{http_code}\n" -u admin:admin http://$H/admin
  curl -sk -o /dev/null -w "HTTPS GET / -> %{http_code}\n" https://$H/
  curl -s -o /dev/null -w "POST /login -> %{http_code}\n" \
    -d 'username=administrator&password=Winter2026!' http://$H/login
  printf 'SYST\r\nLIST\r\nQUIT\r\n' | nc -w 3 $H 21 ;;
scanner)
  curl -s -o /dev/null -A "Mozilla/5.0 (compatible; research-scanner)" \
    -w "GET / -> %{http_code}\n" http://$H/ ;;
campaign)
  ftp_login admin admin ;;
esac
