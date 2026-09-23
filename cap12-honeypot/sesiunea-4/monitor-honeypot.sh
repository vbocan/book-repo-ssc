#!/bin/bash
# monitor-honeypot.sh: rulat din cron la fiecare 5 minute
WEBHOOK="${WEBHOOK:-https://ntfy.sh/<subiect-secret>}"  # sau webhook Discord/Teams
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:9090/}"
STATE_DIR="$HOME/.honeypot-monitor"
mkdir -p "$STATE_DIR"

notify() { curl -s -m 10 -d "$1" "$WEBHOOK" > /dev/null; }

# 1. Starea: alertă doar când se schimbă (UP -> DOWN sau DOWN -> UP)
if response=$(curl -sf -m 5 "$HEALTH_URL"); then state=UP; else state=DOWN; fi
previous=$(cat "$STATE_DIR/state" 2>/dev/null || echo UP)
if [ "$state" != "$previous" ]; then
    notify "Honeypot $(hostname): $previous -> $state"
    echo "$state" > "$STATE_DIR/state"
fi
[ "$state" = DOWN ] && exit 1

# 2. Vârf de activitate: ultima oră peste de 5 ori media orară din ultimele
#    24 de ore (plus o marjă de 50), cel mult o alertă la 6 ore
last_hour=$(echo "$response" | awk '/^LastHour:/ {print $2}')
last_24h=$(echo "$response" | awk '/^Last24h:/ {print $2}')
threshold=$(( 5 * ${last_24h:-0} / 24 + 50 ))
if [ "${last_hour:-0}" -gt "$threshold" ] &&
   [ -z "$(find "$STATE_DIR/spike" -mmin -360 2>/dev/null)" ]; then
    notify "Honeypot $(hostname): $last_hour conexiuni in ultima ora (prag $threshold)"
    touch "$STATE_DIR/spike"
fi

# 3. Spațiul pe disc, cel mult o alertă pe zi
disk=$(df --output=pcent / | tail -1 | tr -dc '0-9')
if [ "${disk:-0}" -gt 85 ] &&
   [ -z "$(find "$STATE_DIR/disk" -mmin -1440 2>/dev/null)" ]; then
    notify "Honeypot $(hostname): disc ocupat ${disk}%"
    touch "$STATE_DIR/disk"
fi
