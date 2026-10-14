#!/bin/sh
# Suricata entrypoint.
# 1. Try to fetch the ET/open ruleset with suricata-update (120s budget; the
#    container starts offline-safe).
# 2. Always install the shipped local.rules; if suricata.rules is missing
#    (offline first boot), local.rules doubles as suricata.rules.
# 3. Ensure classification/reference config files exist, then exec suricata in
#    af-packet mode on eth0 (network_mode: host). eve.json lands on the
#    suricata-logs volume -> fluent-bit -> api.
set -u

mkdir -p /var/lib/suricata/rules /var/log/suricata

if command -v suricata-update >/dev/null 2>&1; then
    echo "[suricata] running suricata-update (120s budget)"
    if timeout 120 suricata-update --no-reload; then
        echo "[suricata] suricata-update finished"
    else
        echo "[suricata] WARNING: suricata-update failed (offline or blocked) - using local baseline rules"
    fi
    # suricata-update leaks ~44MB tmp dirs per run; without this /tmp grows
    # unbounded across container restarts and fills the overlay (observed
    # 351MB after 4 days on a 10GB VPS).
    rm -rf /tmp/tmp*suricata-update 2>/dev/null || true

    # Classtype filter: the full ET/open set is ~69k rules (44MB of text) and
    # compiles to suricata's entire 256MB cgroup — its constant self-reclaim
    # starved every other service on this 512MB box. Keep the attack-relevant
    # classtypes a honeypot actually needs; drop info/policy/protocol noise.
    RULES=/var/lib/suricata/rules/suricata.rules
    if [ -f "$RULES" ]; then
        total=$(grep -c '^alert ' "$RULES" || true)
        grep -E '^alert .*classtype:(trojan-activity|attempted-admin|attempted-user|attempted-recon|web-application-attack|web-application-activity|scan|shellcode-detect|attempted-dos|denial-of-service|misc-attack|default-login-attempt|suspicious-login|bad-unknown|policy-violation|file-format)' \
            "$RULES" > "$RULES.keep" || true
        kept=$(grep -c '^alert ' "$RULES.keep" 2>/dev/null || echo 0)
        if [ "${kept:-0}" -gt 0 ]; then
            mv "$RULES.keep" "$RULES"
            echo "[suricata] rules filtered: $total -> $kept (attack classtypes only)"
        else
            rm -f "$RULES.keep"
            echo "[suricata] classtype filter matched nothing - keeping all $total rules"
        fi
    fi
else
    echo "[suricata] suricata-update not present - using local baseline rules"
fi

cp /etc/suricata/rules/local.rules /var/lib/suricata/rules/local.rules

# local.rules is always loaded via rule-files; when the ruleset update failed
# (offline first boot) just make sure suricata.rules exists as an empty, valid
# file — copying local.rules there too would duplicate every sid and make
# suricata refuse to load the ruleset.
if [ ! -s /var/lib/suricata/rules/suricata.rules ]; then
    echo "[suricata] no suricata.rules present - running on the local.rules baseline"
    : > /var/lib/suricata/rules/suricata.rules
fi

if [ ! -f /etc/suricata/classification.config ]; then
    echo "[suricata] writing minimal classification.config"
    cat > /etc/suricata/classification.config <<'EOF'
config classification: attempted-user,Attempted User Privilege Gain,1
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: attempted-recon,Attempted Information Leak,2
config classification: web-application-attack,Web Application Attack,1
config classification: trojan-activity,A Network Trojan was detected,1
config classification: misc-activity,Misc activity,3
config classification: misc-attack,Misc Attack,2
config classification: bad-unknown,Bad Unknown Traffic,2
config classification: default,Unknown Traffic,3
EOF
fi

if [ ! -f /etc/suricata/reference.config ]; then
    echo "[suricata] writing minimal reference.config"
    printf 'config reference: cve http://cve.mitre.org/cgi-bin/cvename.cgi?name=\nconfig reference: url https://\n' > /etc/suricata/reference.config
fi

# Bake this host's global IPv4 addresses into a runtime copy of the config so
# $HOME_NET is concrete and $EXTERNAL_NET (! $HOME_NET) stays valid. The
# mounted yaml is read-only, hence the copy.
RUNTIME_CFG=/tmp/suricata-runtime.yaml
cp /etc/suricata/suricata.yaml "$RUNTIME_CFG"
HOSTIPS="$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); printf "%s/32,", a[1]}' | sed 's/,$//')"
if [ -z "$HOSTIPS" ]; then
    HOSTIPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | sed '/^$/d' | sed 's|$|/32|' | paste -sd, -)"
fi
if [ -z "$HOSTIPS" ]; then
    echo "[suricata] WARNING: could not detect host addresses - HOME_NET falls back to 0.0.0.0/32"
    HOSTIPS="0.0.0.0/32"
fi
echo "[suricata] HOME_NET = [${HOSTIPS}]"
sed -i "s|<HOME_NET_PLACEHOLDER>|${HOSTIPS}|" "$RUNTIME_CFG"

exec suricata -c "$RUNTIME_CFG" --af-packet
