#!/usr/bin/env bash
# Independent reference for the benchmark: observes each site with curl and openssl only (no SecureSphere
# code), one site at a time, and prints one JSON object per line.
#   bash validation/independent_check.sh validation/dataset.csv > validation/independent.jsonl
# Uses the same identifying User-Agent as SecureSphere, so firewalls treat both the same way.
UA="Mozilla/5.0 (compatible; SecureSphere/1.0; +https://securesphere-psi.vercel.app)"
T=10

tls() {  # does the server complete a handshake with ONLY this protocol version?
  echo | timeout $T openssl s_client -connect "$1:$2" -servername "$1" "$3" -cipher 'ALL:@SECLEVEL=0' 2>/dev/null \
    | grep -E "^New, " | grep -qv "(NONE)" && echo true || echo false  # "New, SSLv3, Cipher is AES128-SHA" = success too
}

tail -n +2 "$1" | cut -d, -f1 | while read -r target; do
  host="${target%%:*}"; port="${target#*:}"; [ "$port" = "$target" ] && port=443
  # DNS: like SecureSphere, fall back to www when the bare name has no address
  curl -s -o /dev/null -m 5 "https://$host/" 2>/dev/null; [ $? -eq 6 ] && host="www.$host"  # 6 = name not found
  verify=$(echo | timeout $T openssl s_client -connect "$host:$port" -servername "$host" -verify_hostname "$host" 2>/dev/null \
           | grep -m1 "Verify return code" | sed -E 's/.*code: ([0-9]+) \((.*)\)/\1|\2/')
  enddate=$(echo | timeout $T openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null \
            | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  t10=$(tls "$host" "$port" -tls1); t11=$(tls "$host" "$port" -tls1_1); t12=$(tls "$host" "$port" -tls1_2); t13=$(tls "$host" "$port" -tls1_3)
  # headers of the final page after redirects (HTTPS), lowercased header names
  hdr=$(curl -s -m $T -k -L --max-redirs 4 -A "$UA" -o /dev/null -D - "https://$host/" 2>/dev/null | tr -d '\r' \
        | awk 'BEGIN{IGNORECASE=1} /^HTTP\//{h=""} {h=h"\n"$0} END{print h}' | tr 'A-Z' 'a-z')
  status=$(printf "%s" "$hdr" | grep -m1 -oE "^http/[0-9.]+ [0-9]+" | awk '{print $2}')
  has() { printf "%s" "$hdr" | grep -q "^$1:" && echo true || echo false; }
  redir=$(curl -s -m $T -o /dev/null -A "$UA" -w "%{http_code} %{redirect_url}" "http://$host/" 2>/dev/null)
  printf '{"target":"%s","host":"%s","verify":"%s","enddate":"%s","tls1_0":%s,"tls1_1":%s,"tls1_2":%s,"tls1_3":%s,"https_status":"%s","hsts":%s,"csp":%s,"xfo":%s,"xcto":%s,"referrer":%s,"http":"%s"}\n' \
    "$target" "$host" "$verify" "$enddate" "$t10" "$t11" "$t12" "$t13" "$status" \
    "$(has strict-transport-security)" "$(has content-security-policy)" "$(has x-frame-options)" \
    "$(has x-content-type-options)" "$(has referrer-policy)" "$redir"
done
