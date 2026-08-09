#!/bin/sh
# Проверки для этапов 3 и 4 из docs/rule-conditions-design.md, раздел 15.
#
# Запускается на роутере, где установлен sing-box. Ничего не применяет и не
# перезапускает: пишет конфигурации в /tmp и отдаёт их `sing-box check`.
# Проверки, которые трогают живую службу, скрипт не выполняет — он печатает
# для них процедуру, потому что каждая из них на время оставляет дом без
# интернета, и решать, когда это делать, должен человек.
#
#   scp tests/router-checks.sh root@192.168.1.1:/tmp/
#   ssh root@192.168.1.1 sh /tmp/router-checks.sh
#
# Вывод: по строке на проверку — PASS, FAIL или SKIP — и причина отказа от
# sing-box. В конце сводка о том, что каждый исход значит для реализации.

SING_BOX=${SING_BOX:-/usr/bin/sing-box}
WORK=/tmp/zarap-checks
PASSED=0
FAILED=0

# Общая часть всех конфигураций. Только tproxy-inbound и direct-outbound:
# vless потребовал бы настоящего Reality-ключа, а проверяется здесь схема
# маршрутизации, а не разбор ссылки.
BASE_INBOUND='{"type":"tproxy","tag":"zarap-tproxy","listen":"0.0.0.0","listen_port":7893}'
BASE_OUTBOUND='{"type":"direct","tag":"direct"}'

emit() {
	# emit <файл> <route-json> [<остальные-верхнеуровневые-поля>]
	printf '{"log":{"level":"info"},"inbounds":[%s],"outbounds":[%s],"route":%s%s}\n' \
		"$BASE_INBOUND" "$BASE_OUTBOUND" "$2" "$3" > "$1"
}

check() {
	# check <название> <файл>
	output=$("$SING_BOX" check -c "$2" 2>&1)
	if [ $? -eq 0 ]; then
		PASSED=$((PASSED + 1))
		printf 'PASS  %s\n' "$1"
		return 0
	fi
	FAILED=$((FAILED + 1))
	printf 'FAIL  %s\n      %s\n' "$1" "$(echo "$output" | head -n 2 | tr '\n' ' ')"
	return 1
}

[ -x "$SING_BOX" ] || { echo "sing-box не найден в $SING_BOX"; exit 1; }
mkdir -p "$WORK" || exit 1

echo "== Версия =="
"$SING_BOX" version | head -n 1
if "$SING_BOX" rule-set --help >/dev/null 2>&1; then
	echo "подкоманда rule-set: есть"
else
	echo "подкоманда rule-set: нет — разбирать формат .srs на роутере будет нечем"
fi
echo

echo "== Статические проверки схемы =="

# 1. То, что Zarap генерирует уже сегодня: источник, диапазон, порты, протокол.
# Тесты под ucode проверяют форму JSON, но не то, что её принимает бинарник.
emit "$WORK/conditions.json" '{"auto_detect_interface":true,"rules":[
 {"inbound":["zarap-tproxy"],"source_ip_cidr":["192.168.1.50/32"],"ip_cidr":["149.154.160.0/20"],"port":[443],"port_range":["1000:2000"],"network":["udp"],"outbound":"direct"},
 {"inbound":["zarap-tproxy"],"network":["udp"],"port":[443],"action":"reject"}
],"final":"direct"}'
check "условия по адресам, портам и протоколу" "$WORK/conditions.json"

# 2. Снифинг как действие правила: старый inbound.sniff удалён в 1.13.0.
emit "$WORK/sniff.json" '{"auto_detect_interface":true,"rules":[
 {"inbound":["zarap-tproxy"],"action":"sniff"},
 {"inbound":["zarap-tproxy"],"domain":["youtube.com"],"domain_suffix":[".youtube.com"],"outbound":"direct"}
],"final":"direct"}'
check "action: sniff и условия по доменам" "$WORK/sniff.json"

# 3. Снифинг с таймаутом: если поле не принимается, ждать придётся умолчание.
emit "$WORK/sniff-timeout.json" '{"auto_detect_interface":true,"rules":[
 {"inbound":["zarap-tproxy"],"action":"sniff","timeout":"500ms"}
],"final":"direct"}'
check "sniff с явным timeout" "$WORK/sniff-timeout.json"

# 4. Удалённый список с детуром и расписанием плюс кэш на постоянном разделе.
emit "$WORK/ruleset.json" '{"auto_detect_interface":true,"rule_set":[
 {"type":"remote","tag":"rs_1","format":"binary","url":"https://example.org/geosite-ads.srs","download_detour":"direct","update_interval":"1d"}
],"rules":[
 {"inbound":["zarap-tproxy"],"rule_set":["rs_1"],"action":"reject"}
],"final":"direct"}' ',"experimental":{"cache_file":{"enabled":true,"path":"/etc/zarap/cache.db"}}'
check "remote rule_set + download_detour + cache_file" "$WORK/ruleset.json"

# 5. Локальный список — запасной вариант, если удалённый откажется работать.
# Файл собирается тут же: check не ограничивается схемой, он открывает и
# разбирает .srs, так что проверка по несуществующему пути ничего не сказала бы
# о форме. Заодно видно, собирает ли установленный бинарник списки сам.
printf '{"version":2,"rules":[{"domain_suffix":[".example.com"]}]}\n' > "$WORK/rs_1.json"
rm -f "$WORK/rs_1.srs"
COMPILED=$("$SING_BOX" rule-set compile --output "$WORK/rs_1.srs" "$WORK/rs_1.json" 2>&1)
if [ -f "$WORK/rs_1.srs" ]; then
	printf '{"log":{"level":"info"},"inbounds":[%s],"outbounds":[%s],"route":{"auto_detect_interface":true,"rule_set":[{"type":"local","tag":"rs_1","format":"binary","path":"%s"}],"rules":[{"inbound":["zarap-tproxy"],"rule_set":["rs_1"],"action":"reject"}],"final":"direct"}}\n' \
		"$BASE_INBOUND" "$BASE_OUTBOUND" "$WORK/rs_1.srs" > "$WORK/ruleset-local.json"
	check "local rule_set из собранного .srs" "$WORK/ruleset-local.json"
	printf '      собранный .srs: %s байт\n' "$(wc -c < "$WORK/rs_1.srs")"
else
	printf 'SKIP  local rule_set: rule-set compile не собрал .srs\n      %s\n' \
		"$(echo "$COMPILED" | head -n 1)"
fi

# 6. Этап 4: слушатель DNS. Inbound типа direct объявлялся устаревшим, так что
# именно здесь схема установленной версии может разойтись с ожидаемой.
printf '{"log":{"level":"info"},"inbounds":[%s,{"type":"direct","tag":"dns-in","listen":"127.0.0.1","listen_port":5353}],"outbounds":[%s],"route":{"rules":[{"inbound":["dns-in"],"action":"hijack-dns"}],"final":"direct"}}\n' \
	"$BASE_INBOUND" "$BASE_OUTBOUND" > "$WORK/dns-inbound.json"
check "direct inbound + action: hijack-dns" "$WORK/dns-inbound.json"

# 7. Этап 4: типизированные DNS-серверы (1.12+) и, отдельно, старая форма.
printf '{"log":{"level":"info"},"inbounds":[%s],"outbounds":[%s],"route":{"final":"direct"},"dns":{"servers":[{"type":"https","tag":"dns_out_1","server":"1.1.1.1","detour":"direct"}],"rules":[{"domain_suffix":[".youtube.com"],"server":"dns_out_1"}],"strategy":"ipv4_only","final":"dns_out_1"}}\n' \
	"$BASE_INBOUND" "$BASE_OUTBOUND" > "$WORK/dns-typed.json"
check "dns.servers в типизированной форме (1.12+)" "$WORK/dns-typed.json"

printf '{"log":{"level":"info"},"inbounds":[%s],"outbounds":[%s],"route":{"final":"direct"},"dns":{"servers":[{"tag":"dns_out_1","address":"https://1.1.1.1/dns-query","detour":"direct"}],"rules":[{"domain_suffix":[".youtube.com"],"server":"dns_out_1"}],"strategy":"ipv4_only","final":"dns_out_1"}}\n' \
	"$BASE_INBOUND" "$BASE_OUTBOUND" > "$WORK/dns-legacy.json"
check "dns.servers в старой форме (address)" "$WORK/dns-legacy.json"

echo
echo "== Ходит ли сам check в сеть =="
# Если проверка конфигурации скачивает списки, она перестаёт быть дешёвой:
# validate в Zarap начнёт ждать сеть внутри RPC-вызова LuCI. Адрес выбран
# нероутируемый, чтобы разница между «не качает» и «качает» была во времени.
emit "$WORK/ruleset-unreachable.json" '{"auto_detect_interface":true,"rule_set":[
 {"type":"remote","tag":"rs_1","format":"binary","url":"https://10.255.255.1/geosite.srs","download_detour":"direct","update_interval":"1d"}
],"rules":[
 {"inbound":["zarap-tproxy"],"rule_set":["rs_1"],"action":"reject"}
],"final":"direct"}' ',"experimental":{"cache_file":{"enabled":true,"path":"/tmp/zarap-check-cache.db"}}'
STARTED=$(date +%s)
"$SING_BOX" check -c "$WORK/ruleset-unreachable.json" >/dev/null 2>&1
CODE=$?
ELAPSED=$(( $(date +%s) - STARTED ))
rm -f /tmp/zarap-check-cache.db
printf 'код %s, %s с\n' "$CODE" "$ELAPSED"
if [ "$ELAPSED" -ge 3 ]; then
	echo "  ВНИМАНИЕ: check ждал сеть. validate придётся вызывать без remote rule_set"
	echo "  или уводить проверку из синхронного RPC."
else
	echo "  check не качает списки — validate остаётся дешёвым."
fi

echo
echo "== Место =="
df -h /overlay 2>/dev/null | tail -n 1
[ -f /etc/zarap/cache.db ] && ls -l /etc/zarap/cache.db

echo
printf 'Итог схемы: PASS %s, FAIL %s\n' "$PASSED" "$FAILED"

cat <<'PROCEDURE'

== Что нужно проверить на живой службе ==

Эти проверки скрипт не выполняет: каждая на время оставляет дом без
интернета. Порядок — от самой дешёвой к самой грубой.

1. Переживает ли ip_cidr снифинг (решает порядок групп, раздел 5.1).
   Написать правило с доменом и правило с диапазоном, применить, открыть
   сайт из доменного правила и посмотреть журнал:
       logread -e sing-box | grep 'outbound connection'
   Если в строке имя (example.com:443) — снифинг подменил назначение, и
   правила по ip_cidr после доменных перестанут совпадать: тогда группа с
   ip_cidr обязана идти перед доменной. Если адрес — порядок свободный.

2. Старт без кэша при недоступном источнике (решает риск 6 и текст ошибки).
       /etc/init.d/sing-box stop
       mv /etc/zarap/cache.db /tmp/cache.db.bak 2>/dev/null
       # подставить в /etc/zarap/sing-box.json url https://10.255.255.1/x.srs
       /etc/init.d/sing-box start; sleep 5
       /etc/init.d/sing-box running; echo "running=$?"
       ss -lntup | grep 7893
       logread -e sing-box | tail -n 20
   Служба не поднялась — откат в apply срабатывает, сообщение должно
   называть список. Поднялась и работает без списка — риск 6 мягче, чем
   записано, и текст ошибки не нужен, а нужно предупреждение на странице.

3. Переживает ли кэш перезагрузку (ради этого он лежит в /etc/zarap).
       ls -l /etc/zarap/cache.db && reboot
   После перезагрузки: сразу ли поднялся TProxy-порт и есть ли в журнале
   повторная загрузка списка.

4. Что делает sing-box, когда кэш некуда писать.
   Заполнять /overlay не нужно — достаточно крошечного tmpfs:
       mkdir -p /tmp/tiny && mount -t tmpfs -o size=64k tmpfs /tmp/tiny
       # cache_file.path = /tmp/tiny/cache.db, затем перезапуск
       umount /tmp/tiny   # после проверки
   Работает без кэша — переполненный flash остаётся предупреждением.
   Отказывается стартовать — это отказ запуска, и предупреждать надо
   заранее и жёстче.

5. Этап 4: пересылка по домену в dnsmasq.
       uci add_list dhcp.@dnsmasq[0].server='/example.com/127.0.0.1#5353'
       uci commit dhcp && /etc/init.d/dnsmasq restart
   С клиента: nslookup example.com <адрес роутера> — и убедиться, что
   остальные имена резолвятся как раньше. Откат: uci del_list той же строки.

Результаты — в docs/rule-conditions-design.md, раздел 15, рядом с таблицей
проверок; расхождения меняют разделы 5.1, 8.2 и риски 6 и 7.
PROCEDURE
