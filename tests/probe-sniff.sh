#!/bin/sh
# Проверка «переживает ли ip_cidr снифинг» — пункт 1 из раздела 15.2
# docs/rule-conditions-design.md.
#
# Домашний трафик не трогает: поднимает отдельный процесс sing-box на своём
# порту, со своей конфигурацией и своим журналом. Рабочий конфиг, nftables,
# dnsmasq и служба sing-box остаются как были.
#
# Вместо TProxy — SOCKS-вход, и это не подмена: клиент, ходящий через socks5
# (не socks5h), резолвит имя сам и отдаёт прокси адрес, ровно как это делает
# захваченное TProxy соединение. Дальше вопрос тот же самый — что видит
# маршрутизатор после снифинга.
#
# Два прогона отвечают на две половины вопроса:
#   A) правило по ip_cidr стоит перед доменным — совпадёт ли оно;
#   B) доменное стоит первым — совпадёт ли оно.
# Диапазон в A взят 0.0.0.0/0 нарочно: он совпадает с любым адресом и не
# совпадает ни с чем, если адреса в назначении уже нет. Это делает ответ
# независимым от того, какой именно IP выдал DNS клиенту и роутеру.
#
#   sh /tmp/probe-sniff.sh
#
# Если curl есть на роутере, скрипт всё делает сам. Если нет — печатает команду
# для компьютера и ждёт трафика окном в WAIT секунд, опрашивая журнал. Ждать
# нажатия Enter нельзя: скрипт часто запускают сразу после вставки в терминал, и
# `read` съедает остаток вставленного текста, не дав ничего сделать.

SING_BOX=${SING_BOX:-/usr/bin/sing-box}
PORT=${PORT:-17893}
DOMAIN=${DOMAIN:-example.com}
WAIT=${WAIT:-60}
CONF=/tmp/zarap-probe.json
LOG=/tmp/zarap-probe.log
PROBE_PID=""

cleanup() {
	[ -n "$PROBE_PID" ] && kill "$PROBE_PID" 2>/dev/null
	PROBE_PID=""
}
trap 'cleanup; exit 130' INT TERM

[ -x "$SING_BOX" ] || { echo "sing-box не найден в $SING_BOX"; exit 1; }

if command -v curl >/dev/null 2>&1; then
	LOCAL_CURL=1
	LISTEN=127.0.0.1
else
	LOCAL_CURL=0
	LISTEN=0.0.0.0
fi

ROUTER_IP=$(ubus call network.interface.lan status 2>/dev/null |
	sed -n 's/.*"address": "\([0-9.]*\)".*/\1/p' | head -n 1)
[ -n "$ROUTER_IP" ] || ROUTER_IP="<адрес роутера>"

# Только для справки: по какому адресу имя резолвится с роутера. На решение не
# влияет — правило в прогоне A совпадает с любым адресом.
RESOLVED=$(nslookup "$DOMAIN" 2>/dev/null |
	sed -n 's/^Address[[:space:]]*[0-9]*:[[:space:]]*\([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\).*/\1/p' |
	tail -n 1)
echo "$DOMAIN резолвится с роутера в ${RESOLVED:-—}"
echo

# write_config <первое-правило> <второе-правило>
write_config() {
	cat > "$CONF" <<CONFIG
{
  "log": { "level": "debug", "timestamp": true, "output": "$LOG" },
  "inbounds": [
    { "type": "mixed", "tag": "probe-in", "listen": "$LISTEN", "listen_port": $PORT }
  ],
  "outbounds": [
    { "type": "direct", "tag": "by_ip" },
    { "type": "direct", "tag": "by_domain" },
    { "type": "direct", "tag": "fallback" }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      { "inbound": ["probe-in"], "action": "sniff" },
      $1,
      $2
    ],
    "final": "fallback"
  }
}
CONFIG
}

BY_IP='{ "inbound": ["probe-in"], "ip_cidr": ["0.0.0.0/0"], "outbound": "by_ip" }'
BY_DOMAIN="{ \"inbound\": [\"probe-in\"], \"domain\": [\"$DOMAIN\"], \"domain_suffix\": [\".$DOMAIN\"], \"outbound\": \"by_domain\" }"

# run <название> <первое-правило> <второе-правило>
run() {
	echo "== $1 =="
	write_config "$2" "$3"
	if ! "$SING_BOX" check -c "$CONF" >/dev/null 2>&1; then
		echo "конфигурация пробы отклонена:"
		"$SING_BOX" check -c "$CONF" 2>&1 | head -n 2
		return 1
	fi

	rm -f "$LOG"
	"$SING_BOX" run -c "$CONF" >/dev/null 2>&1 &
	PROBE_PID=$!
	sleep 2
	if ! kill -0 "$PROBE_PID" 2>/dev/null; then
		echo "проба не поднялась, журнал:"
		tail -n 5 "$LOG" 2>/dev/null
		PROBE_PID=""
		return 1
	fi

	if [ "$LOCAL_CURL" = 1 ]; then
		curl -s -o /dev/null --max-time 20 --socks5 "127.0.0.1:$PORT" "https://$DOMAIN/"
	else
		echo "Выполните на компьютере в этой же сети:"
		echo
		echo "    curl -s -o /dev/null --socks5 $ROUTER_IP:$PORT https://$DOMAIN/"
		echo
		printf 'жду соединения до %s с' "$WAIT"
	fi
	# Опрос журнала вместо ожидания Enter: проба заканчивается сама, как только
	# соединение прошло, и не зависит от того, что осталось во вводе терминала.
	DEADLINE=$(( $(date +%s) + WAIT ))
	while [ "$(date +%s)" -lt "$DEADLINE" ]; do
		grep -q 'outbound connection to' "$LOG" 2>/dev/null && break
		[ "$LOCAL_CURL" = 1 ] && break
		printf '.'
		sleep 2
	done
	[ "$LOCAL_CURL" = 1 ] || echo
	sleep 1
	cleanup

	echo "--- что увидел маршрутизатор ---"
	grep -E 'sniff|outbound connection to' "$LOG" 2>/dev/null | tail -n 6
	VERDICT=$(grep -o 'outbound/direct\[[a-z_]*\]' "$LOG" 2>/dev/null | tail -n 1)
	if [ -n "$VERDICT" ]; then
		echo "выбранный outbound: $VERDICT"
	else
		# Пустой журнал почти всегда значит, что соединения не было вовсе, а не
		# что правило не совпало. Разница важная, поэтому она называется прямо.
		echo "соединение до пробы не дошло: журнал пуст"
		echo "проверьте, что команда curl выполнена, пока проба слушала,"
		echo "и что $ROUTER_IP:$PORT доступен с компьютера"
		[ -s "$LOG" ] && { echo "последние строки журнала:"; tail -n 3 "$LOG"; }
	fi
	echo
}

run "Прогон A: ip_cidr первым" "$BY_IP" "$BY_DOMAIN"
run "Прогон B: домен первым" "$BY_DOMAIN" "$BY_IP"

cat <<'VERDICT'
== Как читать ==

Прогон A выбрал by_ip     — адрес в назначении остался, правила по ip_cidr
                            работают после снифинга, порядок групп свободный.
Прогон A выбрал by_domain — снифинг подменил назначение именем, и правило по
или fallback                ip_cidr после снифинга не совпадает ни с чем:
                            группа с адресами обязана идти перед доменной
                            (раздел 5.1), а условия по адресам и по доменам в
                            одном правиле требуют отдельного разбора.

Прогон B выбрал by_domain — снифинг даёт имя, доменные правила работают.
Прогон B выбрал by_ip     — до доменного правила дело не дошло (в B оно
                            первое, так что это означало бы, что имя не
                            извлеклось): проверьте строку sniffed в журнале.

Строка `outbound connection to ...` показывает, что ушло наружу — имя или
адрес. Имя означает, что резолвить будет сервер, и это то, ради чего снифинг
нужен при заблокированном DNS.

Полный журнал пробы: /tmp/zarap-probe.log
Ничего не осталось запущенным; рабочий sing-box не трогался.
VERDICT
cleanup
