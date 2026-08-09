#!/bin/sh
# Проверка «переживает ли ip_cidr снифинг» — пункт 1 из раздела 15.2
# docs/rule-conditions-design.md.
#
# Всё происходит на роутере: ни второго компьютера, ни curl, ни установки
# пакетов. Домашний трафик не задет — поднимается отдельный процесс sing-box на
# 127.0.0.1 со своей конфигурацией и своим журналом, а служба, рабочий конфиг,
# nftables и dnsmasq остаются как были.
#
# Как воспроизводится ситуация TProxy. Вход пробы — inbound типа direct с
# override_address: любое соединение на его порт уходит на <адрес>:443, то есть
# назначение задано адресом, а не именем, ровно как у захваченного клиента.
# Клиентом работает nc, которому скармливается собранный здесь же TLS
# ClientHello с нужным SNI: сниффер читает первый пакет и дальше рукопожатие
# ему не нужно, а маршрут выбирается сразу — этого и достаточно.
#
# Два прогона отвечают на две половины вопроса:
#   A) правило по ip_cidr стоит перед доменным — совпадёт ли оно;
#   B) доменное стоит первым — совпадёт ли оно.
# Диапазон в A взят 0.0.0.0/0 нарочно: он совпадает с любым адресом и не
# совпадает ни с чем, если адреса в назначении уже нет.
#
#   sh /tmp/probe-sniff.sh

SING_BOX=${SING_BOX:-/usr/bin/sing-box}
PORT=${PORT:-17893}
DOMAIN=${DOMAIN:-example.com}
CONF=/tmp/zarap-probe.json
LOG=/tmp/zarap-probe.log
PROBE_PID=""

cleanup() {
	[ -n "$PROBE_PID" ] && kill "$PROBE_PID" 2>/dev/null
	PROBE_PID=""
}
trap 'cleanup; exit 130' INT TERM

[ -x "$SING_BOX" ] || { echo "sing-box не найден в $SING_BOX"; exit 1; }

HELLO=/tmp/zarap-hello.bin
NC_ERR=/tmp/zarap-nc.err

# Байты в поток. Восьмеричная форма, а не \xNN: %b с шестнадцатеричными
# escape-последовательностями за пределами POSIX, и busybox их может не знать.
emit() {
	out=''
	for value in "$@"; do
		out="$out\\0$(printf '%03o' "$value")"
	done
	printf '%b' "$out"
}

# Минимальный TLS 1.2 ClientHello с одним расширением — server_name. Всё, что
# сниффер читает, здесь есть; random из нулей и один шифронабор его устраивают,
# потому что рукопожатие он не ведёт.
client_hello() {
	host=$1
	length=${#host}
	record=$((56 + length))
	handshake=$((52 + length))
	extensions=$((9 + length))
	sni_extension=$((5 + length))
	sni_list=$((3 + length))

	emit 22 3 1 $((record / 256)) $((record % 256))
	emit 1 0 $((handshake / 256)) $((handshake % 256))
	emit 3 3
	index=0
	while [ "$index" -lt 32 ]; do
		emit 0
		index=$((index + 1))
	done
	emit 0
	emit 0 2 0 47
	emit 1 0
	emit $((extensions / 256)) $((extensions % 256))
	emit 0 0
	emit $((sni_extension / 256)) $((sni_extension % 256))
	emit $((sni_list / 256)) $((sni_list % 256))
	emit 0
	emit $((length / 256)) $((length % 256))
	printf '%s' "$host"
}

# busybox печатает адрес и как «Address 1: 1.2.3.4», и как «Address: 1.2.3.4»,
# а строку самого резолвера — как «Address: 127.0.0.1:53». Отсюда `$` в конце:
# он отсекает порт, то есть отличает адрес имени от адреса сервера, не полагаясь
# на номер, которого может и не быть.
LOOKUP=$(nslookup "$DOMAIN" 2>/dev/null |
	sed -n 's/^Address[^:]*:[[:space:]]*\([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\)[[:space:]]*$/\1/p' |
	head -n 1)
# Какой именно адрес — неважно: правило в прогоне A совпадает с любым. Важно
# только, что назначение задано адресом, поэтому неудача резолва не повод
# останавливаться.
TARGET=${TARGET:-${LOOKUP:-93.184.216.34}}
if [ -n "$LOOKUP" ]; then
	echo "$DOMAIN → $TARGET (назначение задаётся адресом, как при захвате TProxy)"
else
	echo "адрес $DOMAIN узнать не удалось, берём $TARGET — для проверки годится любой"
fi

# Проверка самого генератора: длина известна заранее, и расхождение означает,
# что printf в этой оболочке не понимает восьмеричные escape-последовательности,
# а не что маршрутизатор чего-то не увидел.
client_hello "$DOMAIN" > "$HELLO"
BUILT=$(wc -c < "$HELLO")
WANTED=$((61 + ${#DOMAIN}))
echo "ClientHello: $BUILT байт (ожидалось $WANTED)"
if [ "$BUILT" != "$WANTED" ]; then
	echo "генератор собрал не то — проверять маршрутизацию этим нельзя"
	exit 1
fi
echo

# write_config <первое-правило> <второе-правило> [<добавка-к-входу>]
write_config() {
	cat > "$CONF" <<CONFIG
{
  "log": { "level": "debug", "timestamp": true, "output": "$LOG" },
  "inbounds": [
    {
      "type": "direct", "tag": "probe-in",
      "listen": "127.0.0.1", "listen_port": $PORT,
      "override_address": "$TARGET", "override_port": 443$3
    }
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

# Отправить собранный ClientHello и подержать соединение открытым: клиент,
# закрывший его сразу, оставил бы маршрутизатору меньше времени, чем тот тратит
# на разбор первого пакета.
send_hello() {
	: > "$NC_ERR"
	{ cat "$HELLO"; sleep 2; } | nc "$@" 127.0.0.1 "$PORT" >/dev/null 2>"$NC_ERR"
}

# run <название> <первое-правило> <второе-правило> [<добавка-к-входу>]
run() {
	echo "== $1 =="
	write_config "$2" "$3" "$4"
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

	# Слушает ли проба на самом деле — иначе ответ «соединения не было» ничего
	# не объясняет.
	ss -lnt 2>/dev/null | grep -q ":$PORT" || echo "внимание: порт $PORT не слушается"

	# Соединение держится ещё пару секунд после отправки: клиент, закрывший его
	# сразу, оставил бы маршрутизатору меньше времени, чем тот тратит на разбор.
	if command -v nc >/dev/null 2>&1; then
		send_hello -w 5
		CODE=$?
		# busybox собирают по-разному, и nc без -w — не редкость. Такой nc
		# печатает usage и уходит, а с подавленным stderr это выглядело бы как
		# «соединения не было», то есть как ответ про маршрутизацию.
		if [ -s "$NC_ERR" ]; then
			echo "nc не принял -w: $(head -n 1 "$NC_ERR")"
			send_hello
			CODE=$?
		fi
		echo "клиент nc: код $CODE"
		[ -s "$NC_ERR" ] && { echo "nc сказал:"; head -n 2 "$NC_ERR"; }
	fi
	# Запасной клиент. Нужен ровно тогда, когда nc отсутствует или молча не
	# соединяется, а sing-box на роутере есть по определению.
	if ! grep -q 'inbound connection' "$LOG" 2>/dev/null; then
		if "$SING_BOX" tools connect --help >/dev/null 2>&1; then
			echo "nc не дошёл, пробуем sing-box tools connect"
			{ cat "$HELLO"; sleep 2; } | "$SING_BOX" tools connect "127.0.0.1:$PORT" >/dev/null 2>&1
		fi
	fi
	sleep 2
	cleanup

	echo "--- что увидел маршрутизатор ---"
	grep -E 'sniff|outbound connection to' "$LOG" 2>/dev/null | tail -n 6
	VERDICT=$(grep -o 'outbound/direct\[[a-z_]*\]' "$LOG" 2>/dev/null | tail -n 1)
	if [ -n "$VERDICT" ]; then
		echo "выбранный outbound: $VERDICT"
		# Что именно уехало наружу — имя или адрес. От этого зависит, спасает ли
		# доменное правило при подменённом DNS (раздел 6).
		DIALED=$(grep -o 'outbound connection to [^ ]*' "$LOG" 2>/dev/null |
			tail -n 1 | sed 's/.*to //')
		case "$DIALED" in
			[0-9]*.[0-9]*.[0-9]*.[0-9]*:*) echo "наружу ушёл адрес: $DIALED" ;;
			'') ;;
			*) echo "наружу ушло ИМЯ: $DIALED" ;;
		esac
	elif grep -q 'inbound connection' "$LOG" 2>/dev/null; then
		# Соединение дошло, но маршрут не выбран — это уже разговор про
		# маршрутизатор, а не про клиента.
		echo "соединение принято, но outbound в журнале не назван:"
		tail -n 6 "$LOG"
	else
		echo "соединение до пробы не дошло: клиент не смог подключиться"
		[ -s "$LOG" ] && { echo "последние строки журнала:"; tail -n 3 "$LOG"; }
	fi
	echo
}

run "Прогон A: ip_cidr первым" "$BY_IP" "$BY_DOMAIN"
run "Прогон B: домен первым" "$BY_DOMAIN" "$BY_IP"
# Прогон C ставит единственный вопрос, оставшийся после A и B: можно ли
# заставить outbound звонить по имени вместо адреса. Поле объявлено устаревшим,
# поэтому «конфигурация отклонена» здесь — тоже ответ, а не поломка пробы.
run "Прогон C: попытка отправить наружу имя" "$BY_DOMAIN" "$BY_IP" \
	',
      "sniff_override_destination": true'

cat <<'VERDICT'
== Как читать ==

Сначала строка про снифинг. Если в журнале нет ни одного упоминания sniff с
именем домена, значит собранный здесь ClientHello сниффер не разобрал, и
выводы про ip_cidr делать нельзя — прогоны надо повторить настоящим клиентом
(вариант с curl с другого компьютера описан в разделе 15.2).

Прогон A выбрал by_ip     — адрес в назначении остался, правила по ip_cidr
                            работают после снифинга, порядок групп свободный.
Прогон A выбрал by_domain — снифинг подменил назначение именем, и правило по
или fallback                ip_cidr после снифинга не совпадает ни с чем:
                            группа с адресами обязана идти перед доменной
                            (раздел 5.1).

Прогон B выбрал by_domain — снифинг даёт имя, доменные правила работают.
Прогон B выбрал by_ip     — до доменного правила дело не дошло, хотя оно
                            первое: имя не извлеклось, см. абзац выше.

Прогон C отвечает на отдельный вопрос: строка «наружу ушло ИМЯ» означает, что
резолвить будет сервер и доменное правило спасает при подменённом DNS. «Наружу
ушёл адрес» — что не спасает, и лечится это только маршрутизацией DNS (этап 4).
«Конфигурация пробы отклонена» — тоже ответ: поля больше нет.

Полный журнал пробы: /tmp/zarap-probe.log
Ничего не осталось запущенным; рабочий sing-box не трогался.
VERDICT
cleanup
