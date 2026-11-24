#!/bin/sh
# Публикация Ingress-контроллера minikube на сетевом интерфейсе ВМ3 (порты 80, 443).
# Правило DNAT в iptables сохраняет IP-адрес клиента (ВМ1, ВМ2), поэтому лимит
# частоты шлюза «на IP» различает клиентов. kubectl port-forward так не умеет:
# через него все клиенты видны паттерну с одного адреса 127.0.0.1.
#   aig-ingress-dnat.sh            добавить правила (повторный запуск безопасен)
#   aig-ingress-dnat.sh --delete   удалить правила
set -eu
IFACE="${AIG_IFACE:-enp0s8}"
ACTION="${1:-}"
IP=""
NET='{{with index .NetworkSettings.Networks "minikube"}}{{.IPAddress}}{{end}}'
for _ in $(seq 1 60); do  # minikube может стартовать позже службы: ждём до 5 минут
    IP=$(docker inspect -f "$NET" minikube 2>/dev/null || true)
    [ -n "$IP" ] && break
    [ "$ACTION" = "--delete" ] && exit 0
    sleep 5
done
[ -n "$IP" ] || { echo "minikube не запущен" >&2; exit 1; }
sysctl -q -w net.ipv4.ip_forward=1
for PORT in 80 443; do
    NAT="PREROUTING -i $IFACE -p tcp --dport $PORT -j DNAT --to-destination $IP:$PORT"
    FWD="DOCKER-USER -i $IFACE -d $IP -p tcp --dport $PORT -j ACCEPT"
    if [ "$ACTION" = "--delete" ]; then
        iptables -t nat -D $NAT 2>/dev/null || true
        iptables -D $FWD 2>/dev/null || true
    else
        iptables -t nat -C $NAT 2>/dev/null || iptables -t nat -A $NAT
        iptables -C $FWD 2>/dev/null || iptables -I $FWD
    fi
done
echo "Ingress: $IFACE:80,443 -> $IP (${ACTION:-add})"
