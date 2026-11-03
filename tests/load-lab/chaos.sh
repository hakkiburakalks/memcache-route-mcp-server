#!/usr/bin/env bash
# Network chaos for ONE lab container at a time. Everything happens inside that container's own
# network namespace (tc/iptables via a throwaway helper) or by disconnecting it from the lab
# network; the host network is never changed. Usage:
#   ./chaos.sh latency   SERVICE MS        add MS milliseconds of delay (e.g. 10, 50, 100)
#   ./chaos.sh loss      SERVICE PERCENT   drop PERCENT % of packets (e.g. 1, 5)
#   ./chaos.sh slow      SERVICE           500 ms delay with jitter (a slow node)
#   ./chaos.sh reset     SERVICE           answer new TCP connections to the service with RST
#   ./chaos.sh partition SERVICE           disconnect from the lab network (unreachable node)
#   ./chaos.sh heal      SERVICE           undo all of the above
#   ./chaos.sh restart   SERVICE           restart the container (node or mcrouter restart)
# SERVICE is a compose service: mc1 mc2 mc3 mcrouter mcp
set -euo pipefail
cd "$(dirname "$0")"
action="${1:?action}"; svc="${2:?service}"; arg="${3:-}"
cid=$(docker compose ps -q "$svc")
[ -n "$cid" ] || { echo "no running container for service $svc" >&2; exit 1; }
net=memcached-mcp-lab
img=memcached-mcp-lab-chaos
docker image inspect $img >/dev/null 2>&1 || docker build -q -t $img chaos >/dev/null
helper() { docker run --rm --cap-add NET_ADMIN --network "container:$cid" $img "$1"; }
case "$action" in
  latency)   helper "tc qdisc replace dev eth0 root netem delay ${arg:?ms}ms" ;;
  loss)      helper "tc qdisc replace dev eth0 root netem loss ${arg:?percent}%" ;;
  slow)      helper "tc qdisc replace dev eth0 root netem delay 500ms 100ms" ;;
  reset)     helper "iptables -I INPUT -p tcp --syn -j REJECT --reject-with tcp-reset" ;;
  partition) docker network disconnect $net "$cid" ;;
  heal)      docker network connect $net "$cid" --alias "$svc" 2>/dev/null || true
             helper "tc qdisc del dev eth0 root 2>/dev/null; iptables -F INPUT; true" ;;
  restart)   docker restart "$cid" >/dev/null ;;
  *) echo "unknown action $action" >&2; exit 2 ;;
esac
echo "chaos $action $svc ${arg} done"
