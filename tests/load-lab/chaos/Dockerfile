# Throwaway helper that shares the network namespace of ONE lab container (--network container:X)
# and applies tc/iptables rules there. It never touches the host network.
FROM alpine:3.20
RUN apk add --no-cache iproute2 iptables
ENTRYPOINT ["/bin/sh", "-c"]
