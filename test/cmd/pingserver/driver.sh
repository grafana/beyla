RATE=${1:-10000}
echo Running benchmark with request rate of ${RATE} QPS
wrk -R${RATE} -d60s -c20 -t20 --latency http://localhost:8080/ping