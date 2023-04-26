RATE=${1:-10000}
echo Running benchmark with request rate of ${RATE} QPS
wrk -R${RATE} -d60s -c200 -t200 --latency http://localhost:8080/ping