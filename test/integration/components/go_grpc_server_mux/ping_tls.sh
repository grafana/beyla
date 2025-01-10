while true; do
    echo grpcurl -insecure $TARGET_URL grpc.health.v1.Health/Check
    grpcurl -insecure $TARGET_URL grpc.health.v1.Health/Check
    sleep 1
done