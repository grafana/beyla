while true; do
    echo grpcurl -plaintext $TARGET_URL grpc.health.v1.Health/Check
    grpcurl -plaintext $TARGET_URL grpc.health.v1.Health/Check
    sleep 1
done
