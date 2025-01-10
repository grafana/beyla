package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	kafka "github.com/segmentio/kafka-go"
)

func producerHandler(kafkaWriter *kafka.Writer) {
	msg := kafka.Message{
		Key:   []byte("address-hello"),
		Value: []byte("world"),
	}
	err := kafkaWriter.WriteMessages(context.Background(), msg)

	if err != nil {
		fmt.Printf("error %v\n", err)
	}
}

func getKafkaWriter(kafkaURL, topic string) *kafka.Writer {
	return &kafka.Writer{
		Addr:     kafka.TCP(kafkaURL),
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
	}
}

func getKafkaReader(kafkaURL, topic, groupID string) *kafka.Reader {
	brokers := strings.Split(kafkaURL, ",")
	return kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		GroupID:  groupID,
		Topic:    topic,
		MinBytes: 10e3, // 10KB
		MaxBytes: 10e6, // 10MB
	})
}

func main() {
	// get kafka writer using environment variables.
	kafkaURL := os.Getenv("kafkaURL")
	topic := os.Getenv("topic")

	kafkaWriter := getKafkaWriter(kafkaURL, topic)
	defer kafkaWriter.Close()

	groupID := os.Getenv("groupID")

	reader := getKafkaReader(kafkaURL, topic, groupID)
	defer reader.Close()

	go func() {
		fmt.Println("start consuming ... !!")
		for {
			m, err := reader.ReadMessage(context.Background())
			if err != nil {
				log.Fatalln(err)
			}
			fmt.Printf("message at topic:%v partition:%v offset:%v	%s = %s\n", m.Topic, m.Partition, m.Offset, string(m.Key), string(m.Value))
		}
	}()

	// Call the producer to keep the symbols
	producerHandler(kafkaWriter)
}
