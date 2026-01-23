package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var (
	client mqtt.Client
	topic  string
	qos    byte
	mu     sync.Mutex
	count  int
)

func main() {
	broker := os.Getenv("MQTT_BROKER")
	if broker == "" {
		broker = "vernemq:1883"
	}

	topic = os.Getenv("MQTT_TOPIC")
	if topic == "" {
		topic = "test/topic"
	}

	qosStr := os.Getenv("MQTT_QOS")
	qos = byte(1) // Default to QOS 1 for guaranteed delivery
	if qosStr != "" {
		if q, err := strconv.Atoi(qosStr); err == nil && q >= 0 && q <= 2 {
			qos = byte(q)
		}
	}

	// Wait for broker to be ready
	log.Printf("Waiting for MQTT broker at %s...", broker)
	for {
		opts := mqtt.NewClientOptions().AddBroker("tcp://" + broker)
		opts.SetClientID("gomqtt_publisher")
		opts.SetConnectTimeout(5 * time.Second)
		opts.SetAutoReconnect(false)

		testClient := mqtt.NewClient(opts)
		if token := testClient.Connect(); token.Wait() && token.Error() == nil {
			log.Printf("Connected to MQTT broker at %s", broker)
			testClient.Disconnect(250)
			break
		}
		log.Printf("Failed to connect, retrying in 2 seconds...")
		time.Sleep(2 * time.Second)
	}

	// Set up client options
	opts := mqtt.NewClientOptions().AddBroker("tcp://" + broker)
	opts.SetClientID("gomqtt_publisher_" + strconv.FormatInt(time.Now().Unix(), 10))
	opts.SetCleanSession(true)
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetKeepAlive(60 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetAutoReconnect(true)

	// Set up message handler for publish confirmation
	opts.SetOnConnectHandler(func(c mqtt.Client) {
		log.Println("Connected to MQTT broker")
	})
	opts.SetConnectionLostHandler(func(c mqtt.Client, err error) {
		log.Printf("Connection lost: %v", err)
	})

	client = mqtt.NewClient(opts)

	// Connect to the broker
	log.Printf("Connecting to MQTT broker at %s...", broker)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Fatalf("Error connecting to broker: %v", token.Error())
	}
	defer func() {
		log.Println("Disconnecting from MQTT broker...")
		client.Disconnect(250)
	}()

	http.HandleFunc("/mqtt", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		messageNum := count
		mu.Unlock()

		// Ensure client is connected
		if !client.IsConnected() {
			log.Println("Client not connected, attempting to reconnect...")
			if token := client.Connect(); token.Wait() && token.Error() != nil {
				http.Error(w, "MQTT connection error: "+token.Error().Error(), http.StatusInternalServerError)
				return
			}
		}

		// Publish message with guaranteed delivery (QOS 1)
		payload := fmt.Sprintf("Hello from gomqtt! Message #%d, Timestamp: %s", messageNum, time.Now().Format(time.RFC3339))
		log.Printf("Publishing message #%d to topic '%s' with QOS %d: %s", messageNum, topic, qos, payload)

		token := client.Publish(topic, qos, false, payload)
		token.Wait()

		if token.Error() != nil {
			http.Error(w, "Publish error: "+token.Error().Error(), http.StatusInternalServerError)
			return
		}

		// Respond with the results
		result := map[string]interface{}{
			"message_number": messageNum,
			"topic":          topic,
			"qos":            qos,
			"payload":        payload,
			"published":      true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	fmt.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
