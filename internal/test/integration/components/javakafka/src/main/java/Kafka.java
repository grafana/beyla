import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;

import java.time.Duration;
import java.util.Collections;
import java.util.Properties;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class Kafka {

    public static void main(String[] args) {
        try {
            // Producer
            Properties producerProps = new Properties();
            producerProps.put("bootstrap.servers", "kafka:9092");
            producerProps.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
            producerProps.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
            producerProps.put("partitioner.class", "org.apache.kafka.clients.producer.RoundRobinPartitioner"); // Explicit partitioner

            Thread producerThread = new Thread(() -> {
                KafkaProducer<String, String> producer = new KafkaProducer<>(producerProps);
                for (;;) {
                    producer.send(new ProducerRecord<>("my-topic", "key", "value"));
                    System.out.println("Produced message");
                    try {
                        Thread.sleep(500);
                    } catch (Exception ignore) {}
                }
            });

            // Consumer
            Properties consumerProps = new Properties();
            consumerProps.put("bootstrap.servers", "kafka:9092");
            consumerProps.put("group.id", "1");
            consumerProps.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
            consumerProps.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
            consumerProps.put("auto.offset.reset", "earliest");

            Thread consumerThread = new Thread(() -> {
                KafkaConsumer<String, String> consumer = new KafkaConsumer<>(consumerProps);
                consumer.subscribe(Collections.singletonList("my-topic"));

                while (true) {
                    System.out.println("Polling for new messages...");
                    ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(1000));
                    for (ConsumerRecord<String, String> record : records) {
                        System.out.printf("Consumed message: offset = %d, key = %s, value = %s%n", record.offset(), record.key(), record.value());
                    }
                }
            });

            HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
            server.createContext("/message", new HttpHandler() {
                @Override
                public void handle(HttpExchange exchange) throws IOException {
                    String response = "OK";
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            });

            producerThread.start();
            consumerThread.start();
            server.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
