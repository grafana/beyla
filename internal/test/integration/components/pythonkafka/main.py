#!/usr/bin/env python
import threading, time

from kafka import KafkaAdminClient, KafkaConsumer, KafkaProducer
from kafka import errors as Errors
from kafka.admin import NewTopic
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class Producer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        while True:
            try:
                producer = KafkaProducer(bootstrap_servers='kafka:9092')

                while not self.stop_event.is_set():
                    producer.send('my-topic', b"test")
                    producer.send('my-topic', b"\xc2Hola, mundo!")
                    time.sleep(1)

                producer.close()
                break
            except Exception as e:
                print(f"Producer error occurred: {e}")
            time.sleep(1)


class Consumer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        while True:
            try:
                consumer = KafkaConsumer(bootstrap_servers='kafka:9092',
                                        auto_offset_reset='latest',
                                        group_id='1',
                                        consumer_timeout_ms=1000)
                consumer.subscribe(['my-topic'])

                while not self.stop_event.is_set():
                    for message in consumer:
                        print(message)
                        if self.stop_event.is_set():
                            break

                consumer.close()
                break
            except Exception as e:
                print(f"Consumer error occurred: {e}")
            time.sleep(1)

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/message':
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run_server(server_class=HTTPServer, handler_class=RequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting httpd server on port {port}')
    httpd.serve_forever()

def main():
    # Create 'my-topic' Kafka topic
    while True:
        try:
            admin = KafkaAdminClient(bootstrap_servers='kafka:9092')

            topic = NewTopic(name='my-topic',
                            num_partitions=1,
                            replication_factor=1)
            logger.info(f"Creating topic: {topic}")
            admin.create_topics([topic])
            break
        except Errors.TopicAlreadyExistsError:
            break
        except Exception as e:
            print(f"Admin error occurred: {e}")
        time.sleep(1)

    tasks = [
        Producer(),
        Consumer()
    ]

    # Start threads of a publisher/producer and a subscriber/consumer to 'my-topic' Kafka topic
    for t in tasks:
        t.start()

    run_server()


if __name__ == "__main__":
    main()