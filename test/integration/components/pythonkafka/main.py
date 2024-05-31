import logging
from confluent_kafka import Producer, Consumer, KafkaException
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

topic = 'example_topic'

def delivery_report(err, msg):
    if err is not None:
        logger.error(f"Message delivery failed: {err}")
    else:
        logger.info(f"Message delivered to {msg.topic()} [{msg.partition()}]")

def produce_messages():
    # Kafka producer configuration
    producer_config = {
        'bootstrap.servers': 'localhost:9093'  # Kafka broker address
    }
    logger.info("Creating Kafka producer")
    producer = Producer(producer_config)

    # Produce messages
    for i in range(10):
        message = {'id': i, 'value': f'Test message {i}'}
        producer.produce(topic, key=str(i), value=json.dumps(message), callback=delivery_report)
        producer.poll(0)

    # Wait for any outstanding messages to be delivered and delivery reports to be received
    producer.flush()

# Configuration for the Kafka consumer
consumer_config = {
    'bootstrap.servers': 'localhost:9093',
    'group.id': 'example_group',
    'auto.offset.reset': 'earliest'
}

class KafkaConsumerService:
    def __init__(self):
        logger.info("Creating Kafka consumer")
        self.consumer = Consumer(consumer_config)
        self.consumer.subscribe([topic])
    
    def fetch_message(self):
        try:
            msg = self.consumer.poll(timeout=1.0)
            if msg is None:
                return {'error': 'No message received'}
            if msg.error():
                if msg.error().code() == KafkaException._PARTITION_EOF:
                    logger.info(f"Reached end of partition: {msg.topic()} [{msg.partition()}]")
                    return {'error': 'Reached end of partition'}
                else:
                    raise KafkaException(msg.error())
            else:
                message = json.loads(msg.value().decode('utf-8'))
                return message
        except Exception as e:
            logger.error(f"Error consuming message: {e}")
            return {'error': str(e)}

# Create an instance of the Kafka consumer service
kafka_service = KafkaConsumerService()

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/message':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            message = kafka_service.fetch_message()
            logger.info(f"Sending message: {message}")
            self.wfile.write(json.dumps(message).encode('utf-8'))
        elif self.path == '/produce': 
            produce_messages()
            message = kafka_service.fetch_message()
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run_server(server_class=HTTPServer, handler_class=RequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logger.info(f'Starting httpd server on port {port}')
    httpd.serve_forever()


if __name__ == '__main__':
    run_server()