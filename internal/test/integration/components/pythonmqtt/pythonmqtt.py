import os
import time
import logging
from datetime import datetime
from threading import Lock
from fastapi import FastAPI, HTTPException, Query
from typing import Optional
import uvicorn
import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

app = FastAPI()

# Global variables
client = None
topic = "test/topic"
qos = 1
mu = Lock()
count = 0

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

def wait_for_broker(broker_host, broker_port):
    """Wait for MQTT broker to be ready"""
    logger.info(f"Waiting for MQTT broker at {broker_host}:{broker_port}...")
    while True:
        try:
            test_client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id="pythonmqtt_publisher_test")
            test_client.connect(broker_host, broker_port, 5)
            test_client.disconnect()
            logger.info(f"Connected to MQTT broker at {broker_host}:{broker_port}")
            break
        except Exception as e:
            logger.info(f"Failed to connect, retrying in 2 seconds... Error: {e}")
            time.sleep(2)

def on_connect(client, userdata, flags, reason_code, properties):
    """Callback for when the client receives a CONNACK response from the server"""
    if reason_code.is_failure:
        logger.error(f"Failed to connect, reason code: {reason_code}")
    else:
        logger.info("Connected to MQTT broker")

def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    """Callback for when the client disconnects from the server"""
    if reason_code.is_failure:
        logger.warning(f"Unexpected disconnection: {reason_code}")

def setup_mqtt_client(broker_host, broker_port):
    """Set up and connect MQTT client"""
    global client

    client_id = f"pythonmqtt_publisher_{int(time.time())}"
    client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=client_id, clean_session=True)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

    client.connect(broker_host, broker_port, 60)
    client.loop_start()

    # Wait a bit for connection to establish
    time.sleep(1)

    return client

# Example curl command:
# curl http://localhost:8080/mqtt
@app.get("/mqtt")
async def mqtt_publish():
    """Handle HTTP request to publish MQTT message"""
    global count, client

    mu.acquire()
    count += 1
    message_num = count
    mu.release()

    # Ensure client is connected
    if client is None or not client.is_connected():
        logger.warning("Client not connected, attempting to reconnect...")
        broker = os.getenv("MQTT_BROKER", "vernemq:1883")
        broker_host, broker_port = broker.split(":") if ":" in broker else (broker, 1883)
        broker_port = int(broker_port)
        try:
            client = setup_mqtt_client(broker_host, broker_port)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"MQTT connection error: {str(e)}")

    # Publish message
    payload = f"Hello from pythonmqtt! Message #{message_num}, Timestamp: {datetime.now().isoformat()}"
    logger.info(f"Publishing message #{message_num} to topic '{topic}' with QOS {qos}: {payload}")

    try:
        result = client.publish(topic, payload, qos)
        result.wait_for_publish(timeout=5)

        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise HTTPException(status_code=500, detail=f"Publish error: {result.rc}")

        # Respond with the results
        response = {
            "message_number": message_num,
            "topic": topic,
            "qos": qos,
            "payload": payload,
            "published": True,
        }
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Publish error: {str(e)}")

# Example curl command:
# curl http://localhost:8080/mqtt/connect
@app.get("/mqtt/connect")
async def mqtt_connect():
    """Connect to MQTT broker (or reconnect if already connected)"""
    global client

    broker = os.getenv("MQTT_BROKER", "vernemq:1883")
    broker_host, broker_port = broker.split(":") if ":" in broker else (broker, 1883)
    broker_port = int(broker_port)

    # Disconnect existing client if connected
    if client is not None:
        if client.is_connected():
            logger.info("Disconnecting existing client...")
            client.disconnect()
            client.loop_stop()
        client = None

    try:
        # Create new client and connect
        client_id = f"pythonmqtt_publisher_{int(time.time())}"
        client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=client_id, clean_session=True)

        client.on_connect = on_connect
        client.on_disconnect = on_disconnect

        logger.info(f"Connecting to MQTT broker at {broker_host}:{broker_port}...")
        client.connect(broker_host, broker_port, 60)
        client.loop_start()

        # Wait a bit for connection to establish
        time.sleep(1)

        if client.is_connected():
            response = {
                "connected": True,
                "client_id": client_id,
                "broker": f"{broker_host}:{broker_port}",
            }
            return response
        else:
            raise HTTPException(status_code=500, detail="Failed to connect to MQTT broker")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection error: {str(e)}")

# Example curl command:
# curl http://localhost:8080/mqtt/disconnect
@app.get("/mqtt/disconnect")
async def mqtt_disconnect():
    """Disconnect from MQTT broker"""
    global client

    if client is None:
        return {
            "disconnected": False,
            "message": "No client to disconnect",
        }

    try:
        if client.is_connected():
            logger.info("Disconnecting from MQTT broker...")
            client.disconnect()
            client.loop_stop()
            response = {
                "disconnected": True,
                "message": "Successfully disconnected",
            }
        else:
            client.loop_stop()
            response = {
                "disconnected": True,
                "message": "Client was not connected",
            }

        client = None
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Disconnect error: {str(e)}")

# Example curl commands:
# curl http://localhost:8080/mqtt/subscribe
# curl "http://localhost:8080/mqtt/subscribe?topics=test/topic"
# curl "http://localhost:8080/mqtt/subscribe?topics=test/topic1,test/topic2&qos_level=2"
@app.get("/mqtt/subscribe")
async def mqtt_subscribe(
    topics: Optional[str] = Query(None, description="Comma-separated list of topics to subscribe to"),
    qos_level: Optional[int] = Query(None, description="QoS level (0, 1, or 2)"),
):
    """Subscribe to MQTT topic(s)"""
    global client

    # Use default topic if not provided
    if topics is None:
        topics_to_subscribe = [topic]
    else:
        topics_to_subscribe = [t.strip() for t in topics.split(",") if t.strip()]

    if not topics_to_subscribe:
        raise HTTPException(status_code=400, detail="At least one topic must be provided")

    # Use default QoS if not provided
    subscribe_qos = qos_level if qos_level is not None else qos
    if subscribe_qos < 0 or subscribe_qos > 2:
        raise HTTPException(status_code=400, detail="QoS must be 0, 1, or 2")

    # Ensure client is connected
    if client is None or not client.is_connected():
        logger.warning("Client not connected, attempting to reconnect...")
        broker = os.getenv("MQTT_BROKER", "vernemq:1883")
        broker_host, broker_port = broker.split(":") if ":" in broker else (broker, 1883)
        broker_port = int(broker_port)
        try:
            client = setup_mqtt_client(broker_host, broker_port)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"MQTT connection error: {str(e)}")

    # Subscribe to topics
    subscriptions = []
    for topic_filter in topics_to_subscribe:
        logger.info(f"Subscribing to topic '{topic_filter}' with QoS {subscribe_qos}")
        try:
            result, mid = client.subscribe(topic_filter, subscribe_qos)
            if result != mqtt.MQTT_ERR_SUCCESS:
                raise HTTPException(
                    status_code=500,
                    detail=f"Subscribe error for topic '{topic_filter}': {result}",
                )
            subscriptions.append(
                {
                    "topic": topic_filter,
                    "qos": subscribe_qos,
                    "message_id": mid,
                }
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Subscribe error for topic '{topic_filter}': {str(e)}",
            )

    # Wait a bit for subscription to complete
    time.sleep(0.5)

    response = {
        "subscribed": True,
        "subscriptions": subscriptions,
    }
    return response

if __name__ == "__main__":
    # Get configuration from environment
    broker = os.getenv("MQTT_BROKER", "vernemq:1883")
    broker_host, broker_port = broker.split(":") if ":" in broker else (broker, 1883)
    broker_port = int(broker_port)

    topic = os.getenv("MQTT_TOPIC", "test/topic")

    qos_str = os.getenv("MQTT_QOS", "1")
    try:
        qos = int(qos_str)
        if qos < 0 or qos > 2:
            qos = 1
    except ValueError:
        qos = 1

    # Wait for broker to be ready
    wait_for_broker(broker_host, broker_port)

    # Set up MQTT client
    setup_mqtt_client(broker_host, broker_port)

    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
