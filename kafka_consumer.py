"""Kafka consumer for real-time alert ingestion."""

import asyncio
import json
import os

from logging_config import get_logger

logger = get_logger("alertflow.kafka")

KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "kafka:9092")
ALERT_TOPIC = os.environ.get("ALERTFLOW_KAFKA_TOPIC", "logsentry-to-alertflow")
GROUP_ID = os.environ.get("ALERTFLOW_KAFKA_GROUP", "alertflow-consumers")


class AlertKafkaConsumer:
    """Consumes alerts from Kafka topic and ingests into AlertStore."""

    def __init__(self, store, broker: str = "", topic: str = "", group_id: str = ""):
        self.store = store
        self.broker = broker or KAFKA_BROKER
        self.topic = topic or ALERT_TOPIC
        self.group_id = group_id or GROUP_ID
        self._consumer = None
        self._running = False

    async def start(self):
        """Start consuming messages."""
        try:
            from aiokafka import AIOKafkaConsumer
        except ImportError:
            logger.error("aiokafka not installed: pip install aiokafka")
            return

        self._consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.broker,
            group_id=self.group_id,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )

        await self._consumer.start()
        self._running = True
        logger.info("kafka.consumer.started", broker=self.broker, topic=self.topic, group=self.group_id)

        try:
            async for msg in self._consumer:
                if not self._running:
                    break
                await self._handle_message(msg.value)
        except Exception as e:
            logger.error("kafka.consumer.error", error=str(e))
        finally:
            await self._consumer.stop()

    async def _handle_message(self, data: dict):
        """Process a single Kafka message."""
        try:
            title = data.get("title", data.get("rule_name", "Kafka Alert"))
            severity = data.get("severity", "P3")
            source = data.get("source", "kafka")
            ioc = data.get("ioc", data.get("src_ip", ""))

            dup = await asyncio.to_thread(self.store.find_duplicate, title, source, ioc)
            if dup:
                logger.info("alert.deduplicated", alert_id=dup["id"], title=title)
                return

            alert = await asyncio.to_thread(self.store.add_alert, title, severity, source, ioc=ioc)

            enrichment = data.get("enrichment", {})
            if enrichment:
                await asyncio.to_thread(self.store.update_enrichment, alert["id"], enrichment)

            logger.info("alert.ingested", alert_id=alert["id"], title=title, source=source)
        except Exception as e:
            logger.error("kafka.message.error", error=str(e), data=str(data)[:200])

    async def stop(self):
        """Stop consuming."""
        self._running = False
        if self._consumer:
            await self._consumer.stop()


async def run_kafka_consumer(store):
    """Entry point to run the Kafka consumer."""
    consumer = AlertKafkaConsumer(store)
    await consumer.start()
