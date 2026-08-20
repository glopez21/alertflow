"""Kafka consumer for real-time alert ingestion.

Consumes alert events from a Kafka topic (default ``logsentry-to-alertflow``)
and persists them into the AlertFlow ``AlertStore``.  Built on ``aiokafka``
for non-blocking integration with the ASGI event loop.

Key design decisions
~~~~~~~~~~~~~~~~~~~~
* **Deduplication before insert.**  Every incoming message is checked against
  existing alerts by ``(title, source, ioc)`` triplet to avoid flooding the
  store with duplicate alerts from overlapping detection rules.
* **Sync store calls offloaded to threads.**  ``AlertStore`` methods are
  synchronous (typically backed by SQLite / SQLAlchemy), so they are wrapped
  in ``asyncio.to_thread`` to prevent blocking the event loop.
* **Consumer group coordination.**  Uses a shared ``group_id`` so that
  multiple AlertFlow replicas can partition the topic and scale horizontally
  without duplicating work.
* **Graceful shutdown.**  ``stop()`` sets a flag that the consume-loop checks
  after every message, allowing in-flight processing to finish before the
  consumer leaves the group cleanly.
"""

import asyncio
import json
import os

from logging_config import get_logger

logger = get_logger("alertflow.kafka")

# Defaults read from environment so Docker/K8s deployments can reconfigure
# without code changes.
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "kafka:9092")
ALERT_TOPIC = os.environ.get("ALERTFLOW_KAFKA_TOPIC", "logsentry-to-alertflow")
GROUP_ID = os.environ.get("ALERTFLOW_KAFKA_GROUP", "alertflow-consumers")


class AlertKafkaConsumer:
    """Consumes alerts from Kafka topic and ingests into AlertStore.

    The consumer is single-threaded and designed to run inside an existing
    asyncio event loop (e.g. alongside the FastAPI/Starlette ASGI server).

    Attributes:
        store: An ``AlertStore`` instance used for persistence and
            deduplication lookups.
        broker: Kafka bootstrap server address.
        topic: Kafka topic to subscribe to.
        group_id: Consumer group ID for partition coordination.
    """

    def __init__(self, store, broker: str = "", topic: str = "", group_id: str = ""):
        self.store = store
        self.broker = broker or KAFKA_BROKER
        self.topic = topic or ALERT_TOPIC
        self.group_id = group_id or GROUP_ID
        self._consumer = None
        # Flag checked in the consume loop to allow graceful shutdown.
        self._running = False

    async def start(self):
        """Start consuming messages.

        Creates an ``AIOKafkaConsumer``, subscribes to the configured topic,
        and enters the consume loop.  The loop exits when ``stop()`` is called
        or the consumer is stopped externally.

        ``auto_offset_reset='latest'`` ensures that on first startup we only
        process new alerts — we do not replay historical messages that may
        already exist in the store.
        """
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
            # Offsets are committed automatically so that a crash does not
            # re-deliver already-processed messages.
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
            # Always release the consumer connection regardless of how we exit.
            await self._consumer.stop()

    async def _handle_message(self, data: dict):
        """Process a single Kafka message.

        The handler normalises a few possible field names (``title`` vs
        ``rule_name``, ``ioc`` vs ``src_ip``) so that upstream producers
        with different schemas are handled transparently.

        Args:
            data: Deserialised JSON payload from Kafka.
        """
        try:
            # Normalise field names — different producers may use different keys.
            title = data.get("title", data.get("rule_name", "Kafka Alert"))
            severity = data.get("severity", "P3")
            source = data.get("source", "kafka")
            ioc = data.get("ioc", data.get("src_ip", ""))

            # Deduplicate: if an alert with the same (title, source, ioc)
            # already exists, skip ingestion to avoid noise.
            dup = await asyncio.to_thread(self.store.find_duplicate, title, source, ioc)
            if dup:
                logger.info("alert.deduplicated", alert_id=dup["id"], title=title)
                return

            # Insert the new alert record via a thread to avoid blocking the
            # event loop (AlertStore uses synchronous DB calls).
            alert = await asyncio.to_thread(self.store.add_alert, title, severity, source, ioc=ioc)

            enrichment = data.get("enrichment", {})
            if enrichment:
                await asyncio.to_thread(self.store.update_enrichment, alert["id"], enrichment)

            logger.info("alert.ingested", alert_id=alert["id"], title=title, source=source)
        except Exception as e:
            # Log and swallow — a single bad message must not crash the consumer.
            logger.error("kafka.message.error", error=str(e), data=str(data)[:200])

    async def stop(self):
        """Request a graceful shutdown of the consumer loop.

        Sets the ``_running`` flag to ``False`` so the next iteration of the
        consume loop exits, then stops the underlying Kafka consumer to leave
        the consumer group cleanly.
        """
        self._running = False
        if self._consumer:
            await self._consumer.stop()


async def run_kafka_consumer(store):
    """Entry point to run the Kafka consumer.

    Typically called as a background task during application startup so that
    alert ingestion begins alongside the HTTP server.

    Args:
        store: The ``AlertStore`` instance to persist ingested alerts into.
    """
    consumer = AlertKafkaConsumer(store)
    await consumer.start()
