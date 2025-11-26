#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MQTT → BLE мост для JDY-33.
Поддерживает два режима:
  - ON_DEMAND  — подключаемся к реле по требованию и отключаемся через IDLE_DISCONNECT_SEC.
  - PERSISTENT — держим соединение и следим за ним health-чеком PERSISTENT_HEALTH_SEC.
"""

import os
import time
import binascii
import json
import asyncio
import signal
import atexit
from typing import Optional

from threading import Thread, Lock
import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion, MQTTv311


# ---------- helpers ----------

def env_or(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if (v is not None and v != "") else default


# ---------- config from env ----------

MQTT_HOST = env_or("MQTT_HOST", "core-mosquitto")
MQTT_PORT = int(env_or("MQTT_PORT", "1883"))
MQTT_USER = env_or("MQTT_USER", "")
MQTT_PASS = env_or("MQTT_PASS", "")
MQTT_PREFIX = env_or("MQTT_PREFIX", "bluetoothrelay")

RELAY_NAME = env_or("RELAY_NAME", "Bluetooth JDY-33 Relay")
RELAY_ID = env_or("RELAY_ID", "jdy33_relay")

BLE_ADDR = env_or("BLE_ADDR", "").strip()
BLE_NAME = env_or("BLE_NAME", "").strip()
BLE_WRITE_CHAR = env_or("BLE_WRITE_CHAR", "0000ffe1-0000-1000-8000-00805f9b34fb")

CONNECTION_MODE_RAW = env_or("CONNECTION_MODE", "ON_DEMAND").strip()
LM = CONNECTION_MODE_RAW.lower()
if LM in ("persistent", "true", "1", "yes", "on"):
  CONNECTION_MODE = "PERSISTENT"
else:
  CONNECTION_MODE = "ON_DEMAND"

IDLE_DISCONNECT_SEC = int(env_or("IDLE_DISCONNECT_SEC", "5"))
PERSISTENT_HEALTH_SEC = int(env_or("PERSISTENT_HEALTH_SEC", "30"))

CMD_ON_HEX = env_or("CMD_ON_HEX", "A00101A2").replace(" ", "")
CMD_OFF_HEX = env_or("CMD_OFF_HEX", "A00100A1").replace(" ", "")

CONNECT_RETRY_SEC = 5


def hex_to_bytes(s: str) -> bytes:
    s = s.replace(" ", "")
    return binascii.unhexlify(s)


CMD_ON = hex_to_bytes(CMD_ON_HEX)
CMD_OFF = hex_to_bytes(CMD_OFF_HEX)


# MQTT topics
STATE_TOPIC = f"{MQTT_PREFIX}/state"
CMD_TOPIC = f"{MQTT_PREFIX}/set"
AVAIL_TOPIC = f"{MQTT_PREFIX}/availability"
DISCOVERY_TOPIC = f"homeassistant/switch/{RELAY_ID}/config"


# ---------- BLE transport ----------

class BLETransport:
    """
    Обёртка вокруг bleak с отдельным event loop и health-check.
    """

    def __init__(self, ble_addr: str, write_char: str, ble_name: str = "", health_interval: int = 0):
        self.ble_addr = (ble_addr or "").strip()
        self.ble_name = (ble_name or "").strip()
        self.write_char = write_char

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[Thread] = None
        self._client = None
        self._connect_lock = Lock()

        self._last_activity = 0.0
        self._idle_thread: Optional[Thread] = None
        self._stopping = False

        self._health_interval = max(0, int(health_interval or 0))
        self._health_thread: Optional[Thread] = None

        self._start_loop()

    # -- event loop management --

    def _start_loop(self):
        if self._loop is not None:
            return

        def _runner():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_forever()

        self._thread = Thread(target=_runner, daemon=True)
        self._thread.start()

        # ждём пока цикл поднимется
        while self._loop is None:
            time.sleep(0.05)

    def _run_coro(self, coro):
        if self._loop is None:
            raise RuntimeError("BLE loop not started")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result()

    # -- BLE helpers (async) --

    async def _ac_scan_pick(self) -> Optional[str]:
        from bleak import BleakScanner

        devices = await BleakScanner.discover(timeout=8.0)
        if self.ble_name:
            # точное совпадение имени
            for d in devices:
                if (d.name or "").strip() == self.ble_name:
                    return d.address
            # подстрока
            for d in devices:
                n = (d.name or "").strip()
                if self.ble_name.lower() in n.lower():
                    return d.address

        # если BLE_ADDR уже задан — просто возвращаем его
        if self.ble_addr:
            return self.ble_addr

        # fallback: первый JDY-подобный
        for d in devices:
            n = (d.name or "").strip().lower()
            if "jdy" in n or "bt05" in n:
                return d.address
        return None

    async def _ac_connect(self):
        from bleak import BleakClient

        if self._client is not None:
            try:
                if await self._client.is_connected():
                    return
            except Exception:
                try:
                    await self._client.disconnect()
                except Exception:
                    pass
                self._client = None

        addr = self.ble_addr
        if not addr:
            addr = await self._ac_scan_pick()
            if not addr:
                raise RuntimeError("Не найдено подходящее BLE-устройство JDY-33")
            self.ble_addr = addr

        client = BleakClient(addr)
        await client.connect(timeout=10.0)
        self._client = client

    async def _ac_disconnect(self):
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception:
                pass
        self._client = None

    async def _ac_write(self, data: bytes):
        if self._client is None:
            await self._ac_connect()
        await self._client.write_gatt_char(self.write_char, data, response=False)

    async def _ac_is_connected(self) -> bool:
        if self._client is None:
            return False
        try:
            return await self._client.is_connected()
        except Exception:
            return False

    # -- idle / health timers --

    def _cancel_idle_thread(self):
        t = self._idle_thread
        self._idle_thread = None
        if t is not None:
            # потоку просто дадим закончить; таймер у нас "ручной"
            pass

    def _idle_worker(self, started_at: float):
        time.sleep(IDLE_DISCONNECT_SEC)
        if self._stopping or CONNECTION_MODE != "ON_DEMAND":
            return
        # если с тех пор не было активности — разъединяемся
        if self._last_activity <= started_at:
            print("[BLE] Idle timeout, disconnecting...")
            try:
                self._run_coro(self._ac_disconnect())
            except Exception as e:
                print(f"[BLE] Idle disconnect error: {e}")

    def _bump_idle(self):
        self._last_activity = time.time()
        if CONNECTION_MODE != "ON_DEMAND":
            return
        self._cancel_idle_thread()
        self._idle_thread = Thread(
            target=self._idle_worker,
            args=(self._last_activity,),
            daemon=True,
        )
        self._idle_thread.start()

    def _start_health_monitor(self):
        if self._health_interval <= 0:
            return
        if self._health_thread and self._health_thread.is_alive():
            return

        def _loop():
            while not self._stopping:
                if CONNECTION_MODE == "PERSISTENT":
                    try:
                        if not self.healthy():
                            print("[BLE] Health-check: reconnect...")
                            try:
                                self.ensure_connected()
                            except Exception as e:
                                print(f"[BLE] Health-check connect error: {e}")
                    except Exception as e:
                        print(f"[BLE] Health-check error: {e}")
                # спим маленькими шагами, чтобы быстрее завершаться
                for _ in range(self._health_interval):
                    if self._stopping:
                        return
                    time.sleep(1)

        self._health_thread = Thread(target=_loop, daemon=True)
        self._health_thread.start()

    # -- public API --

    def ensure_connected(self):
        with self._connect_lock:
            self._run_coro(self._ac_connect())

    def send(self, data: bytes):
        if CONNECTION_MODE == "PERSISTENT":
            self.ensure_connected()
            self._start_health_monitor()

        self._run_coro(self._ac_write(data))
        self._bump_idle()

    def healthy(self) -> bool:
        try:
            return self._run_coro(self._ac_is_connected())
        except Exception:
            return False

    def close(self):
        self._stopping = True
        self._cancel_idle_thread()
        try:
            self._run_coro(self._ac_disconnect())
        except Exception:
            pass
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)


# ---------- MQTT bridge ----------

transport = BLETransport(
    ble_addr=BLE_ADDR,
    write_char=BLE_WRITE_CHAR,
    ble_name=BLE_NAME,
    health_interval=PERSISTENT_HEALTH_SEC,
)

_current_state = "OFF"
_mqtt_client: Optional[mqtt.Client] = None


def publish_state():
    if _mqtt_client is None:
        return
    _mqtt_client.publish(STATE_TOPIC, _current_state, retain=True)


def publish_availability(online: bool):
    if _mqtt_client is None:
        return
    _mqtt_client.publish(AVAIL_TOPIC, "online" if online else "offline", retain=True)


def publish_discovery():
    if _mqtt_client is None:
        return
    payload = {
        "name": RELAY_NAME,
        "unique_id": RELAY_ID,
        "command_topic": CMD_TOPIC,
        "state_topic": STATE_TOPIC,
        "availability_topic": AVAIL_TOPIC,
        "payload_on": "ON",
        "payload_off": "OFF",
        "state_on": "ON",
        "state_off": "OFF",
        "retain": True,
    }
    _mqtt_client.publish(DISCOVERY_TOPIC, json.dumps(payload), retain=True)


def handle_command(payload: str):
    global _current_state
    p = (payload or "").strip().upper()
    if p in ("1", "ON", "TRUE"):
        cmd = CMD_ON
        new_state = "ON"
    elif p in ("0", "OFF", "FALSE"):
        cmd = CMD_OFF
        new_state = "OFF"
    else:
        print(f"[MQTT] Unknown payload for command: {payload!r}")
        return

    print(f"[BLE] send {new_state}...")
    try:
        transport.send(cmd)
        _current_state = new_state
        publish_state()
    except Exception as e:
        print(f"[BLE] Error while sending command: {e}")


# ---------- MQTT callbacks ----------

def on_connect(client: mqtt.Client, userdata, flags, rc, properties=None):
    print(f"[MQTT] Connected with result code {rc}")
    client.subscribe(CMD_TOPIC)
    publish_discovery()
    publish_availability(True)
    publish_state()


def on_message(client: mqtt.Client, userdata, msg: mqtt.MQTTMessage):
    if msg.topic == CMD_TOPIC:
        payload = msg.payload.decode("utf-8", "ignore")
        print(f"[MQTT] CMD {payload!r}")
        handle_command(payload)


def on_disconnect(client: mqtt.Client, userdata, rc, properties=None):
    print(f"[MQTT] Disconnected (rc={rc})")
    publish_availability(False)


# ---------- main ----------

def main():
    global _mqtt_client

    client = mqtt.Client(
        client_id=f"jdy33-bridge-{os.getpid()}",
        protocol=MQTTv311,
        callback_api_version=CallbackAPIVersion.VERSION2,
    )
    _mqtt_client = client

    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASS)

    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    def handle_exit(*_a):
        print("[MAIN] Stopping...")
        try:
            publish_availability(False)
        except Exception:
            pass
        try:
            transport.close()
        except Exception:
            pass
        try:
            client.disconnect()
        except Exception:
            pass

    atexit.register(handle_exit)
    signal.signal(signal.SIGINT, lambda *_a: handle_exit())
    signal.signal(signal.SIGTERM, lambda *_a: handle_exit())

    # MQTT connect loop
    while True:
        try:
            print(f"[MQTT] Connecting to {MQTT_HOST}:{MQTT_PORT} ...")
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
            client.loop_forever(retry_first_connection=True)
        except Exception as e:
            print(f"[MQTT] Connection error: {e}. Retry in {CONNECT_RETRY_SEC}s")
            time.sleep(CONNECT_RETRY_SEC)


if __name__ == "__main__":
    main()
