[![version](https://img.shields.io/github/v/release/alexanderznamensky/hassio-addons)](https://github.com/alexanderznamensky/home-assistant-addons/releases)
[![ha_badge](https://img.shields.io/badge/Home%20Assistant-Add%20On-blue.svg)](https://www.home-assistant.io/)

# Home Assistant Add-on: Bluetooth JDY-33 Relay Bridge
[aarch64-shield]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64-shield]: https://img.shields.io/badge/amd64-yes-green.svg
[armv7-shield]: https://img.shields.io/badge/armv7-yes-green.svg
[i386-shield]: https://img.shields.io/badge/i386-yes-green.svg
![aarch64-shield]
![amd64-shield]
![armv7-shield]
![i386-shield]

MQTT-мост для Bluetooth-модулей **JDY-33-BLE** (должен быть совместим с BT05 / JDY-08, но не проверено), работающих по BLE (GATT).

Документация: [Documentation](https://github.com/alexanderznamensky/home-assistant-addons/blob/main/README.md)
и [Documentation](https://github.com/alexanderznamensky/home-assistant-addons/blob/main/bluetooth-jdy33-relay-bridge/DOCS.md)

Позволяет управлять реле прямо из Home Assistant — **без rfcomm, без SPP-порта и без телефона**.

Аддон публикует в Home Assistant **MQTT-свитч** через Discovery и управляет реле по BLE (через GATT-характеристику).
