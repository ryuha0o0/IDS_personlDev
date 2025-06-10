#!/usr/bin/env python3
# File: ids_subscriber.py
# "paho-mqtt 구독" 기반 IDS (콜백 API v2 적용판)
# Python 3.8+ / paho-mqtt 1.6.x 이상 필요
#
# 사용법:
#   $ python3 ids_subscriber.py
#
import json
import threading
import time
import logging
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import Deque, DefaultDict, Tuple, Dict

import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
import requests

# ────────────────────────────────────────────────────────
# 0. 기본값 설정 (여기를 수정하면 인자 없이 바로 적용됨)
# ────────────────────────────────────────────────────────

DEFAULT_BROKER_HOST       = "localhost"
DEFAULT_BROKER_PORT       = 1883
DEFAULT_API_ENDPOINT      = "http://localhost:8080/alert"

DEFAULT_DOS_THRESHOLD       = 50
DEFAULT_REPLAY_THRESHOLD    = 8
DEFAULT_TEMP_RANGE          = "-10,50"
DEFAULT_HUMI_RANGE          = "0,100"
DEFAULT_MAX_PAYLOAD_BYTES   = 200
DEFAULT_SUBSCRIBE_THRESHOLD = 10
DEFAULT_QOS2_HANG_TIMEOUT   = 5

# 허용 토픽 목록 (원한다면 여기에 추가/삭제)
ALLOWED_TOPICS = {"sensor/data", "test/topic"}

# ────────────────────────────────────────────────────────
# 1. 로거 설정
# ────────────────────────────────────────────────────────

def setup_logging():
    fmt = "[%(asctime)s] %(levelname)s %(message)s"
    logging.basicConfig(level=logging.INFO, format=fmt)
    return logging.getLogger("MQTT-IDS")

logger = setup_logging()

# ────────────────────────────────────────────────────────
# 2. Detector 클래스 (기존 로직과 동일)
# ────────────────────────────────────────────────────────
class Detector:
    def __init__(self):
        self.dos_threshold       = DEFAULT_DOS_THRESHOLD
        self.replay_threshold    = DEFAULT_REPLAY_THRESHOLD
        self.subscribe_threshold = DEFAULT_SUBSCRIBE_THRESHOLD
        self.qos2_hang_timeout   = DEFAULT_QOS2_HANG_TIMEOUT

        self.temp_min, self.temp_max = map(float, DEFAULT_TEMP_RANGE.split(','))
        self.humi_min, self.humi_max = map(float, DEFAULT_HUMI_RANGE.split(','))
        self.max_payload_bytes = DEFAULT_MAX_PAYLOAD_BYTES

        # 1초 윈도우용 PUBLISH 카운터 (토픽 구분 없이)
        self.publish_times: Deque[datetime] = deque()

        # Replay: 동일 payload 시각 기록
        self.replay_map: DefaultDict[str, Deque[datetime]] = defaultdict(deque)

        # Subscribe Flood: (client_id)별 구독 요청 시각 기록
        self.subscribe_map: DefaultDict[str, Deque[datetime]] = defaultdict(deque)

        # QoS2 핸드셰이크 페이즈 추적 (msg_id → (client_id, 시작 시각))
        self.qos2_pending: Dict[int, Tuple[str, datetime]] = {}

    def _is_within_window(self, dq: Deque[datetime], ts: datetime, window: int = 1) -> Deque[datetime]:
        cutoff = ts - timedelta(seconds=window)
        while dq and dq[0] < cutoff:
            dq.popleft()
        return dq

    def _send_alert(self, alert_type: str, details: dict) -> None:
        payload = {
            'type': alert_type,
            'timestamp': datetime.now().isoformat(),
            'details': details
        }
        try:
            requests.post(DEFAULT_API_ENDPOINT, json=payload, timeout=5)
        except Exception as e:
            logger.error(f"[Alert Send Error] {e}")

    def on_publish(self, client_id: str, topic: str, payload_str: str, qos: int, msg_id: int) -> None:
        """
        PUBLISH 메시지가 paho의 on_message()로 넘어왔을 때 호출
        """
        ts = datetime.now()

        # 1) QoS2 핸드셰이크 시작
        if qos == 2:
            self.qos2_pending[msg_id] = (client_id, ts)

        # 2) DoS: 전체 PUBLISH 카운트
        self.publish_times.append(ts)
        self.publish_times = self._is_within_window(self.publish_times, ts, window=1)
        if len(self.publish_times) >= self.dos_threshold:
            msg = f"[DoS Attack Detected] 1초간 PUBLISH ≥ {self.dos_threshold}"
            logger.warning(msg)
            self._send_alert('DoS', {'count_per_sec': len(self.publish_times)})

        # 3) Replay: 동일 payload 반복 체크
        dq = self.replay_map[payload_str]
        dq.append(ts)
        dq = self._is_within_window(dq, ts, window=1)
        self.replay_map[payload_str] = dq
        if len(dq) >= self.replay_threshold:
            msg = f"[Replay Attack Detected] Payload=\"{payload_str[:20]}…\" Count={len(dq)}/sec"
            logger.warning(msg)
            self._send_alert('Replay', {'payload_preview': payload_str[:50], 'count_per_sec': len(dq)})

        # 4) DataInjection: JSON 파싱 → 키/범위 검사
        trimmed = payload_str.strip()
        if trimmed.startswith('{'):
            try:
                data = json.loads(trimmed)
            except Exception:
                msg = f"[DataInjection Detected: Invalid JSON] Payload=\"{trimmed[:40]}…\""
                logger.warning(msg)
                self._send_alert('DataInjection_InvalidJSON', {'payload_preview': trimmed[:100]})
            else:
                if "temperature" not in data or "humidity" not in data:
                    msg = f"[DataInjection Detected: Missing Field] Payload=\"{trimmed[:40]}…\""
                    logger.warning(msg)
                    self._send_alert('DataInjection_MissingField', {'payload_preview': trimmed[:100]})
                else:
                    try:
                        t = float(data["temperature"])
                        h = float(data["humidity"])
                    except Exception:
                        msg = f"[DataInjection Detected: Non-Numeric Field] Payload=\"{trimmed[:40]}…\""
                        logger.warning(msg)
                        self._send_alert('DataInjection_NonNumeric', {'payload_preview': trimmed[:100]})
                    else:
                        if not (self.temp_min <= t <= self.temp_max):
                            msg = f"[DataInjection Detected: Temp Out-of-Range ({t})]"
                            logger.warning(msg)
                            self._send_alert('DataInjection_TempOutOfRange', {'value': t})
                        if not (self.humi_min <= h <= self.humi_max):
                            msg = f"[DataInjection Detected: Humi Out-of-Range ({h})]"
                            logger.warning(msg)
                            self._send_alert('DataInjection_HumiOutOfRange', {'value': h})

        # 5) Malformed Size: 페이로드 크기 검사
        length = len(payload_str.encode("utf-8"))
        if length > self.max_payload_bytes:
            msg = f"[Malformed Size Detected] PayloadLen={length} > {self.max_payload_bytes}"
            logger.warning(msg)
            self._send_alert('MalformedSize', {'length': length})

    def on_pubrel(self, msg_id: int, client_id: str) -> None:
        """
        클라이언트가 PUBREL을 보내면, QoS2 핸드셰이크 완료로 간주
        """
        if msg_id in self.qos2_pending:
            del self.qos2_pending[msg_id]

    def check_qos2_timeouts(self) -> None:
        """
        주기적으로 QoS2 페이즈가 일정 시간 이상 지났으면 Hang 탐지
        """
        now = datetime.now()
        to_remove = []
        for mid, (client_id, start_ts) in self.qos2_pending.items():
            if (now - start_ts).total_seconds() >= self.qos2_hang_timeout:
                msg = f"[QoS2 Hang Detected] Client={client_id} MsgID={mid}"
                logger.warning(msg)
                self._send_alert('QoS2Hang', {'client_id': client_id, 'msg_id': mid})
                to_remove.append(mid)
        for mid in to_remove:
            del self.qos2_pending[mid]

    def on_subscribe_event(self, client_id: str) -> None:
        """
        클라이언트가 SUBSCRIBE 요청을 보낼 때 호출
        """
        ts = datetime.now()
        dq = self.subscribe_map[client_id]
        dq.append(ts)
        dq = self._is_within_window(dq, ts, window=1)
        self.subscribe_map[client_id] = dq
        if len(dq) >= self.subscribe_threshold:
            msg = f"[Subscribe Flood Detected] Client={client_id} Count={len(dq)}/sec"
            logger.warning(msg)
            self._send_alert('SubscribeFlood', {'client_id': client_id, 'count_per_sec': len(dq)})


# ────────────────────────────────────────────────────────
# 3. MQTT 클라이언트(구독자) 설정 및 실행
# ────────────────────────────────────────────────────────

def main():
    detector = Detector()

    # 1) QoS2 Timeout 검사 스레드 (daemon)
    def qos2_timeout_loop():
        while True:
            detector.check_qos2_timeouts()
            time.sleep(1)

    threading.Thread(target=qos2_timeout_loop, daemon=True).start()

    # 2) paho-mqtt 클라이언트 생성 및 브로커 연결
    client = mqtt.Client(
        protocol=mqtt.MQTTv5,
        callback_api_version=CallbackAPIVersion.VERSION2
    )
    try:
        client.connect(DEFAULT_BROKER_HOST, DEFAULT_BROKER_PORT, keepalive=60)
    except Exception as e:
        logger.error(f"[Connection Error] Cannot connect to broker {DEFAULT_BROKER_HOST}:{DEFAULT_BROKER_PORT} → {e}")
        return

    # 3) on_message 콜백 정의 (정상적인 PUBLISH 처리)
    def on_message(client_mqtt, userdata, msg):
        """
        MQTT 5.0 에서도 on_message의 시그니처는 동일:
        (client, userdata, msg)
        """
        client_id = client._client_id.decode()  # IDS 자체 클라이언트 ID
        topic = msg.topic
        try:
            payload_str = msg.payload.decode('utf-8', errors='ignore')
        except:
            payload_str = ""
        qos = msg.qos
        msg_id = msg.mid

        # 1) Unauthorized Topic 검사
        if topic not in ALLOWED_TOPICS:
            msg = f"[Unauthorized Topic Detected] Topic=\"{topic}\" Payload=\"{payload_str[:20]}…\""
            logger.warning(msg)
            detector._send_alert('UnauthorizedTopic', {'topic': topic, 'payload_preview': payload_str[:50]})
            return

        # 2) 정상 토픽 → Publish 탐지
        detector.on_publish(client_id, topic, payload_str, qos, msg_id)

    # 4) on_subscribe 콜백 정의 (버전 2 시그니처)
    def on_subscribe(client_mqtt, userdata, mid, reasonCodes, properties):
        """
        버전 2: on_subscribe(client, userdata, mid, reasonCodes, properties)
        """
        client_id = client._client_id.decode()
        detector.on_subscribe_event(client_id)

    # 5) on_disconnect 콜백 정의 (버전 2 시그니처)
    def on_disconnect(client_mqtt, userdata, reasonCode, properties):
        """
        버전 2: on_disconnect(client, userdata, reasonCode, properties)
        """
        logger.info(f"[MQTT Disconnect] reasonCode={reasonCode}")

    # 6) 콜백 등록
    client.on_message    = on_message
    client.on_subscribe  = on_subscribe
    client.on_disconnect = on_disconnect

    # 7) IDS는 모든 토픽 구독 ("#")
    client.subscribe("#", qos=1)
    logger.info(f"[*] MQTT IDS Subscribing to all topics (#) at {DEFAULT_BROKER_HOST}:{DEFAULT_BROKER_PORT}")

    # 8) 네트워크 루프 시작 (블로킹)
    client.loop_forever()

if __name__ == "__main__":
    main()
