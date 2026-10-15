"""
Simulation Service — replays BoT-IoT test data through the event processor.
Replayed rows are stored as network_record events with source="dataset_replay";
they are never presented as live capture.
"""
from typing import Optional, Dict, Any
import os
import time
import threading
import pandas as pd

from config import Config
from core.models import SOURCE_REPLAY
from services.event_processor import EventProcessor


class SimulationService:
    _instance = None
    _lock = threading.Lock()

    def __init__(self, flask_app=None):
        self.flask_app = flask_app
        self.processor = EventProcessor.get_instance()
        self.is_running = False
        self.is_paused = False
        self.thread: Optional[threading.Thread] = None
        self.delay_seconds = 0.5
        self.current_scenario = "mixed_botiot"
        self.events_sent = 0

    @classmethod
    def get_instance(cls, flask_app=None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(flask_app)
            elif flask_app is not None:
                cls._instance.flask_app = flask_app
            return cls._instance

    def start(self, scenario: str = "mixed_botiot", speed_fps: float = 2.0) -> Dict[str, Any]:
        if self.is_running and not self.is_paused:
            return {"status": "already_running", "scenario": self.current_scenario}
        self.current_scenario = scenario
        self.delay_seconds = max(0.05, 1.0 / max(0.1, speed_fps))
        self.is_running = True
        self.is_paused = False
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()
        return {"status": "started", "scenario": scenario, "delay": self.delay_seconds}

    def pause(self):
        self.is_paused = True
        return {"status": "paused"}

    def resume(self):
        self.is_paused = False
        return {"status": "resumed"}

    def stop(self):
        self.is_running = False
        self.is_paused = False
        return {"status": "stopped", "events_sent": self.events_sent}

    def get_status(self):
        return {
            "is_running": self.is_running,
            "is_paused": self.is_paused,
            "scenario": self.current_scenario,
            "delay": self.delay_seconds,
            "events_sent": self.events_sent,
        }

    def _loop(self):
        csv_path = os.path.join(Config.DATA_DIR, "botiot_attack_test.csv")
        if not os.path.exists(csv_path):
            self.is_running = False
            return

        df = pd.read_csv(csv_path)
        total = len(df)
        cursor = 0

        while self.is_running:
            if self.is_paused:
                time.sleep(0.3)
                continue

            row = df.iloc[cursor % total].to_dict()
            cursor += 1
            row["stime"] = time.time()

            if self.flask_app:
                with self.flask_app.app_context():
                    self.processor.ingest(row, source=SOURCE_REPLAY)
            else:
                self.processor.ingest(row, source=SOURCE_REPLAY)

            self.events_sent += 1
            time.sleep(self.delay_seconds)
