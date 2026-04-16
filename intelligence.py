from collections import deque
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2
import threading

from app.database import get_pg
from app.security import log_attack

# {node_id: (lat, lng)}
_node_coords = {}
_coords_lock = threading.Lock()


def load_node_coords():
    conn = get_pg()
    cur = conn.cursor()
    cur.execute("SELECT node_id, lat, lng FROM nodes")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    with _coords_lock:
        for node_id, lat, lng in rows:
            _node_coords[node_id] = (lat, lng)
    print(f"[INTEL] Loaded coords for {len(_node_coords)} nodes")


# {node_id: deque of (timestamp, event_type)}
_recent_events = {}
_events_lock = threading.Lock()

# {node_id: {intervals: deque, mean: float, std: float}}
_baselines = {}
_baselines_lock = threading.Lock()

# {node_id: int 0-100}
_threat_scores = {}
_scores_lock = threading.Lock()


def haversine_distance(lat1, lng1, lat2, lng2) -> float:
    """Distance in meters between two coords."""
    earth_radius = 6371000
    lat1, lng1, lat2, lng2 = map(radians, [lat1, lng1, lat2, lng2])
    dlat = lat2 - lat1
    dlng = lng2 - lng1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlng / 2) ** 2
    return earth_radius * 2 * atan2(sqrt(a), sqrt(1 - a))


def check_physical_plausibility(
    node_id: str,
    event_time: datetime,
    event_type: str,
) -> dict:
    """
    Check if event is physically plausible given recent events at other nodes.
    """
    del event_type

    max_human_speed = 3.0
    max_vehicle_speed = 30.0
    lookback_seconds = 300

    if not _node_coords:
        load_node_coords()

    if node_id not in _node_coords:
        return {
            "plausible": True,
            "flag": "no_coords",
            "details": "coords unavailable",
        }

    lat1, lng1 = _node_coords[node_id]
    cutoff = event_time - timedelta(seconds=lookback_seconds)
    results = []

    with _events_lock:
        for other_id, events in _recent_events.items():
            if other_id == node_id or other_id not in _node_coords:
                continue

            lat2, lng2 = _node_coords[other_id]
            distance = haversine_distance(lat1, lng1, lat2, lng2)

            for evt_time, evt_type in events:
                del evt_type
                if evt_time < cutoff:
                    continue

                time_diff = abs((event_time - evt_time).total_seconds())
                if time_diff < 1:
                    time_diff = 1

                apparent_speed = distance / time_diff

                if apparent_speed > max_vehicle_speed:
                    results.append(
                        {
                            "plausible": False,
                            "flag": "teleportation_attack",
                            "details": (
                                f"Speed {apparent_speed:.1f}m/s between {node_id} "
                                f"and {other_id} - physically impossible. "
                                f"Distance: {distance:.0f}m Time: {time_diff:.1f}s"
                            ),
                        }
                    )
                elif apparent_speed > max_human_speed:
                    results.append(
                        {
                            "plausible": True,
                            "flag": "vehicle_detected",
                            "details": (
                                f"Speed {apparent_speed:.1f}m/s - vehicle or "
                                f"motorized intrusion. Nodes: {node_id} + {other_id}"
                            ),
                        }
                    )

    if not results:
        return {"plausible": True, "flag": "ok", "details": "plausible"}

    impossible = [result for result in results if not result["plausible"]]
    if impossible:
        return impossible[0]
    return results[0]


def record_event(node_id: str, event_time: datetime, event_type: str):
    """Record event for future plausibility checks."""
    with _events_lock:
        if node_id not in _recent_events:
            _recent_events[node_id] = deque(maxlen=20)
        _recent_events[node_id].append((event_time, event_type))


def update_heartbeat_baseline(node_id: str, heartbeat_time: datetime):
    """
    Update behavioral baseline for node.
    Returns (normal: bool, z_score: float).
    """
    with _baselines_lock:
        if node_id not in _baselines:
            _baselines[node_id] = {
                "last_time": heartbeat_time,
                "intervals": deque(maxlen=20),
                "mean": None,
                "std": None,
            }
            return True, 0.0

        baseline = _baselines[node_id]
        last_time = baseline["last_time"]
        interval = (heartbeat_time - last_time).total_seconds()
        baseline["last_time"] = heartbeat_time
        baseline["intervals"].append(interval)

        intervals = list(baseline["intervals"])
        if len(intervals) < 5:
            return True, 0.0

        mean = sum(intervals) / len(intervals)
        variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
        std = variance ** 0.5

        baseline["mean"] = mean
        baseline["std"] = std

        if std < 0.1:
            return True, 0.0

        z_score = abs(interval - mean) / std
        if z_score > 3.0:
            log_attack(
                node_id,
                "heartbeat_anomaly",
                f"Interval {interval:.1f}s deviates {z_score:.1f}σ from baseline {mean:.1f}s",
            )
            return False, z_score

        return True, z_score


def update_threat_score(node_id: str, delta: int, reason: str):
    """Update threat score for node."""
    with _scores_lock:
        current = _threat_scores.get(node_id, 0)
        new_score = max(0, min(100, current + delta))
        _threat_scores[node_id] = new_score
        print(f"[INTEL] {node_id} threat score: {current}->{new_score} ({reason})")
        return new_score


def get_threat_score(node_id: str) -> int:
    with _scores_lock:
        return _threat_scores.get(node_id, 0)


def get_all_threat_scores() -> list[dict]:
    with _scores_lock:
        return [
            {"node_id": node_id, "score": score}
            for node_id, score in sorted(_threat_scores.items())
        ]


def decay_threat_scores():
    """Decay all non-zero scores by 1."""
    with _scores_lock:
        for node_id in list(_threat_scores.keys()):
            if _threat_scores[node_id] > 0:
                _threat_scores[node_id] -= 1
