from ultralytics import YOLO
from PIL import Image as PILImage
import os

model = None

# COCO class IDs that map directly to weapons
_WEAPON_CLASS_IDS = {
    43: "knife",
    76: "scissors",
}

# Objects that are non-threatening when seen on a person
_SAFE_CLASS_NAMES = {
    "person", "cell phone", "bottle", "cup",
    "chair", "backpack", "handbag", "suitcase",
}

_SUSPICIOUS_CONF_THRESHOLD = 0.55


def load_model():
    global model
    if model is None:
        print("[YOLO] Loading YOLOv8n model...")
        model = YOLO("yolov8n.pt")
        print("[YOLO] Model ready")
    return model


def detect_humans(image_path: str, confidence: float = 0.5) -> dict:
    """
    Two-stage detection using a single YOLOv8n model.

    Stage 1 — person detection on the full image (unchanged from original).
    Stage 2 — weapon / suspicious-object scan on each cropped person region.
               Only runs when Stage 1 finds at least one person.

    Returns
    -------
    {
        human_detected    : bool,
        confidence        : float,   # highest person confidence (0.0 if none)
        armed             : bool,    # True if weapon found in any crop
        weapon_confidence : float,   # highest weapon confidence (0.0 if none)
        weapon_class      : str,     # "knife" | "scissors" | "suspicious_object" | ""
        bbox_count        : int,     # number of person bboxes found
        image_path        : str,
    }
    """
    m = load_model()

    # ── Stage 1: person detection ─────────────────────────────────────────────
    results = m(image_path, conf=confidence, verbose=False)

    person_boxes      = []
    best_person_conf  = 0.0

    for result in results:
        for box in result.boxes:
            cls   = int(box.cls[0])
            conf  = float(box.conf[0])
            label = m.names[cls]
            if label == "person":
                person_boxes.append({
                    "label":      label,
                    "confidence": round(conf, 3),
                    "bbox":       box.xyxy[0].tolist(),
                })
                if conf > best_person_conf:
                    best_person_conf = conf

    human_detected = len(person_boxes) > 0

    # ── Stage 2: weapon scan on each person crop ──────────────────────────────
    armed             = False
    weapon_confidence = 0.0
    weapon_class      = ""

    if human_detected:
        try:
            img   = PILImage.open(image_path).convert("RGB")
            img_w, img_h = img.size

            for person in person_boxes:
                x1, y1, x2, y2 = [int(v) for v in person["bbox"]]
                x1 = max(0, x1);  y1 = max(0, y1)
                x2 = min(img_w, x2);  y2 = min(img_h, y2)

                if (x2 - x1) < 10 or (y2 - y1) < 10:
                    continue  # skip degenerate crops

                crop         = img.crop((x1, y1, x2, y2))
                crop_results = m(crop, conf=0.3, verbose=False)

                for cr in crop_results:
                    for box in cr.boxes:
                        cls   = int(box.cls[0])
                        conf  = float(box.conf[0])
                        label = m.names[cls]

                        # Explicit weapon class IDs
                        if cls in _WEAPON_CLASS_IDS:
                            armed = True
                            if conf > weapon_confidence:
                                weapon_confidence = conf
                                weapon_class      = _WEAPON_CLASS_IDS[cls]

                        # Suspicious: not in safe list, above threshold
                        elif label not in _SAFE_CLASS_NAMES and conf > _SUSPICIOUS_CONF_THRESHOLD:
                            armed = True
                            if conf > weapon_confidence:
                                weapon_confidence = conf
                                weapon_class      = "suspicious_object"

        except Exception as exc:
            print(f"[YOLO] Stage 2 error: {exc}")

    return {
        "human_detected":    human_detected,
        "confidence":        round(best_person_conf, 3),
        "armed":             armed,
        "weapon_confidence": round(weapon_confidence, 3),
        "weapon_class":      weapon_class,
        "bbox_count":        len(person_boxes),
        "image_path":        str(image_path),
    }
