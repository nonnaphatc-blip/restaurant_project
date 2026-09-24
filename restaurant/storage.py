"""JSON file storage: one lock, atomic writes, transaction helper."""
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
# Vercel's filesystem is read-only except /tmp, so data there is NOT permanent.
DATA_DIR = os.environ.get("DATA_DIR") or (
    "/tmp/restaurant-data" if os.environ.get("VERCEL") else os.path.join(BASE, "data"))
DB_FILE = os.path.join(DATA_DIR, "db.json")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
TZ = timezone(timedelta(hours=7))  # Thailand
FMT = "%Y-%m-%d %H:%M:%S"
COLLECTIONS = ("users", "categories", "menu", "tables", "orders", "bills",
               "reservations", "queue", "ingredients", "events")
_lock = threading.RLock()


class AppError(Exception):
    """Error whose message is safe to show to the user."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


class StorageError(AppError):
    def __init__(self, message):
        super().__init__(message, 500)


def now_str():
    return datetime.now(TZ).strftime(FMT)


def today_str():
    return now_str()[:10]


def default_db():
    db = {name: [] for name in COLLECTIONS}
    db["seq"] = {}
    db["settings"] = {"vat": 7.0, "service": 10.0, "point_per_baht": 10.0,
                      "egg_price": 10.0, "size_price": 20.0}
    return db


def load():
    with _lock:
        try:
            with open(DB_FILE, encoding="utf-8") as f:
                db = json.load(f)
        except FileNotFoundError:
            return default_db()
        except (OSError, ValueError) as e:
            raise StorageError("อ่านไฟล์ข้อมูลไม่ได้ กรุณาติดต่อผู้ดูแลระบบ") from e
        for key, value in default_db().items():
            db.setdefault(key, value)
        return db


def save(db):
    with _lock:
        tmp = None
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(db, f, ensure_ascii=False, indent=1)
            os.replace(tmp, DB_FILE)
        except (OSError, TypeError) as e:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
            raise StorageError("บันทึกข้อมูลไม่สำเร็จ") from e


@contextmanager
def transaction():
    """Load, let the caller change db, save. If the caller raises, nothing is saved."""
    with _lock:
        db = load()
        yield db
        save(db)


def next_id(db, coll):
    db["seq"][coll] = db["seq"].get(coll, 0) + 1
    return db["seq"][coll]
