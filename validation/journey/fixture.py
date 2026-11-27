"""Pinned Qeynos2 hunting fixture used by the headless journey.

These values describe the fixture, not a server build. Build identity is
always measured from the binaries passed in. Sources: the server README and
tests/qeynos2.rs at 3939f187af2c357b759ad10ae5fb2d6ff4801077 and the
2026-11-24 fixture worklog in Operations.
"""

SERVER_MODE = "qeynos2-hunting"
CHARACTER = "Clientab"
ZONE_ID = 2
ZONE_NAME = "qeynos2"
WORLD_NAME = "Rust Qeynos2"
WORLD_HOST = "127.0.0.1"

# Server model-origin seed pose on an empty state directory.
SEED_XYZ = (-925.0, 1194.0, 3.125)
SEED_HEADING = 0
# Headless subtracts this from wire Z to report its feet position.
CLIENT_FEET_OFFSET = 3.125

RAT_NAME_PREFIX = "a_large_rat"
RAT_SPAWN_ID = 10863
RAT_NPC_TYPE = 2011
RAT_MAX_HP = 11
RAT_INCARNATION = 1
DAMAGE_RANGE = (1, 3)

# The one movement command of the journey.
MOVE = {"kind": "move_for", "east": -1, "north": 0, "duration_ms": 200}
ATTACK_LEASE_MS = 2000

ENTRY_STAGES = (
    "login_accepted",
    "world_selected",
    "world_authenticated",
    "character_selected",
    "zone_endpoint",
    "zone_entered",
    "client_ready",
)

POSE_FORMAT = "qeynos2-pose-v1"
POSE_FILE = "clientab.pose"

# Pinned map inputs. The client's geometry digest is the .map SHA-256.
PINNED_MAPS = {
    "qeynos2.map": "040343c54e3b02bfd1637ce8fca8839dd676e17c41fb24c042ccfa0bd649435c",
    "qeynos2.wtr": "237d114e3b60a839c9ee0b2cba23dc4221057afc7add8aabae55ee61e89c4bdc",
}

# Ordered journey milestones. The host owns inputs, environment and cleanup;
# the guest owns the rest.
HOST_PRE = ("inputs", "environment")
GUEST = (
    "observer_self_check",
    "server_start",
    "entry",
    "move",
    "stop",
    "target",
    "hit",
    "camp",
    "restart",
    "relog",
)
HOST_POST = ("cleanup",)
MILESTONES = HOST_PRE + GUEST + HOST_POST

# Waits (seconds).
SERVER_START_TIMEOUT = 10.0
READY_TIMEOUT = 90.0
MOTION_EXPIRE_TIMEOUT = 2.0
# The pinned client (d034b7e) sends its resting position only at a 1300 ms
# keepalive and the first stationary packet about 1300 ms later, so the
# server's stopped sample can lag the stop command by ~2.6 s.
STOP_TIMEOUT = 8.0
STOP_QUIET = 0.5
TARGET_TIMEOUT = 3.0
HIT_TIMEOUT = 2.0
ATTACK_OBSERVE = 2.3
WIRE_ACK_TIMEOUT = 3.0
CAMP_TIMEOUT = 60.0
SERVER_STOP_TIMEOUT = 10.0
CHILD_STOP_TIMEOUT = 20.0
LOG_LIMIT_BYTES = 64 * 1024 * 1024
