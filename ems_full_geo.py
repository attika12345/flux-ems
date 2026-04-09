# EMS_VERSION = "2026-03-01-v4"
APP_VERSION = "2026-03-15-v6"
APP_NAME    = "Flux EMS Pro"
BUILD_DATE  = "2026-03-15"
import os
import time as _time
_SCRIPT_START = _time.time()
import time
import json
import csv
import threading
from datetime import datetime, timedelta, timezone

import serial
import serial.tools.list_ports
import requests
import pytz
from flask import Flask, jsonify, request, render_template_string
import webbrowser

# Encryption for sensitive config values
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# -------------------------
# Simulation & Testing modes
# -------------------------

SIMULATION = False
TEST_MODE  = False  # PRODUCTION MODE — Real money, live Stripe only

sim_state = {
    'output_priority': 2,   # 0xE204
    'charge_priority': 2,   # 0xE20F default = Hybrid
    'bypass_enable': 0,
    'soc': 78, 'bat_v': 540, 'bat_i': -64, 'bat_p': 346,
    'pv1_v': 1437, 'pv1_i': 19, 'pv1_p': 272,
    'pv2_v': 0, 'pv2_i': 0, 'pv2_p': 0,
    'inv_v': 2355, 'load_i': 26, 'load_p': 609,
    'grid_v': 2365, 'grid_freq': 5013, 'inv_freq': 5013,
    'controller_temp': 0, 'battery_temp': 0,
    'device_state': 4, 'charge_state': 1,
    'fault_bits_1': 0, 'fault_bits_2': 0,
    'pv_generation_today': 3, 'load_consumption_today': 32,
    'running_days': 0, 'product_type': 4,
    'software_version_1': 6, 'software_version_2': 93201,
    'hardware_version_1': 2, 'hardware_version_2': 0,
    'serial_number': 'SR-2412180134-301828',
    'model_code': 30, 'rs485_address': 1, 'rs485_version': 107,
    'battery_type': 6, 'nominal_capacity': 100, 'system_voltage': 48
}

# -------------------------
# Inverter / Serial config
# -------------------------

BAUD     = 9600
SLAVE_ID = 1
UK_TZ    = pytz.timezone('Europe/London')  # updated at runtime by _update_local_tz()

def _update_local_tz():
    """Re-read timezone from config and update the global UK_TZ."""
    global UK_TZ
    with config_lock:
        tz_name = config.get('timezone', 'Europe/London')
    try:
        UK_TZ = pytz.timezone(tz_name)
        print(f"[TZ] Timezone set to {tz_name}")
    except Exception as e:
        print(f"[TZ] Invalid timezone '{tz_name}': {e} — keeping {UK_TZ}")

AGILE_SLOT_MINUTES = 30

# ── LICENSE ───────────────────────────────────────────────────────────────────
import uuid
import hashlib
import subprocess
import platform as _platform

LICENSE_API  = "https://license.fluxsignals.com"  # Production only
GRACE_DAYS   = 1  # 1 day grace period for paid licenses (Worker handles trial period)

def get_machine_id() -> str:
    """Stable hardware fingerprint — works on all modern Windows versions."""
    # 1) Try PowerShell CIM (modern, reliable)
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"],
            stderr=subprocess.DEVNULL
        ).decode().strip()

        if raw and raw not in ("00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"):
            return hashlib.sha256(raw.encode()).hexdigest()[:32]
    except Exception:
        pass

    # 2) Try WMIC (legacy)
    try:
        raw = subprocess.check_output(
            "wmic csproduct get uuid", shell=True
        ).decode(errors="ignore").split("\n")

        uuid_val = [x.strip() for x in raw if x.strip() and x.strip() != "UUID"][0]
        if uuid_val:
            return hashlib.sha256(uuid_val.encode()).hexdigest()[:32]
    except Exception:
        pass

    # 3) Fallback: combine multiple system properties
    try:
        parts = [
            _platform.node(),
            _platform.machine(),
            _platform.processor(),
            _platform.version(),
        ]
        fp = "|".join(parts)
        return hashlib.sha256(fp.encode()).hexdigest()[:32]
    except Exception:
        pass

    # 4) Absolute fallback (should never happen)
    return hashlib.sha256(b"fallback_machine").hexdigest()[:32]

# ── Config Encryption (Fernet + HKDF) ────────────────────────────────────────
EMBED_SECRET = b"FluxEMS-2026-f7a3d9c2e1b4-secure"  # Hidden after obfuscation
SENSITIVE_KEYS = {"license_key", "trial_token", "machine_id_locked",
                  "registered_code_hash", "license_last_ok", "license_grace_until"}

def _get_fernet_cipher() -> Fernet:
    """Get Fernet cipher using machine_id + embedded secret."""
    try:
        mid = get_machine_id().encode()
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ems-config")
        key = hkdf.derive(mid + EMBED_SECRET)
        return Fernet(base64.urlsafe_b64encode(key))
    except Exception:
        raise RuntimeError("Failed to initialize encryption")

def _encrypt_value(val: str) -> str:
    """Encrypt a value using Fernet."""
    try:
        return f"enc:{_get_fernet_cipher().encrypt(val.encode()).decode()}"
    except Exception:
        return val  # Fallback: store unencrypted (shouldn't happen)

def _decrypt_value(val: str) -> str:
    """Decrypt a value, return empty string if tampered."""
    if not isinstance(val, str) or not val.startswith("enc:"):
        return val  # Already plain text
    try:
        encrypted = val[4:]  # Remove "enc:" prefix
        return _get_fernet_cipher().decrypt(encrypted.encode()).decode()
    except Exception:
        return ""  # Decryption failed = tampered/corrupted

def _do_heartbeat(key: str) -> tuple:
    """Call CF Worker /heartbeat. Returns (valid: bool, reason: str)."""
    mid = get_machine_id()
    code_hash = _get_code_hash()
    try:
        session = requests.Session()
        session.trust_env = False
        r = session.post(
            f"{LICENSE_API}/heartbeat",
            json={
                "license_key": key,
                "machine_id": mid,
                "code_hash": code_hash,
                "app_version": APP_VERSION,
            },
            timeout=10,
        )
        d = r.json()
        if d.get("valid"):
            grace = (datetime.now(timezone.utc) + timedelta(days=GRACE_DAYS)).isoformat()
            with config_lock:
                config["license_last_ok"]     = datetime.now(timezone.utc).isoformat()
                config["license_grace_until"] = grace
                config["registered_code_hash"] = code_hash
            save_config()
            return True, "licensed"
        return False, d.get("reason", "invalid")
    except Exception:
        # Network error → honor grace period (if it exists)
        # If no grace period AND no trial, reject the request to prevent unlimited offline usage
        with config_lock:
            g = config.get("license_grace_until")
        if g:
            try:
                if datetime.now(timezone.utc) < datetime.fromisoformat(g):
                    return True, "grace_period"
            except Exception:
                pass
        # No valid grace period — trial validation requires Worker (cannot be verified offline)
        return False, "offline_no_grace"  # No grace period and no network — reject

def _do_trial_check() -> tuple:
    """Validate trial period via Worker (server-side timestamp = tamper-proof)."""
    with config_lock:
        token = config.get("trial_token", "")
    if not token:
        print("[TRIAL] No trial token found")
        return False, "no_trial_token"
    try:
        mid = get_machine_id()
        session = requests.Session()
        session.trust_env = False
        r = session.post(
            f"{LICENSE_API}/validate_trial",
            json={"trial_token": token, "machine_id": mid},
            timeout=10,
        )
        d = r.json()
        result = (d.get("valid", False), d.get("reason", "trial_expired"))
        print(f"[TRIAL] Worker response: {result}")
        return result
    except Exception as e:
        # Network error — trial cannot be validated without Worker
        # No fallback: this prevents offline operation for trial (only paid licenses have grace)
        print(f"[TRIAL] Worker error: {e}")
        return False, "trial_offline_no_validation"

def check_license() -> tuple:
    """
    Returns (valid: bool, reason: str).
    valid=False → show paywall, disable automation.
    """
    with config_lock:
        key = config.get("license_key", "").strip()
        trial = config.get("trial_token", "")

    # 1) No license key → trial mode
    if not key:
        return _do_trial_check()

    # 2) Machine lock check
    ok, reason = _check_machine_lock()
    if not ok:
        return False, reason

    # 3) Online heartbeat (paid license)
    return _do_heartbeat(key)

def _get_code_hash() -> str:
    """Get hash of this script to detect tampering."""
    try:
        with open(__file__, 'rb') as f:
            # Skip the first 3000 bytes (config might be there), hash the rest
            f.seek(3000)
            return hashlib.sha256(f.read()).hexdigest()[:16]
    except Exception:
        return "unknown"

def _check_machine_lock() -> tuple:
    """
    Verify machine binding. On first license activation, machine_id is locked.
    Returns (valid: bool, reason: str).
    """
    with config_lock:
        registered_mid = config.get("machine_id_locked")
        key = config.get("license_key", "").strip()

    if not key:
        return True, "no_lock_trial"

    current_mid = get_machine_id()

    # First license activation — lock to this machine
    if not registered_mid:
        with config_lock:
            config["machine_id_locked"] = current_mid
        save_config()
        return True, "machine_locked"

    # Validate machine hasn't changed
    if current_mid != registered_mid:
        print(f"[LICENSE] Machine ID mismatch!")
        print(f"[LICENSE]   Registered: {registered_mid[:16]}...")
        print(f"[LICENSE]   Current:    {current_mid[:16]}...")
        return False, "machine_changed"

    return True, "machine_ok"

def _heartbeat_loop():
    """Background thread: re-validate license every 24 hours."""
    while True:
        time.sleep(24 * 3600)
        valid, reason = check_license()
        if not valid:
            print(f"[LICENSE] Invalid: {reason} — disabling automation")
            # Fatal errors: machine lock violation or tampered client
            if reason in ("machine_changed", "tampered_client"):
                fatal_msg = {
                    "machine_changed": "FATAL: Code has been moved to unauthorized device — shutting down",
                    "tampered_client": "FATAL: Client code integrity violation — shutting down"
                }
                print(f"[LICENSE] {fatal_msg.get(reason, 'Unknown fatal error')}")
                with config_lock:
                    config["automation_enabled"] = False
                with ems_lock:
                    ems_state["last_error"] = fatal_msg.get(reason, "Fatal license error")
                time.sleep(5)
                _sys.exit(1)
            with config_lock:
                config["automation_enabled"] = False
            with ems_lock:
                ems_state["last_error"] = f"License {reason} — subscribe at fluxsignals.com"
# ─────────────────────────────────────────────────────────────────────────────

import sys as _sys

# ── STARTUP DIAGNOSTIC ──────────────────────────────────────
print("=" * 60)
print(f"[DIAG] Python: {_sys.executable}")
print(f"[DIAG] Script: {__file__ if '__file__' in dir() else 'N/A'}")
print(f"[DIAG] CWD:    {os.getcwd()}")
print(f"[DIAG] Frozen: {getattr(_sys, 'frozen', False)}")
print("=" * 60)
# ─────────────────────────────────────────────────────────────

def _app_dir():
    """Returns a writable directory for data files.
    Tries multiple locations in order until one works.
    """
    def _test_writable(path):
        try:
            os.makedirs(path, exist_ok=True)
            test = os.path.join(path, '.ems_write_test')
            with open(test, 'w') as tf:
                tf.write('ok')
            os.remove(test)
            return True
        except Exception:
            return False

    candidates = []

    # 1. Script/exe directory
    try:
        if getattr(_sys, 'frozen', False):
            candidates.append(os.path.dirname(os.path.abspath(_sys.executable)))
        else:
            candidates.append(os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        pass

    # 2. Current working directory
    candidates.append(os.path.abspath('.'))

    # 3. AppData\Local (always exists on Windows, no OneDrive issues)
    candidates.append(os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'ems_optimizer'))

    # 4. Home directory subfolder
    candidates.append(os.path.join(os.path.expanduser('~'), 'ems_optimizer'))

    # 5. Temp
    import tempfile
    candidates.append(os.path.join(tempfile.gettempdir(), 'ems_optimizer'))

    for d in candidates:
        if d and _test_writable(d):
            print(f"[INIT] APP_DIR: {d}")
            return d

    # Should never reach here
    import tempfile
    return tempfile.gettempdir()

APP_DIR      = _app_dir()
# Force-create data directory immediately (before any file operations)
try:
    os.makedirs(APP_DIR, exist_ok=True)
    print(f"[INIT] APP_DIR: {APP_DIR}")
except Exception as _e:
    print(f"[INIT] WARNING: Cannot create APP_DIR {APP_DIR}: {_e}")
CONFIG_FILE  = os.path.join(APP_DIR, "ems_config.json")
HISTORY_FILE = os.path.join(APP_DIR, "ems_history.csv")
PRICES_CACHE_FILE_BASE = os.path.join(APP_DIR, "ems_prices_cache.json")

# -------------------------
# Register map (full original)
# -------------------------

REGISTERS = {
    # System Info
    'product_type':       {'reg': 0x000B, 'type': 'BYTE', 'writable': False, 'unit': '', 'desc': 'Product type', 'values': {0: 'domestic controller', 1: 'controller for street light', 3: 'grid-connected inverter', 4: 'all-in-one solar charger inverter', 5: 'power frequency off-grid'}},
    'software_version_1': {'reg': 0x0014, 'type': '', 'writable': False, 'unit': '0.01', 'desc': 'Software version 1'},
    'software_version_2': {'reg': 0x0015, 'type': '', 'writable': False, 'unit': '0.01', 'desc': 'Software version 2'},
    'hardware_version_1': {'reg': 0x0016, 'type': '', 'writable': False, 'unit': '0.01', 'desc': 'Hardware version 1'},
    'hardware_version_2': {'reg': 0x0017, 'type': '', 'writable': False, 'unit': '0.01', 'desc': 'Hardware version 2'},
    'rs485_address':      {'reg': 0x001A, 'type': '', 'writable': False, 'unit': '', 'desc': 'RS485 address'},
    'model_code':         {'reg': 0x001B, 'type': '', 'writable': False, 'unit': '', 'desc': 'Model Code'},
    'rs485_version':      {'reg': 0x001C, 'type': '', 'writable': False, 'unit': '0.01', 'desc': 'RS485 version'},
    'product_sn':         {'reg': (0x0035, 0x0048), 'type': 'ASCII', 'writable': False, 'unit': '', 'desc': 'Product SN'},
    # Battery & Power
    'battery_soc':                 {'reg': 0x0100, 'type': '', 'writable': False, 'unit': '%', 'desc': 'Battery capacity SOC'},
    'battery_voltage':             {'reg': 0x0101, 'type': '', 'writable': False, 'unit': '0.1V', 'desc': 'Battery voltage'},
    'battery_current':             {'reg': 0x0102, 'type': 'SHORT', 'writable': False, 'unit': '0.1A', 'desc': 'Battery current'},
    'controller_temp':             {'reg': 0x0103, 'type': 'BYTE', 'writable': False, 'unit': 'C', 'desc': 'Controller temperature'},
    'battery_temp':                {'reg': 0x0103, 'type': 'BYTE', 'writable': False, 'unit': 'C', 'desc': 'Battery temperature'},
    'device_total_charging_power': {'reg': 0x010E, 'type': '', 'writable': False, 'unit': 'W', 'desc': 'Device Total charging power'},
    # PV
    'pv1_voltage': {'reg': 0x0107, 'type': '', 'writable': False, 'unit': '0.1V', 'desc': 'PV1 voltage'},
    'pv1_current': {'reg': 0x0108, 'type': '', 'writable': False, 'unit': '0.1A', 'desc': 'PV1 current'},
    'pv1_power':   {'reg': 0x0109, 'type': '', 'writable': False, 'unit': 'W', 'desc': 'PV1 power'},
    'pv2_voltage': {'reg': 0x010F, 'type': '', 'writable': False, 'unit': '0.1V', 'desc': 'PV2 voltage'},
    'pv2_current': {'reg': 0x0110, 'type': '', 'writable': False, 'unit': '0.1A', 'desc': 'PV2 current'},
    'pv2_power':   {'reg': 0x0111, 'type': '', 'writable': False, 'unit': 'W', 'desc': 'PV2 power'},
    # Charging
    'device_charge_state': {'reg': 0x010B, 'type': '', 'writable': False, 'unit': '', 'desc': 'Device Charge state', 'values': {0: 'Charge off', 1: 'Quick charge', 2: 'Const voltage charge', 4: 'Float charge', 6: 'Li battery activate', 8: 'Full'}},
    # Faults
    'fault_bits_1': {'reg': 0x0200, 'type': '16BIT_FLAGS', 'writable': False, 'unit': '', 'desc': 'Fault Bits 1'},
    'fault_bits_2': {'reg': 0x0201, 'type': '16BIT_FLAGS', 'writable': False, 'unit': '', 'desc': 'Fault Bits 2'},
    'fault_bits_3': {'reg': 0x0202, 'type': '16BIT_FLAGS', 'writable': False, 'unit': '', 'desc': 'Fault Bits 3'},
    'fault_bits_4': {'reg': 0x0203, 'type': '16BIT_FLAGS', 'writable': False, 'unit': '', 'desc': 'Fault Bits 4'},
    'fault_code_1': {'reg': 0x0204, 'type': '', 'writable': False, 'unit': '', 'desc': 'Fault Code 1'},
    'fault_code_2': {'reg': 0x0205, 'type': '', 'writable': False, 'unit': '', 'desc': 'Fault Code 2'},
    'fault_code_3': {'reg': 0x0206, 'type': '', 'writable': False, 'unit': '', 'desc': 'Fault Code 3'},
    'fault_code_4': {'reg': 0x0207, 'type': '', 'writable': False, 'unit': '', 'desc': 'Fault Code 4'},
    # Device State
    'device_state': {'reg': 0x0210, 'type': '', 'writable': False, 'unit': '', 'desc': 'Device state', 'values': {0: 'Power-up delay', 1: 'Waiting state', 2: 'Initialization', 3: 'Soft start', 4: 'Mains powered operation', 5: 'Inverter powered operation', 6: 'Inverter to mains', 7: 'Mains to inverter', 8: 'Battery activate', 9: 'Shutdown by user', 10: 'Fault'}},
    # Grid & Inverter
    'grid_phase_a_voltage':             {'reg': 0x0213, 'type': '', 'writable': False, 'unit': '0.1V', 'desc': 'Grid phase-A voltage'},
    'grid_frequency':                   {'reg': 0x0215, 'type': '', 'writable': False, 'unit': '0.01Hz', 'desc': 'Grid frequency'},
    'inverter_phase_a_output_voltage':  {'reg': 0x0216, 'type': '', 'writable': False, 'unit': '0.1V', 'desc': 'Inverter phase-A output voltage'},
    'inverter_frequency':               {'reg': 0x0218, 'type': '', 'writable': False, 'unit': '0.01Hz', 'desc': 'Inverter frequency'},
    'load_phase_a_current':             {'reg': 0x0219, 'type': '', 'writable': False, 'unit': '0.1A', 'desc': 'Load Phase-A current'},
    'load_pf':                          {'reg': 0x021A, 'type': '', 'writable': False, 'unit': '0.01', 'desc': 'Load PF'},
    'load_phase_a_active_power':        {'reg': 0x021B, 'type': '', 'writable': False, 'unit': 'W', 'desc': 'Load Phase-A active power'},
    # Config (writable)
    'nominal_battery_capacity': {'reg': 0xE002, 'type': '', 'writable': True, 'unit': '1AH', 'desc': 'Nominal battery capacity'},
    'system_voltage':           {'reg': 0xE003, 'type': '', 'writable': False, 'unit': 'V', 'desc': 'System Voltage'},
    'battery_type':             {'reg': 0xE004, 'type': '', 'writable': True, 'unit': '', 'desc': 'Battery Type', 'values': {0: 'User define', 1: 'SLD', 2: 'FLD'}},
    'output_priority':      {'reg': 0xE204, 'type': '', 'writable': True, 'unit': '', 'desc': 'Output priority',
                             'values': {0: 'Solar only', 1: 'Line/Grid priority', 2: 'SBU (Solar-Battery-Utility)'}},
    'charge_priority':      {'reg': 0xE20F, 'type': '', 'writable': True, 'unit': '', 'desc': 'Charge priority',
                             'values': {0: 'PV preferred', 1: 'Mains preferred', 2: 'Hybrid (PV+Mains)', 3: 'PV only'}},
    'overload_bypass_enable': {'reg': 0xE212, 'type': '', 'writable': True, 'unit': '', 'desc': 'Overload bypass enable', 'values': {0: 'Disable', 1: 'Enable'}},
    # Statistics — today
    'battery_charge_ah_today':      {'reg': 0xF02D, 'type': '', 'writable': False, 'unit': 'AH',     'desc': 'Battery charge AH of the day'},
    'battery_discharge_ah_today':   {'reg': 0xF02E, 'type': '', 'writable': False, 'unit': 'AH',     'desc': 'Battery discharge AH of the day'},
    'pv_power_generation_today':    {'reg': 0xF02F, 'type': '', 'writable': False, 'unit': '0.1kWh', 'desc': 'PV power generation of the day'},
    'load_power_consumption_today': {'reg': 0xF030, 'type': '', 'writable': False, 'unit': '0.1kWh', 'desc': 'Load power consumption of the day'},
    'total_running_days':           {'reg': 0xF031, 'type': '', 'writable': False, 'unit': 'day',    'desc': 'Total running days'},
    'total_battery_overdischarge':  {'reg': 0xF032, 'type': '', 'writable': False, 'unit': '',       'desc': 'Total number of battery overdischarge'},
    'total_battery_full_charge':    {'reg': 0xF033, 'type': '', 'writable': False, 'unit': '',       'desc': 'Total number of battery full charge'},
    'mains_charge_ah_today':        {'reg': 0xF03C, 'type': '', 'writable': False, 'unit': 'AH',     'desc': 'Mains charge level of today'},
    'mains_load_kwh_today':         {'reg': 0xF03D, 'type': '', 'writable': False, 'unit': '0.1kWh', 'desc': 'Power consumption by load from mains today'},
    # Historical data (last 7 days)
    'history_pv_power_generation_today_minus_1': {'reg': 0xF000, 'writable': False},
    'history_pv_power_generation_today_minus_2': {'reg': 0xF001, 'writable': False},
    'history_pv_power_generation_today_minus_3': {'reg': 0xF002, 'writable': False},
    'history_pv_power_generation_today_minus_4': {'reg': 0xF003, 'writable': False},
    'history_pv_power_generation_today_minus_5': {'reg': 0xF004, 'writable': False},
    'history_pv_power_generation_today_minus_6': {'reg': 0xF005, 'writable': False},
    'history_pv_power_generation_today_minus_7': {'reg': 0xF006, 'writable': False},
    'history_battery_charge_level_today_minus_1': {'reg': 0xF007, 'writable': False},
    'history_battery_charge_level_today_minus_2': {'reg': 0xF008, 'writable': False},
    'history_battery_charge_level_today_minus_3': {'reg': 0xF009, 'writable': False},
    'history_battery_charge_level_today_minus_4': {'reg': 0xF00A, 'writable': False},
    'history_battery_charge_level_today_minus_5': {'reg': 0xF00B, 'writable': False},
    'history_battery_charge_level_today_minus_6': {'reg': 0xF00C, 'writable': False},
    'history_battery_charge_level_today_minus_7': {'reg': 0xF00D, 'writable': False},
    'history_battery_discharge_level_today_minus_1': {'reg': 0xF00E, 'writable': False},
    'history_battery_discharge_level_today_minus_2': {'reg': 0xF00F, 'writable': False},
    'history_battery_discharge_level_today_minus_3': {'reg': 0xF010, 'writable': False},
    'history_battery_discharge_level_today_minus_4': {'reg': 0xF011, 'writable': False},
    'history_battery_discharge_level_today_minus_5': {'reg': 0xF012, 'writable': False},
    'history_battery_discharge_level_today_minus_6': {'reg': 0xF013, 'writable': False},
    'history_battery_discharge_level_today_minus_7': {'reg': 0xF014, 'writable': False},
    'history_power_consumption_load_today_minus_1': {'reg': 0xF01C, 'writable': False},
    'history_power_consumption_load_today_minus_2': {'reg': 0xF01D, 'writable': False},
    'history_power_consumption_load_today_minus_3': {'reg': 0xF01E, 'writable': False},
    'history_power_consumption_load_today_minus_4': {'reg': 0xF01F, 'writable': False},
    'history_power_consumption_load_today_minus_5': {'reg': 0xF020, 'writable': False},
    'history_power_consumption_load_today_minus_6': {'reg': 0xF021, 'writable': False},
    'history_power_consumption_load_today_minus_7': {'reg': 0xF022, 'writable': False},
    # Historical mains charge (last 7 days)
    'history_mains_charge_level_today_minus_1': {'reg': 0xF015, 'writable': False, 'unit': 'AH',     'desc': 'History mains charge level today-1'},
    'history_mains_charge_level_today_minus_2': {'reg': 0xF016, 'writable': False, 'unit': 'AH',     'desc': 'History mains charge level today-2'},
    'history_mains_charge_level_today_minus_3': {'reg': 0xF017, 'writable': False, 'unit': 'AH',     'desc': 'History mains charge level today-3'},
    'history_mains_charge_level_today_minus_4': {'reg': 0xF018, 'writable': False, 'unit': 'AH',     'desc': 'History mains charge level today-4'},
    'history_mains_charge_level_today_minus_5': {'reg': 0xF019, 'writable': False, 'unit': 'AH',     'desc': 'History mains charge level today-5'},
    'history_mains_charge_level_today_minus_6': {'reg': 0xF01A, 'writable': False, 'unit': 'AH',     'desc': 'History mains charge level today-6'},
    'history_mains_charge_level_today_minus_7': {'reg': 0xF01B, 'writable': False, 'unit': 'AH',     'desc': 'History mains charge level today-7'},
    # Historical mains load (last 7 days)
    'history_mains_load_today_minus_1': {'reg': 0xF023, 'writable': False, 'unit': '0.1kWh', 'desc': 'History mains load today-1'},
    'history_mains_load_today_minus_2': {'reg': 0xF024, 'writable': False, 'unit': '0.1kWh', 'desc': 'History mains load today-2'},
    'history_mains_load_today_minus_3': {'reg': 0xF025, 'writable': False, 'unit': '0.1kWh', 'desc': 'History mains load today-3'},
    'history_mains_load_today_minus_4': {'reg': 0xF026, 'writable': False, 'unit': '0.1kWh', 'desc': 'History mains load today-4'},
    'history_mains_load_today_minus_5': {'reg': 0xF027, 'writable': False, 'unit': '0.1kWh', 'desc': 'History mains load today-5'},
    'history_mains_load_today_minus_6': {'reg': 0xF028, 'writable': False, 'unit': '0.1kWh', 'desc': 'History mains load today-6'},
    'history_mains_load_today_minus_7': {'reg': 0xF029, 'writable': False, 'unit': '0.1kWh', 'desc': 'History mains load today-7'},
}

# Convenience aliases
REG_SOC        = REGISTERS['battery_soc']['reg']                        # 0x0100
REG_BAT_V      = REGISTERS['battery_voltage']['reg']                    # 0x0101
REG_BAT_I      = REGISTERS['battery_current']['reg']                    # 0x0102
REG_BAT_P      = REGISTERS['device_total_charging_power']['reg']        # 0x010E
REG_PV_V       = REGISTERS['pv1_voltage']['reg']                        # 0x0107
REG_PV_I       = REGISTERS['pv1_current']['reg']                        # 0x0108
REG_PV_P       = REGISTERS['pv1_power']['reg']                          # 0x0109
REG_INV_V      = REGISTERS['inverter_phase_a_output_voltage']['reg']    # 0x0216
REG_LOAD_I     = REGISTERS['load_phase_a_current']['reg']               # 0x0219
REG_GRID_V     = REGISTERS['grid_phase_a_voltage']['reg']               # 0x0213
REG_OUTPUT_PRI = REGISTERS['output_priority']['reg']                    # 0xE204
REG_CHARGE_PRI = REGISTERS['charge_priority']['reg']                    # 0xE20F
REG_BYPASS     = REGISTERS['overload_bypass_enable']['reg']             # 0xE212

# ── E204 output priority values ──
OUTPUT_SBU = 2   # expensive/normal: Solar-Battery-Utility (battery before grid for load)
OUTPUT_SUB = 3   # cheap slot: Solar-Utility-Battery (grid charges battery)

# ── E20F charge priority values ──
MODE_PV_PREFERRED   = 0   # PV preferred
MODE_MAINS_PREFERRED = 1  # Mains preferred
MODE_HYBRID         = 2   # PV + mains (normal charging)
MODE_PV_ONLY        = 3   # PV only, mains does NOT charge

# Octopus Agile defaults
PRODUCT_CODE = "AGILE-24-10-01"
TARIFF_CODE  = "E-1R-AGILE-24-10-01-B"

# -------------------------
# Serial port + lock  (replaces pymodbus)
# -------------------------

SERIAL_PORT  = None          # auto-detected at startup
_serial_lock = threading.Lock()

def modbus_crc(data: bytes) -> bytes:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc.to_bytes(2, byteorder='little')

def _build_read(reg: int, count: int = 1) -> bytes:
    pkt = bytes([SLAVE_ID, 0x03, reg >> 8, reg & 0xFF, count >> 8, count & 0xFF])
    return pkt + modbus_crc(pkt)

def _parse_block(resp: bytes, count: int, signed_indices: set = None) -> list | None:
    """Parse a multi-register Modbus response. Returns list of ints or None on error."""
    expected = 3 + count * 2 + 2  # addr + func + byte_count + data + crc
    if len(resp) < expected:
        return None
    if resp[-2:] != modbus_crc(resp[:-2]):
        return None
    result = []
    for i in range(count):
        val = (resp[3 + i*2] << 8) | resp[4 + i*2]
        if signed_indices and i in signed_indices and val > 32767:
            val -= 65536
        result.append(val)
    return result

def _build_write(reg: int, value: int) -> bytes:
    pkt = bytes([SLAVE_ID, 0x06, reg >> 8, reg & 0xFF, value >> 8, value & 0xFF])
    return pkt + modbus_crc(pkt)

def find_serial_port() -> str | None:
    global SERIAL_PORT
    if SIMULATION:
        return "SIMULATION"
    if SERIAL_PORT:
        return SERIAL_PORT

    ports = serial.tools.list_ports.comports()

    # 1. lepes: description alapjan szures (mint dashboard.py)
    usb_ports = [p for p in ports if any(
        x in (p.description or '').lower()
        for x in ["usb", "ch340", "serial", "cp210", "ftdi", "uart"]
    )]
    # Ha nincs description match, probald az osszes portot
    candidates = usb_ports if usb_ports else list(ports)

    print(f"[SER] Ports found: {[p.device for p in ports]}")
    print(f"[SER] USB candidates: {[p.device for p in candidates]}")

    for p in candidates:
        port = p.device
        try:
            cmd = _build_read(REG_SOC, 1)
            with serial.Serial(port, BAUD, timeout=1) as s:
                if s.in_waiting:
                    s.read_all()
                s.write(cmd)
                time.sleep(0.15)
                resp = s.read_all()
            if len(resp) >= 7 and resp[-2:] == modbus_crc(resp[:-2]):
                SERIAL_PORT = port
                print(f"[SER] Inverter found on {port}")
                return port
            else:
                print(f"[SER] {port}: no valid response (len={len(resp)})")
        except Exception as e:
            print(f"[SER] {port}: {e}")
            continue

    print("[SER] No inverter found. Check: USB connected? Correct SLAVE_ID?")
    return None

def _sim_read(reg: int) -> int:
    """Return sim_state value for a register address."""
    _map = {
        REG_SOC:    'soc',    REG_BAT_V:  'bat_v',  REG_BAT_I:  'bat_i',
        REG_BAT_P:  'bat_p',  REG_PV_V:   'pv1_v',  REG_PV_I:   'pv1_i',
        REG_PV_P:   'pv1_p',  REG_INV_V:  'inv_v',  REG_LOAD_I: 'load_i',
        REG_GRID_V: 'grid_v', REG_OUTPUT_PRI: 'output_priority', REG_BYPASS: 'bypass_enable',
        REGISTERS['pv2_voltage']['reg']:   'pv2_v',
        REGISTERS['pv2_current']['reg']:   'pv2_i',
        REGISTERS['pv2_power']['reg']:     'pv2_p',
        REGISTERS['grid_frequency']['reg']:            'grid_freq',
        REGISTERS['inverter_frequency']['reg']:        'inv_freq',
        REGISTERS['controller_temp']['reg']:           'controller_temp',
        REGISTERS['battery_temp']['reg']:              'battery_temp',
        REGISTERS['device_state']['reg']:              'device_state',
        REGISTERS['device_charge_state']['reg']:       'charge_state',
        REGISTERS['fault_bits_1']['reg']:              'fault_bits_1',
        REGISTERS['fault_bits_2']['reg']:              'fault_bits_2',
        REGISTERS['pv_power_generation_today']['reg']: 'pv_generation_today',
        REGISTERS['load_power_consumption_today']['reg']: 'load_consumption_today',
        REGISTERS['total_running_days']['reg']:        'running_days',
        REGISTERS['product_type']['reg']:              'product_type',
        REGISTERS['software_version_1']['reg']:        'software_version_1',
        REGISTERS['software_version_2']['reg']:        'software_version_2',
        REGISTERS['hardware_version_1']['reg']:        'hardware_version_1',
        REGISTERS['hardware_version_2']['reg']:        'hardware_version_2',
        REGISTERS['model_code']['reg']:                'model_code',
        REGISTERS['rs485_address']['reg']:             'rs485_address',
        REGISTERS['rs485_version']['reg']:             'rs485_version',
        REGISTERS['battery_type']['reg']:              'battery_type',
        REGISTERS['nominal_battery_capacity']['reg']:  'nominal_capacity',
        REGISTERS['system_voltage']['reg']:            'system_voltage',
        REGISTERS['load_phase_a_active_power']['reg']: 'load_p',
    }
    key = _map.get(reg)
    return sim_state.get(key, 0) if key else 0

def read_register(reg: int, signed: bool = False):
    """Read a single holding register. Uses serial lock for real hardware."""
    if SIMULATION:
        val = _sim_read(reg)
        if signed and val > 32767:
            val -= 65536
        return val

    port = find_serial_port()
    if not port:
        return None
    cmd = _build_read(reg, 1)
    with _serial_lock:
        try:
            with serial.Serial(port, BAUD, timeout=1) as s:
                if s.in_waiting:
                    s.read_all()
                s.write(cmd)
                time.sleep(0.12)
                resp = s.read_all()
            if len(resp) < 7 or resp[-2:] != modbus_crc(resp[:-2]):
                return None
            value = (resp[3] << 8) | resp[4]
            if signed and value > 32767:
                value -= 65536
            return value
        except Exception as e:
            print(f"[MODBUS] read 0x{reg:04X}: {e}")
            return None

def read_all_registers() -> dict:
    """
    Batch-read all telemetry registers in ONE serial session under lock.
    Much faster than individual read_register() calls during polling.
    """
    reads = [
        ('soc',       REG_SOC,      False),
        ('bat_v',     REG_BAT_V,    False),
        ('bat_i',     REG_BAT_I,    True),
        ('bat_p',     REG_BAT_P,    True),
        ('pv1_v',     REG_PV_V,     False),
        ('pv1_i',     REG_PV_I,     True),
        ('pv1_p',     REG_PV_P,     True),
        ('inv_v',     REG_INV_V,    False),
        ('load_i',    REG_LOAD_I,   True),
        ('load_pf',   REGISTERS['load_pf']['reg'],                   False),
        ('grid_v',    REG_GRID_V,   False),
        ('grid_freq', REGISTERS['grid_frequency']['reg'],            False),
        ('inv_freq',  REGISTERS['inverter_frequency']['reg'],        False),
        ('ctrl_temp', REGISTERS['controller_temp']['reg'],           False),
        ('bat_temp',  REGISTERS['battery_temp']['reg'],              False),
        ('dev_state', REGISTERS['device_state']['reg'],              False),
        ('chg_state', REGISTERS['device_charge_state']['reg'],       False),
        ('fault1',    REGISTERS['fault_bits_1']['reg'],              False),
        ('fault2',    REGISTERS['fault_bits_2']['reg'],              False),
        ('pv_today',  REGISTERS['pv_power_generation_today']['reg'], False),
        ('load_today',REGISTERS['load_power_consumption_today']['reg'], False),
        ('run_days',  REGISTERS['total_running_days']['reg'],        False),
    ]

    if SIMULATION:
        result = {}
        for key, reg, signed in reads:
            v = _sim_read(reg)
            if signed and v > 32767:
                v -= 65536
            result[key] = v
        return result

    port = find_serial_port()
    if not port:
        return {}

    result = {}
    with _serial_lock:
        try:
            with serial.Serial(port, BAUD, timeout=1) as s:
                def rd(reg, signed=False):
                    try:
                        if s.in_waiting: s.read_all()
                        s.write(_build_read(reg, 1))
                        time.sleep(0.15)
                        resp = s.read_all()
                        if len(resp) >= 7 and resp[-2:] == modbus_crc(resp[:-2]):
                            val = (resp[3] << 8) | resp[4]
                            if signed and val > 32767:
                                val -= 65536
                            return val
                        return None
                    except Exception:
                        return None

                result['soc']       = rd(REG_SOC)
                result['bat_v']     = rd(REG_BAT_V)
                result['bat_i']     = rd(REG_BAT_I,    True)
                result['bat_p']     = rd(REG_BAT_P,    True)
                result['pv1_v']     = rd(REG_PV_V)
                result['pv1_i']     = rd(REG_PV_I,     True)
                result['pv1_p']     = rd(REG_PV_P,     True)
                result['inv_v']     = rd(REG_INV_V)
                result['load_i']    = rd(REG_LOAD_I,   True)
                result['grid_v']    = rd(REG_GRID_V)
                result['grid_freq'] = rd(REGISTERS['grid_frequency']['reg'])
                result['inv_freq']  = rd(REGISTERS['inverter_frequency']['reg'])
                _raw_temp = rd(0x0103)  # BYTE register: high byte=ctrl, low byte=bat
                result['ctrl_temp'] = ((_raw_temp >> 8) & 0xFF) if _raw_temp is not None else None
                result['bat_temp']  = (_raw_temp & 0xFF) if _raw_temp is not None else None
                result['dev_state'] = rd(REGISTERS['device_state']['reg'])
                result['chg_state'] = rd(REGISTERS['device_charge_state']['reg'])
                result['fault1']    = rd(REGISTERS['fault_bits_1']['reg'])
                result['fault2']    = rd(REGISTERS['fault_bits_2']['reg'])
                result['load_pf']      = rd(REGISTERS['load_pf']['reg'])
                result['output_pri']   = rd(REG_OUTPUT_PRI)
                result['charge_pri']   = rd(REG_CHARGE_PRI)
                result['pv_today']     = rd(REGISTERS['pv_power_generation_today']['reg'])
                result['load_today']   = rd(REGISTERS['load_power_consumption_today']['reg'])
                result['mains_load']   = rd(REGISTERS['mains_load_kwh_today']['reg'])    # xF03D
                result['mains_charge'] = rd(REGISTERS['mains_charge_ah_today']['reg'])   # xF03C
                result['run_days']     = rd(REGISTERS['total_running_days']['reg'])

        except Exception as e:
            print(f"[MODBUS] read_all error: {e}")
    return result

# ── Inverter history registers (7-day, read on demand, cached 1h) ─────────────
_inverter_history_cache: dict = {}
_inverter_history_last_fetch = None

def read_inverter_history() -> dict:
    """
    Read all 7-day history registers from the inverter (xF000-xF03D range).
    Returns last 7 days + today with: pv_kwh, load_kwh, bat_charge_ah,
    bat_discharge_ah, mains_charge_ah, mains_load_kwh.
    Cached for 1 hour (these values only change daily).
    """
    global _inverter_history_cache, _inverter_history_last_fetch

    now = datetime.now(timezone.utc)
    if (_inverter_history_last_fetch and
            (now - _inverter_history_last_fetch).total_seconds() < 3600):
        return _inverter_history_cache

    # Register lists: index 0 = today-7 (oldest), index 6 = today-1 (most recent)
    pv_regs       = [0xF006, 0xF005, 0xF004, 0xF003, 0xF002, 0xF001, 0xF000]
    bat_ch_regs   = [0xF00D, 0xF00C, 0xF00B, 0xF00A, 0xF009, 0xF008, 0xF007]
    bat_dc_regs   = [0xF014, 0xF013, 0xF012, 0xF011, 0xF010, 0xF00F, 0xF00E]
    mains_ch_regs = [0xF01B, 0xF01A, 0xF019, 0xF018, 0xF017, 0xF016, 0xF015]
    load_regs     = [0xF022, 0xF021, 0xF020, 0xF01F, 0xF01E, 0xF01D, 0xF01C]
    mains_ld_regs = [0xF029, 0xF028, 0xF027, 0xF026, 0xF025, 0xF024, 0xF023]
    today_reg_map = {
        'pv':       0xF02F,
        'load':     0xF030,
        'bat_ch':   0xF02D,
        'bat_dc':   0xF02E,
        'mains_ch': 0xF03C,
        'mains_ld': 0xF03D,
    }

    if SIMULATION:
        # Return synthetic data in simulation mode
        today_date = datetime.now().date()
        days = []
        for i in range(8):
            d = today_date - timedelta(days=7-i)
            days.append({
                'date': str(d),
                'pv_kwh': round(1.5 + i * 0.3, 2),
                'load_kwh': round(3.5 + (i % 3) * 0.5, 2),
                'bat_charge_ah': 20 + i * 2,
                'bat_discharge_ah': 15 + i,
                'mains_charge_ah': 5 + i,
                'mains_load_kwh': round(0.5 + (i % 4) * 0.3, 2),
            })
        _inverter_history_cache = {'days': days, 'fetched': now.isoformat()}
        _inverter_history_last_fetch = now
        return _inverter_history_cache

    port = find_serial_port()
    if not port:
        return _inverter_history_cache

    raw = {}
    with _serial_lock:
        try:
            with serial.Serial(port, BAUD, timeout=1) as s:
                def rd(reg):
                    try:
                        if s.in_waiting: s.read_all()
                        s.write(_build_read(reg, 1))
                        time.sleep(0.15)
                        resp = s.read_all()
                        if len(resp) >= 7 and resp[-2:] == modbus_crc(resp[:-2]):
                            return (resp[3] << 8) | resp[4]
                        return None
                    except Exception:
                        return None

                for i, reg in enumerate(pv_regs):
                    raw[f'pv_{i}']       = rd(reg)
                for i, reg in enumerate(bat_ch_regs):
                    raw[f'bat_ch_{i}']   = rd(reg)
                for i, reg in enumerate(bat_dc_regs):
                    raw[f'bat_dc_{i}']   = rd(reg)
                for i, reg in enumerate(mains_ch_regs):
                    raw[f'mains_ch_{i}'] = rd(reg)
                for i, reg in enumerate(load_regs):
                    raw[f'load_{i}']     = rd(reg)
                for i, reg in enumerate(mains_ld_regs):
                    raw[f'mains_ld_{i}'] = rd(reg)
                for k, reg in today_reg_map.items():
                    raw[f'today_{k}']    = rd(reg)
        except Exception as e:
            print(f"[HISTORY] read error: {e}")

    today_date = datetime.now().date()
    days = []
    for i in range(7):
        d = today_date - timedelta(days=7 - i)
        pv_r   = raw.get(f'pv_{i}')
        ld_r   = raw.get(f'load_{i}')
        ml_r   = raw.get(f'mains_ld_{i}')
        days.append({
            'date':             str(d),
            'pv_kwh':           round(pv_r / 10, 2)  if pv_r  is not None else None,
            'load_kwh':         round(ld_r / 10, 2)  if ld_r  is not None else None,
            'bat_charge_ah':    raw.get(f'bat_ch_{i}'),
            'bat_discharge_ah': raw.get(f'bat_dc_{i}'),
            'mains_charge_ah':  raw.get(f'mains_ch_{i}'),
            'mains_load_kwh':   round(ml_r / 10, 2)  if ml_r  is not None else None,
        })
    # today
    t_pv = raw.get('today_pv')
    t_ld = raw.get('today_load')
    t_ml = raw.get('today_mains_ld')
    days.append({
        'date':             str(today_date),
        'pv_kwh':           round(t_pv / 10, 2)  if t_pv  is not None else None,
        'load_kwh':         round(t_ld / 10, 2)  if t_ld  is not None else None,
        'bat_charge_ah':    raw.get('today_bat_ch'),
        'bat_discharge_ah': raw.get('today_bat_dc'),
        'mains_charge_ah':  raw.get('today_mains_ch'),
        'mains_load_kwh':   round(t_ml / 10, 2)  if t_ml  is not None else None,
    })

    _inverter_history_cache = {'days': days, 'fetched': now.isoformat()}
    _inverter_history_last_fetch = now
    return _inverter_history_cache

def write_register(reg: int, value: int) -> bool:
    """Write a single holding register under lock."""
    if SIMULATION:
        if reg == REG_OUTPUT_PRI:
            sim_state['output_priority'] = value
        elif reg == REG_CHARGE_PRI:
            sim_state['charge_priority'] = value
        elif reg == REG_BYPASS:
            sim_state['bypass_enable'] = value
        print(f"[SIM] write 0x{reg:04X}={value}")
        return True

    port = find_serial_port()
    if not port:
        print(f"[MODBUS] write 0x{reg:04X}: no port")
        return False
    cmd = _build_write(reg, value)
    with _serial_lock:
        try:
            with serial.Serial(port, BAUD, timeout=1) as s:
                if s.in_waiting:
                    s.read_all()
                s.write(cmd)
                time.sleep(0.12)
                resp = s.read_all()
            if len(resp) >= 8 and resp[-2:] == modbus_crc(resp[:-2]):
                print(f"[MODBUS] write 0x{reg:04X}={value} OK")
                return True
            print(f"[MODBUS] write 0x{reg:04X}={value} bad response len={len(resp)}")
            return False
        except Exception as e:
            print(f"[MODBUS] write 0x{reg:04X}={value}: {e}")
            return False

def read_register_ascii(start_reg: int, count: int) -> str | None:
    """Read ASCII string from consecutive registers (serial number etc.)."""
    if SIMULATION:
        return sim_state.get('serial_number', 'SIM')
    port = find_serial_port()
    if not port:
        return None
    values = []
    with _serial_lock:
        try:
            with serial.Serial(port, BAUD, timeout=1) as s:
                for i in range(count):
                    if s.in_waiting:
                        s.read_all()
                    s.write(_build_read(start_reg + i, 1))
                    time.sleep(0.10)
                    resp = s.read_all()
                    if len(resp) >= 7 and resp[-2:] == modbus_crc(resp[:-2]):
                        values.append((resp[3] << 8) | resp[4])
                    else:
                        return None
        except Exception:
            return None
    chars = []
    for v in values:
        chars.extend([(v >> 8) & 0xFF, v & 0xFF])
    return ''.join(chr(c) for c in chars if c != 0).strip()

# -------------------------
# Octopus / price
# -------------------------

config_lock  = threading.Lock()
config = {
    "octopus_api_key":         "",
    "product_code":            PRODUCT_CODE,
    "tariff_code":             TARIFF_CODE,
    "min_soc":                 20,
    "max_soc":                 90,
    "max_cheap_slots":         8,
    "automation_enabled":      True,
    "expensive_threshold":     24.0,
    "tomorrow_api_key":        "",  # get a free key at tomorrow.io/home (500 calls/day)
    # Tariff type: "agile" (Octopus Agile API), "tibber" (Tibber), "pvpc" (Spain), "fixed" (Economy7/Go), "flat" (no time-of-use)
    "tariff_type":             "agile",
    "cheap_window_start":      0,     # hour (for fixed window, e.g. 0 = midnight)
    "cheap_window_end":        7,     # hour (for fixed window, e.g. 7 = 07:00)
    "cheap_price_fixed":       9.0,   # cheap rate for fixed window display
    "tibber_api_key":          "",    # Tibber personal access token
    # Localisation
    "timezone":                "Europe/London",  # IANA tz name, e.g. "America/New_York"
    "currency_symbol":         "p",              # p / ¢ / ct / €
}

prices_lock   = threading.Lock()
cached_prices: list = []
last_price_fetch = None
PRICES_CACHE_FILE = PRICES_CACHE_FILE_BASE

def save_prices_cache():
    try:
        with prices_lock:
            data = [{"start": p["start"].isoformat(), "end": p["end"].isoformat(), "price": p["price"]} for p in cached_prices]
            fetched = last_price_fetch.isoformat() if last_price_fetch else None
        os.makedirs(APP_DIR, exist_ok=True)
        with open(PRICES_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"fetched": fetched, "prices": data}, f)
        print(f"[CACHE] Saved {len(data)} prices to cache")
    except Exception as e:
        print(f"[CACHE] Save error: {e}")
        print(f"[CACHE] PRICES_CACHE_FILE={PRICES_CACHE_FILE}")

def load_prices_cache():
    global cached_prices, last_price_fetch
    try:
        if not os.path.exists(PRICES_CACHE_FILE):
            return False
        with open(PRICES_CACHE_FILE, "r") as f:
            data = json.load(f)
        fetched_str = data.get("fetched")
        if fetched_str:
            fetched = datetime.fromisoformat(fetched_str)
            age = (datetime.now(timezone.utc) - fetched).total_seconds()
            if age > 7200:  # 2 hours
                print("[CACHE] Price cache stale, will refresh")
                return False
        loaded = []
        for p in data.get("prices", []):
            loaded.append({
                "start": datetime.fromisoformat(p["start"]).astimezone(timezone.utc),
                "end":   datetime.fromisoformat(p["end"]).astimezone(timezone.utc),
                "price": p["price"]
            })
        with prices_lock:
            cached_prices = loaded
            last_price_fetch = datetime.fromisoformat(fetched_str) if fetched_str else None
        print(f"[CACHE] Loaded {len(loaded)} prices from cache")
        return True
    except Exception as e:
        print(f"[CACHE] Load error: {e}")
        return False

def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Decrypt sensitive fields
            for key in SENSITIVE_KEYS:
                if key in data and isinstance(data[key], str):
                    data[key] = _decrypt_value(data[key])
            with config_lock:
                config.update(data)
            print("[CFG] Loaded config.")
        except Exception as e:
            print("[CFG] Load error:", e)
    else:
        print("[CFG] Using default config.")

def save_config():
    with config_lock:
        raw = config.copy()
    # Sanitise: only keep JSON-serialisable primitives
    safe = {}
    for k, v in raw.items():
        if isinstance(v, (str, int, float, bool, type(None))):
            # Encrypt sensitive keys
            if k in SENSITIVE_KEYS and v and isinstance(v, str):
                safe[k] = _encrypt_value(v)
            else:
                safe[k] = v
        else:
            safe[k] = str(v)
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(safe, f, indent=2)
        # Atomic replace (works on Windows too)
        if os.path.exists(CONFIG_FILE):
            os.replace(tmp, CONFIG_FILE)
        else:
            os.rename(tmp, CONFIG_FILE)
        print("[CFG] Saved config.")
        return True, None
    except Exception as e:
        print(f"[CFG] Save error: {e} | APP_DIR={APP_DIR} | keys={list(safe.keys())}")
        return False, str(e)

load_config()
_update_local_tz()

def _update_prices_octopus():
    """Fetch half-hourly Agile prices from Octopus Energy API."""
    global cached_prices, last_price_fetch
    try:
        with config_lock:
            api_key      = config.get("octopus_api_key", "").strip()
            product_code = config.get("product_code", PRODUCT_CODE)
            tariff_code  = config.get("tariff_code", TARIFF_CODE)
        if not api_key:
            print("[OCTOPUS] No API key configured")
            return
        now = datetime.now(UK_TZ)
        periods = []
        session = requests.Session()
        session.trust_env = False
        for days_ahead in [0, 1]:
            date_str = (now + timedelta(days=days_ahead)).strftime("%Y-%m-%d")
            url = f"https://api.octopus.energy/v1/products/{product_code}/electricity-tariffs/{tariff_code}/standard-unit-rates/"
            params = {"period_from": f"{date_str}T00:00:00Z", "period_to": f"{date_str}T23:59:59Z", "page_size": 500}
            r = session.get(url, auth=(api_key, ''), params=params, timeout=15)
            print(f"[OCTOPUS] HTTP {r.status_code} for {date_str}")
            if r.status_code == 200:
                results = r.json().get('results', [])
                for result in results:
                    vf = datetime.fromisoformat(result['valid_from'].replace('Z', '+00:00')).astimezone(timezone.utc)
                    vt = datetime.fromisoformat(result['valid_to'].replace('Z', '+00:00')).astimezone(timezone.utc)
                    if int((vt - vf).total_seconds() / 60) != AGILE_SLOT_MINUTES:
                        continue
                    periods.append({'start': vf, 'end': vt, 'price': result['value_inc_vat']})
            else:
                print(f"[OCTOPUS] Error: {r.text[:200]}")
                if r.status_code == 401:
                    print("[OCTOPUS] Invalid API key!")
                    break
        periods.sort(key=lambda x: x['start'])
        with prices_lock:
            cached_prices    = periods
            last_price_fetch = datetime.now(timezone.utc)
        print(f"[OCTOPUS] Updated {len(periods)} slots")
        save_prices_cache()
    except Exception as e:
        print(f"[OCTOPUS] Error: {e}")


def _update_prices_tibber():
    """Fetch hourly spot prices from Tibber GraphQL API.
    Covers: Germany, Netherlands, Norway, Sweden, Finland, Denmark, Austria.
    Price unit: local currency/kWh × 100  (e.g. EUR/kWh → eurocents/kWh).
    """
    global cached_prices, last_price_fetch
    try:
        with config_lock:
            api_key = config.get("tibber_api_key", "").strip()
        if not api_key:
            print("[TIBBER] No API key configured")
            return

        query = """{ viewer { homes { currentSubscription { priceInfo {
            today    { total startsAt }
            tomorrow { total startsAt }
        }}}}}"""

        session = requests.Session()
        session.trust_env = False
        r = session.post(
            "https://api.tibber.com/v1-beta/gql",
            json={"query": query},
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=15,
        )
        if r.status_code != 200:
            print(f"[TIBBER] HTTP {r.status_code}: {r.text[:200]}")
            return

        homes = r.json().get("data", {}).get("viewer", {}).get("homes", [])
        if not homes:
            print("[TIBBER] No homes in API response — check token")
            return

        price_info = homes[0].get("currentSubscription", {}).get("priceInfo", {})
        raw = price_info.get("today", []) + price_info.get("tomorrow", [])

        periods = []
        for entry in raw:
            start = datetime.fromisoformat(entry["startsAt"]).astimezone(timezone.utc)
            price_cents = round(entry["total"] * 100, 4)   # EUR/kWh → ct/kWh
            # Tibber is hourly — split into two 30-min slots for compatibility
            mid = start + timedelta(minutes=30)
            end = start + timedelta(hours=1)
            periods.append({'start': start, 'end': mid,  'price': price_cents})
            periods.append({'start': mid,   'end': end,  'price': price_cents})

        periods.sort(key=lambda x: x['start'])
        with prices_lock:
            cached_prices    = periods
            last_price_fetch = datetime.now(timezone.utc)
        print(f"[TIBBER] Updated {len(periods)} slots ({len(raw)} hours)")
        save_prices_cache()
    except Exception as e:
        print(f"[TIBBER] Error: {e}")


def _update_prices_pvpc():
    """Fetch hourly PVPC spot prices from REE (Red Eléctrica de España).
    Free API, no key required. Price unit: €/MWh → divide by 10 to get ct/kWh.
    """
    global cached_prices, last_price_fetch
    try:
        session = requests.Session()
        session.trust_env = False
        periods = []
        now_local = datetime.now(UK_TZ)  # UK_TZ is set to Europe/Madrid by user
        for days_ahead in [0, 1]:
            day = now_local.date() + timedelta(days=days_ahead)
            url = "https://apidatos.ree.es/en/datos/mercados/precios-mercados-tiempo-real"
            params = {
                "start_date": f"{day}T00:00",
                "end_date":   f"{day}T23:59",
                "time_trunc": "hour",
            }
            r = session.get(url, params=params, timeout=15)
            print(f"[PVPC] HTTP {r.status_code} for {day}")
            if r.status_code != 200:
                continue
            data = r.json()
            # Find PVPC indicator (id=1001 or type contains PVPC)
            included = data.get("included", [])
            pvpc = next((i for i in included if "PVPC" in i.get("type", "").upper()
                         or i.get("id") == "1001"), None)
            if not pvpc:
                pvpc = included[0] if included else None
            if not pvpc:
                continue
            for val in pvpc.get("attributes", {}).get("values", []):
                dt_str = val.get("datetime", "")
                price_eur_mwh = val.get("value", 0)
                start = datetime.fromisoformat(dt_str).astimezone(timezone.utc)
                price_ct = round(price_eur_mwh / 10, 4)   # €/MWh → ct/kWh
                mid = start + timedelta(minutes=30)
                end = start + timedelta(hours=1)
                periods.append({'start': start, 'end': mid,  'price': price_ct})
                periods.append({'start': mid,   'end': end,  'price': price_ct})

        periods.sort(key=lambda x: x['start'])
        with prices_lock:
            cached_prices    = periods
            last_price_fetch = datetime.now(timezone.utc)
        print(f"[PVPC] Updated {len(periods)} slots")
        save_prices_cache()
    except Exception as e:
        print(f"[PVPC] Error: {e}")


def update_prices():
    """Route to the correct price API based on tariff_type setting."""
    with config_lock:
        tariff_type = config.get("tariff_type", "agile")
    if tariff_type == "agile":
        _update_prices_octopus()
    elif tariff_type == "tibber":
        _update_prices_tibber()
    elif tariff_type == "pvpc":
        _update_prices_pvpc()
    else:
        # fixed / flat — no price API needed
        print(f"[PRICE] Tariff '{tariff_type}' — no API fetch needed")

def get_price_now():
    now = datetime.now(timezone.utc)
    with prices_lock:
        for p in cached_prices:
            if p['start'] <= now < p['end']:
                return p['price']
    return None

def should_charge_now(price_now: float) -> tuple:
    """
    Slot-szűrő: alkalmas-e ez a slot töltésre?
    Egyszerű döntés: ár < cheap_threshold ÉS kell töltés (compute_required_slots > 0).
    Az ultra-cheap mindig True.
    """
    if price_now <= 0:
        return True, f"negative_price:{price_now:.2f}p"
    if price_now < ULTRA_CHEAP_THRESHOLD:
        return True, f"ultra_cheap:{price_now:.2f}p"
    with config_lock:
        threshold = float(config.get("expensive_threshold", 24.0))
    if price_now >= threshold:
        return False, f"above_threshold:{price_now:.1f}p>={threshold:.1f}p"
    return True, f"below_threshold:{price_now:.1f}p<{threshold:.1f}p"


def compute_cheap_slots():
    """
    Select the N cheapest charging slots where price < cheap_threshold.
    N = compute_required_slots() (based on battery SOC + consumption).

    Negative-price slots are always included regardless of n_needed.
    For fixed-window tariffs (Economy7/Go), generates synthetic slots from the configured window.
    For flat tariffs, always returns [] (no grid charging).
    """
    with config_lock:
        tariff_type  = config.get("tariff_type", "agile")
        threshold    = float(config.get("expensive_threshold", 24.0))
        win_start    = int(config.get("cheap_window_start", 0))
        win_end      = int(config.get("cheap_window_end", 7))
        fixed_price  = float(config.get("cheap_price_fixed", 9.0))

    n_slots = compute_required_slots()

    # ── Flat tariff: no time-of-use benefit, never charge from grid ──
    if tariff_type == "flat":
        with ems_lock:
            ems_state["slots_status"] = "flat tariff — maximising solar self-consumption"
        return []

    # ── Fixed window tariff (Economy7, Octopus Go, etc.) ─────────────
    if tariff_type == "fixed":
        now_utc = datetime.now(timezone.utc)
        now_uk  = now_utc.astimezone(UK_TZ)
        slots   = []
        for days_ahead in [0, 1]:
            base = now_uk.date() + timedelta(days=days_ahead)
            # window may span midnight (e.g. 23:00–07:00)
            if win_end <= win_start:
                ws = UK_TZ.localize(datetime.combine(base, datetime.min.time().replace(hour=win_start, minute=0, second=0)))
                we = UK_TZ.localize(datetime.combine(base + timedelta(days=1), datetime.min.time().replace(hour=win_end, minute=0, second=0)))
            else:
                ws = UK_TZ.localize(datetime.combine(base, datetime.min.time().replace(hour=win_start, minute=0, second=0)))
                we = UK_TZ.localize(datetime.combine(base, datetime.min.time().replace(hour=win_end, minute=0, second=0)))
            cur = ws
            while cur < we:
                slot_end = cur + timedelta(minutes=30)
                if slot_end.astimezone(timezone.utc) > now_utc:
                    slots.append({'start': cur.astimezone(timezone.utc),
                                  'end':   slot_end.astimezone(timezone.utc),
                                  'price': fixed_price})
                cur = slot_end
        if n_slots == 0:
            with ems_lock:
                ems_state["slots_status"] = "0 slots needed — battery/PV sufficient"
            return []
        result = slots[:n_slots]
        with ems_lock:
            ems_state["slots_status"] = f"{len(result)} slots selected (fixed window {win_start:02d}:00-{win_end:02d}:00)"
        print(f"[SLOTS] Fixed window: {len(result)} slots at {fixed_price}p (need={n_slots})")
        return result

    # ── Agile tariff: dynamic pricing from Octopus API ───────────────
    with prices_lock:
        price_copy = list(cached_prices)
    if not price_copy:
        with ems_lock:
            ems_state["slots_status"] = "no Octopus prices cached — check API key"
        return []

    now_utc      = datetime.now(timezone.utc)
    now_uk       = now_utc.astimezone(UK_TZ)
    tomorrow_end = (now_uk.replace(hour=23, minute=30, second=0, microsecond=0)
                    + timedelta(days=1)).astimezone(timezone.utc)

    candidates = [p for p in price_copy
                  if p['end'] > now_utc and p['start'] <= tomorrow_end]

    # Negative price: always include (grid pays us)
    negative = [p for p in candidates if p['price'] < 0]
    # Normal cheap: 0p to threshold — only if battery needs charging
    normal   = [p for p in candidates if 0 <= p['price'] < threshold]

    if n_slots == 0 and not negative:
        with ems_lock:
            ems_state["slots_status"] = "0 slots needed — battery/PV sufficient"
        print("[SLOTS] 0 slots needed")
        return []

    extra    = max(0, n_slots - len(negative))
    cheapest = negative + sorted(normal, key=lambda x: x['price'])[:extra]
    result   = sorted(cheapest, key=lambda x: x['start'])

    slot_prices = [f"{s['price']:.1f}p" for s in result]
    print(f"[SLOTS] {len(result)} slots (need={n_slots}, neg={len(negative)}): {slot_prices}")
    with ems_lock:
        ems_state["slots_status"] = f"{len(result)} slots selected"
    return result

# -------------------------
# Global state
# -------------------------

telemetry_lock = threading.Lock()
telemetry = {
    "timestamp": None, "last_good_poll": None, "poll_errors": 0,
    "soc": None, "bat_v": None, "bat_i": None, "bat_p": None,
    "pv1_v": None, "pv1_i": None, "pv1_p": None,
    "pv2_v": None, "pv2_i": None, "pv2_p": None,
    "inv_v": None, "load_i": None, "load_p": None, "load_pf": None,
    "grid_v": None, "grid_freq": None, "inv_freq": None,
    "controller_temp": None, "battery_temp": None,
    "device_state": None, "charge_state": None,
    "fault_bits_1": None, "fault_bits_2": None,
    "total_pv_generation": None, "total_load_consumption": None,
    "total_running_days": None, "price_now": None,
    "output_priority": None, "charge_priority_val": None,
    "mains_load_kwh_today": None, "mains_charge_ah_today": None,
}

ems_lock = threading.Lock()
ems_state = {
    "current_mode":         "UNKNOWN",
    "last_action":          None,
    "last_error":           None,
    "next_cheap_slot":      None,
    "cheap_slots":          [],
    "slots_status":         "initializing",
    "next_switch_time":     None,
    "control_mode":         "auto",
    "charge_mode":              "unknown",   # current E20F mode label
    "last_mode_change":         None,        # timestamp of last mode change
    "high_consumer_active":     False,       # Rule 1 state flag
    "high_consumer_entry_load": 0,           # load_p at HC entry (W)
    "bat_protect_active":       False,       # SOC low protection (SUB+PV-only)
}

last_log_time = None

# -------------------------
# EMS mode helpers
# ── E204 ONLY, exactly like dashboard.py ──
# cheap slot  → E204=3 (SBU)  Solar-Battery-Utility
# normal/exp  → E204=2 (SUB)  Solar-Utility-Battery
# -------------------------


def set_mode_protect(reason: str):
    """Akkuvédelem: E204=SUB(3) + E20F=PV-only(3) – grid adja a terhelést, NEM tölt."""
    ok = write_register(REG_OUTPUT_PRI, OUTPUT_SUB)   # E204=3: grid a terhelésre
    time.sleep(3)
    write_register(REG_CHARGE_PRI, MODE_PV_ONLY)      # E20F=3: grid nem tölt
    with ems_lock:
        ems_state["current_mode"] = "Protect – Grid Load Only"
        ems_state["charge_mode"]      = "PV-only"
        ems_state["last_mode_change"] = datetime.now().strftime("%a %d-%b %H:%M")
        ems_state["last_action"]  = f"{datetime.now()}: E204=SUB(3)+E20F=PV-only [{reason}] ok={ok}"

def set_mode_cheap(reason: str):
    """Olcsó slot: E204=SUB(3) + E20F=Hybrid(2) – grid tölti az akkumulátort."""
    ok = write_register(REG_OUTPUT_PRI, OUTPUT_SUB)   # E204=3
    time.sleep(3)
    write_register(REG_CHARGE_PRI, MODE_HYBRID)       # E20F=2: grid+PV tölt
    with ems_lock:
        ems_state["current_mode"] = "Cheap – Grid Charging"
        ems_state["charge_mode"]      = "Hybrid"
        ems_state["last_mode_change"] = datetime.now().strftime("%a %d-%b %H:%M")
        ems_state["last_action"]  = f"{datetime.now()}: E204=SUB(3)+E20F=Hybrid [{reason}] ok={ok}"

def set_mode_expensive(reason: str):
    """Drága slot: E204=SBU(2) + E20F=PV-only(3) – grid NEM tölt."""
    ok = write_register(REG_OUTPUT_PRI, OUTPUT_SBU)   # E204=2
    time.sleep(3)
    write_register(REG_CHARGE_PRI, MODE_PV_ONLY)      # E20F=3: csak PV tölt
    with ems_lock:
        if ems_state["current_mode"] != "Expensive – Solar/Battery":
            ems_state["last_mode_change"] = datetime.now().strftime("%a %d-%b %H:%M")
        ems_state["current_mode"] = "Expensive – Solar/Battery"
        ems_state["charge_mode"]      = "PV-only"
        ems_state["last_action"]  = f"{datetime.now()}: E204=SBU(2)+E20F=PV-only [{reason}] ok={ok}"

def set_charge_mode(mode: int, reason: str):
    """Write xE20F charge priority. Must be called AFTER a 3s delay from any E204 write."""
    ok = write_register(REG_CHARGE_PRI, mode)
    mode_name = {0: 'PV-preferred', 1: 'Mains-preferred', 2: 'Hybrid', 3: 'PV-only'}.get(mode, str(mode))
    with ems_lock:
        if ems_state["charge_mode"] != mode_name:
            ems_state["last_mode_change"] = datetime.now().strftime("%a %d-%b %H:%M")
        ems_state["charge_mode"]      = mode_name
        ems_state["last_action"]  = f"{datetime.now()}: E20F={mode_name} [{reason}] ok={ok}"

# -------------------------
# Telemetry polling + CSV logging
# -------------------------

def ensure_history_header():
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                "timestamp", "soc", "bat_v", "bat_i", "bat_p",
                "pv1_v", "pv1_i", "pv1_p", "pv2_v", "pv2_i", "pv2_p",
                "inv_v", "load_i", "load_p", "load_pf",
                "grid_v", "grid_freq", "inv_freq",
                "controller_temp", "battery_temp",
                "device_state", "charge_state",
                "fault_bits_1", "fault_bits_2",
                "total_pv_generation", "total_load_consumption", "total_running_days",
                "price_now"
            ])

def poll_telemetry_loop():
    global last_log_time
    ensure_history_header()
    _poll_fail = 0
    while True:
        now_utc = datetime.now(timezone.utc)
        try:
            r = read_all_registers()
            if not r or r.get('soc') is None:
                _poll_fail += 1
                if _poll_fail % 5 == 1:  # log every 5th failure, not every time
                    print(f"[POLL] WARNING: No SOC from inverter (fail #{_poll_fail}) — serial busy or disconnected?")
                time.sleep(2)
                continue
            _poll_fail = 0  # reset on success
            with telemetry_lock:
                telemetry["last_good_poll"] = now_utc.strftime("%H:%M:%S")
                telemetry["poll_errors"] = 0

            def v(key, divisor=1):
                raw = r.get(key)
                return (raw / divisor) if raw is not None else None

            with telemetry_lock:
                prev = telemetry.copy()
                def keep(tkey, new_val):
                    return new_val if new_val is not None else prev.get(tkey)

                telemetry["timestamp"]           = now_utc.strftime("%Y-%m-%d %H:%M:%S")
                telemetry["soc"]                 = keep("soc",           r.get('soc'))
                telemetry["bat_v"]               = keep("bat_v",         v('bat_v', 10))
                # Inverter convention: positive = discharging → negate to standard (positive = charging)
                _raw_bat_i = v('bat_i', 10)
                telemetry["bat_i"]               = keep("bat_i",         (-_raw_bat_i) if _raw_bat_i is not None else None)
                # bat_p: use register if non-zero, else calculate from V*I
                _reg_bat_p = r.get('bat_p')
                _bat_v_raw = r.get('bat_v')
                _bat_i_raw = r.get('bat_i')
                if _bat_v_raw is not None and _bat_i_raw is not None:
                    # signed: if bat_i_raw > 32767, it's negative
                    _bat_i_s = _bat_i_raw - 65536 if _bat_i_raw > 32767 else _bat_i_raw
                    # Negate: inverter positive = discharge, we want positive = charging
                    _calc_bat_p = round((_bat_v_raw / 10) * (-_bat_i_s / 10))
                elif _reg_bat_p and _reg_bat_p != 0:
                    _calc_bat_p = -_reg_bat_p  # also negate register value
                else:
                    _calc_bat_p = None
                telemetry["bat_p"]               = keep("bat_p",         _calc_bat_p)
                telemetry["pv1_v"]               = keep("pv1_v",         v('pv1_v', 10))
                telemetry["pv1_i"]               = keep("pv1_i",         v('pv1_i', 10))
                telemetry["pv1_p"]               = keep("pv1_p",         r.get('pv1_p'))
                telemetry["pv2_v"]               = keep("pv2_v",         None)
                telemetry["pv2_i"]               = keep("pv2_i",         None)
                telemetry["pv2_p"]               = keep("pv2_p",         None)
                telemetry["inv_v"]               = keep("inv_v",         v('inv_v', 10))
                telemetry["load_i"]              = keep("load_i",        v('load_i', 10))
                # load_p számítása mint dashboard.py: inverter_v * load_i
                _inv_v  = r.get('inv_v')
                _load_i = r.get('load_i')
                if _inv_v is not None and _load_i is not None:
                    _computed_load_p = round((_inv_v / 10) * (_load_i / 10))
                else:
                    _computed_load_p = None
                telemetry["load_p"]              = keep("load_p",        _computed_load_p)
                telemetry["load_pf"]             = keep("load_pf",       v('load_pf', 100))
                telemetry["grid_v"]              = keep("grid_v",        v('grid_v', 10))
                telemetry["grid_freq"]           = keep("grid_freq",     v('grid_freq', 100))
                telemetry["inv_freq"]            = keep("inv_freq",      v('inv_freq', 100))
                telemetry["controller_temp"]     = keep("controller_temp", r.get('ctrl_temp'))
                telemetry["battery_temp"]        = keep("battery_temp",    r.get('bat_temp'))
                telemetry["device_state"]        = keep("device_state",    r.get('dev_state'))
                telemetry["charge_state"]        = keep("charge_state",    r.get('chg_state'))
                telemetry["fault_bits_1"]        = keep("fault_bits_1",    r.get('fault1'))
                telemetry["fault_bits_2"]        = keep("fault_bits_2",    r.get('fault2'))
                telemetry["total_pv_generation"]    = keep("total_pv_generation",    v('pv_today',   10))
                telemetry["total_load_consumption"] = keep("total_load_consumption", v('load_today',  10))
                telemetry["mains_load_kwh_today"]   = keep("mains_load_kwh_today",   v('mains_load',  10))  # xF03D
                telemetry["mains_charge_ah_today"]  = keep("mains_charge_ah_today",  r.get('mains_charge'))  # xF03C
                telemetry["total_running_days"]     = keep("total_running_days",      r.get('run_days'))
                telemetry["output_priority"]        = keep("output_priority",         r.get('output_pri'))
                telemetry["charge_priority_val"]    = keep("charge_priority_val",     r.get('charge_pri'))

            # CSV every 5 minutes
            if last_log_time is None or (now_utc - last_log_time) >= timedelta(minutes=5):
                last_log_time = now_utc
                with telemetry_lock:
                    row = [
                        telemetry["timestamp"], telemetry["soc"],
                        telemetry["bat_v"], telemetry["bat_i"], telemetry["bat_p"],
                        telemetry["pv1_v"], telemetry["pv1_i"], telemetry["pv1_p"],
                        telemetry["pv2_v"], telemetry["pv2_i"], telemetry["pv2_p"],
                        telemetry["inv_v"], telemetry["load_i"], telemetry["load_p"], telemetry["load_pf"],
                        telemetry["grid_v"], telemetry["grid_freq"], telemetry["inv_freq"],
                        telemetry["controller_temp"], telemetry["battery_temp"],
                        telemetry["device_state"], telemetry["charge_state"],
                        telemetry["fault_bits_1"], telemetry["fault_bits_2"],
                        telemetry["total_pv_generation"], telemetry["total_load_consumption"],
                        telemetry["total_running_days"], telemetry["price_now"],
                    ]
                with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow(row)

            # Ár frissítése minden pollban (ne csak az EMS schedulerben)
            price_now = get_price_now()
            if price_now is not None:
                with telemetry_lock:
                    telemetry["price_now"] = price_now

        except Exception as e:
            print("[POLL] error:", e)

        time.sleep(5)

# -------------------------
# EMS scheduler loop
# -------------------------



# -------------------------
# Geo-location + config extras
# -------------------------

DAILY_FILE     = os.path.join(APP_DIR, "ems_daily.json")
OPTIMIZER_FILE = os.path.join(APP_DIR, "ems_optimizer.json")
BATTERY_KWH           = 4.1   # usable kWh (5.12 * 0.80)
PANEL_KWP             = 1.76  # 4 x 440W
ULTRA_CHEAP_THRESHOLD = 0.0   # p/kWh — free/zero price only (negative = always charge)

# UK átlagos napi besugárzás (kWh/m²/nap) havonta, borult égbolt nélkül
_UK_CLEAR_SKY_KWH = {1:0.6,2:1.2,3:2.2,4:3.5,5:4.8,6:5.5,7:5.2,8:4.5,9:3.0,10:1.8,11:0.8,12:0.5}

def _cloud_radiation_kwh(cloud_pct: float, month: int) -> float:
    """Felhőzetszázalék + hónap alapján becsüli a napi besugárzást (kWh/m²)."""
    clear = _UK_CLEAR_SKY_KWH.get(month, 2.0)
    factor = 1.0 - 0.75 * (max(0.0, min(100.0, cloud_pct)) / 100.0)
    return max(0.0, round(clear * factor, 2))

geo_lock = threading.Lock()
geo_state = {
    "lat": 53.07,   # Newark-on-Trent default
    "lon": -0.81,
    "city": "Newark-on-Trent",
    "source": "default",
}

def detect_location():
    """Try manual config first, then IP geolocation, fall back to NG24 4JH default."""
    global geo_state

    # 1. Manual override takes priority
    with config_lock:
        manual_lat  = config.get("manual_lat")
        manual_lon  = config.get("manual_lon")
        manual_city = config.get("manual_city", "")

    print(f"[GEO] detect_location called: manual_lat={manual_lat!r} manual_lon={manual_lon!r}")
    if manual_lat is not None and manual_lon is not None:
        with geo_lock:
            geo_state.update({
                "lat": float(manual_lat),
                "lon": float(manual_lon),
                "city": manual_city or f"{manual_lat:.2f},{manual_lon:.2f}",
                "source": "manual",
            })
        print(f"[GEO] Manual location: {geo_state['city']} ({manual_lat}, {manual_lon})")
        return

    # 2. IP geolocation
    try:
        session = requests.Session()
        session.trust_env = False
        r = session.get("https://ipapi.co/json/", timeout=8)
        if r.status_code == 200:
            d = r.json()
            lat = float(d.get("latitude", 53.07))
            lon = float(d.get("longitude", -0.81))
            city = d.get("city", "Unknown")
            with geo_lock:
                geo_state.update({"lat": lat, "lon": lon, "city": city, "source": "ipapi"})
            print(f"[GEO] IP located: {city} ({lat:.3f}, {lon:.3f})")
            with config_lock:
                config["lat"] = lat
                config["lon"] = lon
                config["city"] = city
            save_config()
    except Exception as e:
        print(f"[GEO] Fallback to default (network blocked?): {e}")
        with config_lock:
            saved_lat = config.get("lat")
            saved_lon = config.get("lon")
        if saved_lat and saved_lon:
            with geo_lock:
                geo_state["lat"] = saved_lat
                geo_state["lon"] = saved_lon
                geo_state["source"] = "saved"

# -------------------------
# Open-Meteo weather forecast
# -------------------------

weather_lock = threading.Lock()
weather_state = {
    "last_fetch": None,
    "tomorrow_cloud_avg": None,
    "tomorrow_radiation_kwh": None,
    "tomorrow_pv_estimate_kwh": None,
    "today_cloud_avg": None,
    "current_cloud": None,
    "current_radiation": None,
    "hourly_cloud": {},
    "hourly_radiation": {},
    "forecast_days": [],
}

def fetch_weather():
    """Fetch weather from Open-Meteo (free, no API key, hourly GHI + cloud cover)."""
    with geo_lock:
        lat = geo_state["lat"]
        lon = geo_state["lon"]
    if lat is None or lon is None:
        print("[WEATHER] No location available yet")
        return
    try:
        url    = "https://api.open-meteo.com/v1/forecast"
        params = {
            "latitude":      lat,
            "longitude":     lon,
            "hourly":        "shortwave_radiation,cloud_cover",
            "daily":         "sunrise,sunset",
            "timezone":      "UTC",
            "forecast_days": 3,
        }
        session = requests.Session()
        session.trust_env = False
        r = session.get(url, params=params, timeout=20)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        d = r.json()

        hourly_times  = d["hourly"]["time"]             # ["2026-03-17T00:00", ...]  UTC
        hourly_rad    = d["hourly"]["shortwave_radiation"]  # W/m²
        hourly_cloud  = d["hourly"]["cloud_cover"]          # 0-100 %
        daily_times   = d["daily"]["time"]              # ["2026-03-17", ...]
        daily_sunrise = d["daily"]["sunrise"]           # UTC ISO strings
        daily_sunset  = d["daily"]["sunset"]

        now_uk       = datetime.now(UK_TZ)
        today_str    = now_uk.strftime("%Y-%m-%d")
        tomorrow_str = (now_uk + timedelta(days=1)).strftime("%Y-%m-%d")

        # ── Build hourly lookup dicts (key = UK local "YYYY-MM-DDTHH:00") ──
        hourly_cloud_dict = {}
        hourly_rad_dict   = {}
        for i, t_str in enumerate(hourly_times):
            # Open-Meteo UTC naive strings e.g. "2026-03-17T06:00"
            t_utc = datetime.fromisoformat(t_str).replace(tzinfo=timezone.utc)
            t_uk  = t_utc.astimezone(UK_TZ)
            key   = t_uk.strftime("%Y-%m-%dT%H:00")
            hourly_cloud_dict[key] = float(hourly_cloud[i] or 0)
            hourly_rad_dict[key]   = float(hourly_rad[i]   or 0)

        # ── Per-day aggregates from hourly data ────────────────────────
        def get_day_stats(day_str):
            vals_rad   = [v for k, v in hourly_rad_dict.items()   if k.startswith(day_str)]
            vals_cloud = [v for k, v in hourly_cloud_dict.items() if k.startswith(day_str)]
            cloud_avg = round(sum(vals_cloud) / len(vals_cloud), 1) if vals_cloud else 50.0
            # Sum hourly W/m² → daily kWh/m² (each value = 1 h of irradiance)
            rad_kwh   = round(sum(vals_rad) / 1000, 2) if vals_rad else 0.0
            return cloud_avg, rad_kwh

        # Sunrise/sunset lookup by date string
        day_sr = {daily_times[i]: daily_sunrise[i] for i in range(len(daily_times))}
        day_ss = {daily_times[i]: daily_sunset[i]  for i in range(len(daily_times))}

        today_cloud,    today_rad    = get_day_stats(today_str)
        tomorrow_cloud, tomorrow_rad = get_day_stats(tomorrow_str)

        # ── Update optimizer solar window from sunrise/sunset ─────────
        t_sr = day_sr.get(tomorrow_str)
        t_ss = day_ss.get(tomorrow_str)
        if t_sr and t_ss:
            try:
                sr_uk = datetime.fromisoformat(t_sr).replace(tzinfo=timezone.utc).astimezone(UK_TZ)
                ss_uk = datetime.fromisoformat(t_ss).replace(tzinfo=timezone.utc).astimezone(UK_TZ)
                opt_now = load_optimizer()
                opt_now["solar_start_hour"] = sr_uk.hour
                opt_now["solar_end_hour"]   = ss_uk.hour
                save_optimizer(opt_now)
            except Exception:
                pass

        # ── PV estimate ───────────────────────────────────────────────
        pv_scale = 0.35
        try:
            if os.path.exists(OPTIMIZER_FILE):
                with open(OPTIMIZER_FILE, "r") as f:
                    opt_r = json.load(f)
                pv_scale = opt_r.get("pv_scale_factor", 0.35)
        except Exception:
            pass

        tomorrow_pv = round(tomorrow_rad * PANEL_KWP * pv_scale, 2)

        # ── Build forecast_days (today + next 2 days) ─────────────────
        forecast_days = []
        for d_str in daily_times[:3]:
            c, rad = get_day_stats(d_str)
            forecast_days.append({
                "date":            d_str,
                "cloud_avg":       c,
                "radiation_kwh":   rad,
                "pv_estimate_kwh": round(rad * PANEL_KWP * pv_scale, 2),
            })

        # ── Current hour ──────────────────────────────────────────────
        cur_key   = now_uk.strftime("%Y-%m-%dT%H:00")
        cur_cloud = hourly_cloud_dict.get(cur_key)
        cur_rad   = hourly_rad_dict.get(cur_key)

        with weather_lock:
            weather_state.update({
                "last_fetch":               datetime.now(timezone.utc).isoformat(),
                "error":                    None,
                "today_cloud_avg":          today_cloud,
                "tomorrow_cloud_avg":       tomorrow_cloud,
                "tomorrow_radiation_kwh":   tomorrow_rad,
                "tomorrow_pv_estimate_kwh": tomorrow_pv,
                "forecast_days":            forecast_days,
                "current_cloud":            cur_cloud,
                "current_radiation":        cur_rad,
                "hourly_cloud":             hourly_cloud_dict,
                "hourly_radiation":         hourly_rad_dict,
            })
        print(f"[WEATHER] open-meteo OK | Now: cloud={cur_cloud}% rad={cur_rad}W/m² | "
              f"Tomorrow: cloud={tomorrow_cloud:.0f}% PV≈{tomorrow_pv:.2f}kWh")

    except Exception as e:
        err_msg = str(e)
        print(f"[WEATHER] Error: {err_msg}")
        with weather_lock:
            weather_state["error"] = err_msg
            weather_state["last_fetch"] = datetime.now(timezone.utc).isoformat()

# -------------------------
# Daily summary + learning
# -------------------------

def integrate_today_from_csv() -> dict:
    """
    CSV-ből trapéz-integráció: pv1_p, bat_p, load_p.
    grid_kwh = energiamérleg: load + bat_charge - pv - bat_discharge
    Returns: {"pv_kwh", "load_kwh", "grid_kwh", "bat_charge_kwh", "bat_discharge_kwh"}
    Üres dict ha nincs elég adat.
    """
    if not os.path.exists(HISTORY_FILE):
        return {}
    today_str = datetime.now(UK_TZ).strftime("%Y-%m-%d")
    pv_kwh = load_kwh = bat_ch = bat_dis = 0.0
    prev_ts = None
    count = 0
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    ts_str = row.get("timestamp", "")
                    if not ts_str:
                        continue
                    ts = datetime.fromisoformat(ts_str)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if ts.astimezone(UK_TZ).strftime("%Y-%m-%d") != today_str:
                        prev_ts = None
                        continue
                    pv_w   = float(row["pv1_p"]) if row.get("pv1_p", "") != "" else 0
                    bat_w  = float(row["bat_p"])  if row.get("bat_p",  "") != "" else 0
                    load_w = float(row["load_p"]) if row.get("load_p", "") != "" else 0
                    if prev_ts is not None:
                        h = (ts - prev_ts).total_seconds() / 3600
                        if 0 < h <= 0.25:
                            pv_kwh   += max(0, pv_w)   * h / 1000
                            load_kwh += max(0, load_w)  * h / 1000
                            bat_ch   += max(0, bat_w)   * h / 1000
                            bat_dis  += max(0, -bat_w)  * h / 1000
                            count += 1
                    prev_ts = ts
                except Exception:
                    continue
    except Exception as e:
        print(f"[CSV] integrate error: {e}")
        return {}
    if count < 3:
        return {}
    # Grid import = energiamérleg: amit a hálózatról vettünk
    grid_kwh = max(0.0, load_kwh + bat_ch - pv_kwh - bat_dis)
    return {
        "pv_kwh":            round(pv_kwh,   3),
        "load_kwh":          round(load_kwh,  3),
        "grid_kwh":          round(grid_kwh,  3),
        "bat_charge_kwh":    round(bat_ch,    3),
        "bat_discharge_kwh": round(bat_dis,   3),
    }

def load_daily_records() -> list:
    if not os.path.exists(DAILY_FILE):
        return []
    try:
        with open(DAILY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[DAILY] Load error: {e}")
        return []

def save_daily_records(records: list):
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(DAILY_FILE, "w", encoding="utf-8") as f:
            json.dump(records[-90:], f, indent=2)
    except Exception as e:
        print(f"[DAILY] Save error: {e}")

def load_optimizer() -> dict:
    defaults = {
        "pv_scale_factor": 0.35,
        "avg_daily_consumption_kwh": 5.0,
        "avg_daily_pv_kwh": 2.0,
        "charge_kwh_per_slot": 1.25,
        "days_of_data": 0,
        "last_update": None,
        # Cloud-bucket PV yield: learned kWh per kWp per day, keyed by cloud% band
        # Populated after enough history. Falls back to radiation*scale if empty.
        "pv_yield_by_cloud": {},
        # Prediction accuracy: how far off our PV forecasts have been on average
        "pv_prediction_mae_kwh": None,
    }
    if not os.path.exists(OPTIMIZER_FILE):
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            with open(OPTIMIZER_FILE, "w", encoding="utf-8") as f:
                json.dump(defaults, f, indent=2)
            print(f"[OPT] Created: {OPTIMIZER_FILE}")
        except Exception as e:
            print(f"[OPT] v4 CANNOT CREATE: {OPTIMIZER_FILE} | APP_DIR={APP_DIR} | err={e}")
        return defaults
    try:
        with open(OPTIMIZER_FILE, "r") as f:
            d = json.load(f)
        defaults.update(d)
        return defaults
    except Exception:
        return defaults

def save_optimizer(opt: dict):
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(OPTIMIZER_FILE, "w", encoding="utf-8") as f:
            json.dump(opt, f, indent=2)
    except Exception as e:
        print(f"[OPT] Save error: {e}")

def record_daily_summary():
    """
    Called at 22:00 - saves today's summary to ems_daily.json
    and updates the optimizer with learned parameters.
    """
    now_uk = datetime.now(UK_TZ)
    today_str = now_uk.strftime("%Y-%m-%d")

    with telemetry_lock:
        soc_now   = telemetry.get("soc")
        pv_today  = telemetry.get("total_pv_generation")   # kWh
        load_today= telemetry.get("total_load_consumption") # kWh

    with weather_lock:
        cloud_avg     = weather_state.get("today_cloud_avg")
        forecast_days = weather_state.get("forecast_days", [])
        tomorrow_pv_pred = weather_state.get("tomorrow_pv_estimate_kwh")

    # Get TODAY's actual radiation from forecast_days (index 0 = today)
    today_radiation_kwh = None
    for fd in forecast_days:
        if fd.get("date") == today_str:
            today_radiation_kwh = fd.get("radiation_kwh")
            break

    records = load_daily_records()

    # Find today's morning SOC from records (first entry of today if exists)
    morning_soc = None
    for rec in records:
        if rec.get("date") == today_str and rec.get("morning_soc") is not None:
            morning_soc = rec["morning_soc"]
            break

    # Remove existing today record if any (we'll replace it)
    records = [r for r in records if r.get("date") != today_str]

    new_record = {
        "date":              today_str,
        "pv_kwh":            pv_today,
        "consumption_kwh":   load_today,
        "evening_soc":       soc_now,
        "morning_soc":       morning_soc,
        "cloud_avg":         cloud_avg,
        "radiation_kwh":     today_radiation_kwh,   # actual measured radiation today
        "pv_predicted_kwh":  tomorrow_pv_pred,       # what we forecast for *tomorrow* tonight
        "cheap_slots_used":  None,                   # filled by scheduler
    }
    records.append(new_record)
    save_daily_records(records)
    print(f"[DAILY] Recorded {today_str}: PV={pv_today} kWh, Load={load_today} kWh, "
          f"SOC={soc_now}%, radiation={today_radiation_kwh} kWh/m²")

    # Update optimizer with rolling averages (last 14 days)
    update_optimizer_learning(records)

def _cloud_bucket(cloud_pct: float) -> str:
    """Return the cloud-coverage bucket key for a given cloud percentage."""
    if cloud_pct < 25:   return "0-25"
    elif cloud_pct < 50: return "25-50"
    elif cloud_pct < 75: return "50-75"
    else:                return "75-100"

def _cloud_based_pv_estimate(cloud_pct: float, opt: dict) -> float | None:
    """
    Return learned PV estimate (kWh) for tomorrow based on cloud % bucket.
    Returns None if not enough data for that bucket yet.
    """
    yields = opt.get("pv_yield_by_cloud", {})
    if not yields:
        return None
    bucket = _cloud_bucket(cloud_pct)
    yield_per_kwp = yields.get(bucket)
    if yield_per_kwp is None:
        return None
    return round(yield_per_kwp * PANEL_KWP, 2)

def update_optimizer_learning(records: list):
    """
    Update rolling averages and per-cloud-bucket PV yields from last 14 days.

    Three learning layers:
      1. Rolling avg PV + consumption (simple baselines)
      2. pv_scale_factor: calibrated from actual radiation vs actual PV
         (replaces the old hardcoded 8.0 MJ/m² assumption)
      3. pv_yield_by_cloud: kWh/kWp per cloud-bucket (0-25/25-50/50-75/75-100 %)
         so predictions adapt to real-world conditions, not just theory
      4. pv_prediction_mae_kwh: mean absolute error of yesterday's PV forecast
         vs today's actual — used as a safety margin in slot decisions
    """
    valid = [r for r in records
             if r.get("pv_kwh") is not None
             and r.get("consumption_kwh") is not None]
    recent = valid[-14:]

    if len(recent) < 2:
        print(f"[OPT] Not enough data yet ({len(recent)} days), skipping learning")
        return

    opt = load_optimizer()

    # ── Layer 1: rolling averages ─────────────────────────────────────
    avg_pv   = sum(r["pv_kwh"] for r in recent) / len(recent)
    avg_cons = sum(r["consumption_kwh"] for r in recent) / len(recent)
    opt["avg_daily_pv_kwh"]            = round(avg_pv, 2)
    opt["avg_daily_consumption_kwh"]   = round(avg_cons, 2)
    opt["days_of_data"]                = len(valid)
    opt["last_update"]                 = datetime.now(UK_TZ).isoformat()

    # ── Layer 2: pv_scale_factor from actual radiation ────────────────
    # Days where we have both actual radiation AND actual PV
    rad_days = [r for r in recent
                if r.get("radiation_kwh") and r.get("radiation_kwh", 0) > 0
                and r.get("pv_kwh", 0) > 0]
    if rad_days:
        # Actual scale = what fraction of theoretical we really got
        scales = [r["pv_kwh"] / (r["radiation_kwh"] * PANEL_KWP) for r in rad_days]
        new_scale = sum(scales) / len(scales)
        # EMA: 25% weight on new data each learning cycle
        opt["pv_scale_factor"] = round(
            opt["pv_scale_factor"] * 0.75 + new_scale * 0.25, 3
        )
        opt["pv_scale_factor"] = max(0.05, min(0.95, opt["pv_scale_factor"]))
        print(f"[OPT] pv_scale calibrated: {new_scale:.3f} → stored {opt['pv_scale_factor']:.3f} "
              f"(from {len(rad_days)} days with radiation data)")

    # ── Layer 3: cloud-bucket yield learning ─────────────────────────
    # Group days by cloud% → learn kWh/kWp for each sky condition
    cloud_days = [r for r in recent
                  if r.get("cloud_avg") is not None and r.get("pv_kwh", 0) > 0]
    if cloud_days:
        bucket_samples: dict[str, list[float]] = {}
        for r in cloud_days:
            b = _cloud_bucket(r["cloud_avg"])
            bucket_samples.setdefault(b, []).append(r["pv_kwh"] / PANEL_KWP)

        yields = opt.get("pv_yield_by_cloud", {})
        for bucket, samples in bucket_samples.items():
            new_yield = sum(samples) / len(samples)
            old_yield = yields.get(bucket, new_yield)
            # EMA: 30% weight on new observations
            yields[bucket] = round(old_yield * 0.70 + new_yield * 0.30, 3)
        opt["pv_yield_by_cloud"] = yields
        print(f"[OPT] Cloud-bucket yields updated: { {k: f'{v:.2f}' for k,v in yields.items()} }")

    # ── Layer 4: prediction accuracy (MAE) ───────────────────────────
    # Compare yesterday's PV prediction (stored as "pv_predicted_kwh" two days ago)
    # with today's actual PV. We use consecutive pairs: record[n] predicted record[n+1].
    errors = []
    for i in range(len(recent) - 1):
        pred = recent[i].get("pv_predicted_kwh")
        actual = recent[i + 1].get("pv_kwh")
        if pred is not None and actual is not None:
            errors.append(abs(pred - actual))
    if errors:
        mae = sum(errors) / len(errors)
        old_mae = opt.get("pv_prediction_mae_kwh") or mae
        opt["pv_prediction_mae_kwh"] = round(old_mae * 0.7 + mae * 0.3, 3)
        print(f"[OPT] PV forecast MAE: {opt['pv_prediction_mae_kwh']:.2f} kWh "
              f"(from {len(errors)} pairs)")

    # ── Layer 5: weekday hourly consumption patterns ──────────────────
    patterns = analyze_hourly_patterns()
    if patterns.get("weekday_hourly_load_w"):
        opt["weekday_hourly_load_w"] = patterns["weekday_hourly_load_w"]
        opt["solar_start_hour"]      = patterns.get("typical_solar_start", 7)
        print(f"[OPT] Weekday patterns saved, solar starts at {opt['solar_start_hour']}:00")

    # ── Layer 6: inverter register history (pontosabb mint CSV) ───────────
    # Az inverter saját registerei megbízhatóbbak a load_p CSV integrálásnál.
    # Frissíti az átlag PV, fogyasztás, hálózati import értékeket.
    inv_hist_days = _inverter_history_cache.get('days', [])
    if len(inv_hist_days) >= 3:
        # Kizárjuk a mai (részleges) napot — csak teljes napok
        full_days = [d for d in inv_hist_days[:-1] if d.get('pv_kwh') is not None][-7:]
        if full_days:
            pv_vals    = [d['pv_kwh']         for d in full_days if (d.get('pv_kwh')         or 0) > 0]
            load_vals  = [d['load_kwh']        for d in full_days if (d.get('load_kwh')        or 0) > 0]
            mains_vals = [d['mains_load_kwh']  for d in full_days if d.get('mains_load_kwh') is not None]

            if pv_vals:
                opt['avg_daily_pv_kwh'] = round(sum(pv_vals) / len(pv_vals), 2)
            if load_vals:
                opt['avg_daily_consumption_kwh'] = round(sum(load_vals) / len(load_vals), 2)
            if mains_vals:
                opt['avg_mains_kwh_7d'] = round(sum(mains_vals) / len(mains_vals), 2)
                avg_load_r = opt.get('avg_daily_consumption_kwh', 5.0)
                if avg_load_r > 0:
                    self_suff = max(0.0, 1.0 - opt['avg_mains_kwh_7d'] / avg_load_r) * 100
                    opt['self_sufficiency_pct'] = round(self_suff, 1)
            # Ha a days_of_data még 0 (nincs CSV history), de az inverter register
            # history elég napot tartalmaz → Phase 2-t aktiváljuk
            if not opt.get("days_of_data") and len(full_days) >= 2:
                opt["days_of_data"] = len(full_days)
                print(f"[OPT] Layer6: days_of_data={len(full_days)} (from inverter history, Phase 2 active)")
            print(f"[OPT] Register history: pv={opt.get('avg_daily_pv_kwh', 0):.2f} kWh "
                  f"load={opt.get('avg_daily_consumption_kwh', 0):.2f} kWh "
                  f"mains={opt.get('avg_mains_kwh_7d', '?')} kWh/day "
                  f"self-suff={opt.get('self_sufficiency_pct','?')}% "
                  f"days={opt.get('days_of_data',0)}")

    save_optimizer(opt)
    print(f"[OPT] Learned: avg_pv={opt.get('avg_daily_pv_kwh',0):.2f} kWh, "
          f"avg_cons={opt.get('avg_daily_consumption_kwh',0):.2f} kWh, "
          f"avg_mains={opt.get('avg_mains_kwh_7d','?')} kWh, "
          f"days={len(valid)}, scale={opt['pv_scale_factor']:.3f}")


def analyze_hourly_patterns() -> dict:
    """
    Read CSV history and build hourly PV/load patterns, including per-weekday
    consumption profiles (so Saturday heavy-wash loads appear separately from
    a quiet Tuesday morning).

    Returns dict with:
      - hourly_pv_avg[h]               average PV power by hour (W)
      - hourly_load_avg[h]             average load by hour (W)
      - weekday_hourly_load_w[wd][h]   per-weekday average load (W),
                                        wd=0 Mon … 6 Sun, h=0..23
      - typical_solar_start/end/peak
    """
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        from collections import defaultdict
        hourly_pv   = defaultdict(list)
        hourly_load = defaultdict(list)
        # weekday (0-6) → hour (0-23) → [W samples]
        wd_load: dict = defaultdict(lambda: defaultdict(list))
        cutoff = datetime.now(timezone.utc) - timedelta(days=60)  # 60 days for weekly patterns

        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    ts_str = row.get("timestamp", "")
                    if not ts_str:
                        continue
                    ts = datetime.fromisoformat(ts_str)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if ts < cutoff:
                        continue
                    ts_uk   = ts.astimezone(UK_TZ)
                    hour    = ts_uk.hour
                    weekday = ts_uk.weekday()   # 0=Mon, 6=Sun
                    pv   = float(row["pv1_p"]) if row.get("pv1_p") and row["pv1_p"] != "" else None
                    load = float(row["load_p"]) if row.get("load_p") and row["load_p"] != "" else None
                    if pv   is not None: hourly_pv[hour].append(pv)
                    if load is not None:
                        hourly_load[hour].append(load)
                        wd_load[weekday][hour].append(load)
                except Exception:
                    continue

        avg_pv   = {h: round(sum(v)/len(v)) for h, v in hourly_pv.items()   if v}
        avg_load = {h: round(sum(v)/len(v)) for h, v in hourly_load.items() if v}

        # Per-weekday averages (string keys so JSON round-trips cleanly)
        wd_avg: dict = {}
        for wd, hours in wd_load.items():
            wd_avg[str(wd)] = {str(h): round(sum(v)/len(v)) for h, v in hours.items() if v}

        solar_hours = [h for h, w in avg_pv.items() if w > 50]
        result = {
            "hourly_pv_avg":            avg_pv,
            "hourly_load_avg":          avg_load,
            "weekday_hourly_load_w":    wd_avg,
            "typical_solar_start":      min(solar_hours) if solar_hours else 7,
            "typical_solar_end":        max(solar_hours) if solar_hours else 18,
            "peak_solar_hour":          max(avg_pv, key=avg_pv.get) if avg_pv else 12,
            "data_points":              sum(len(v) for v in hourly_pv.values()),
        }
        print(f"[HOURLY] Solar {result['typical_solar_start']}:00-{result['typical_solar_end']}:00, "
              f"peak at {result['peak_solar_hour']}:00, "
              f"{result['data_points']} data points, "
              f"{len(wd_avg)} weekdays learned")
        return result
    except Exception as e:
        print(f"[HOURLY] Error: {e}")
        return {}

def compute_dynamic_target_soc() -> tuple:
    """
    Calculate the battery charge target dynamically, based on learned
    per-weekday hourly consumption patterns.

    Logic:
      - Find the hours from NOW until the sun rises tomorrow (solar_start_hour).
      - For each of those hours, look up the learned average load for
        that weekday + hour combination.
      - Sum the expected energy use, add 15 % safety margin.
      - Convert to a target SOC %, clamped to [min_soc, hard_max_soc].

    Falls back to hard_max_soc when patterns are not yet available.
    Returns (target_soc_pct: float, reason: str)
    """
    opt = load_optimizer()
    with config_lock:
        min_soc  = int(config.get("min_soc", 20))
        hard_max = int(config.get("max_soc", 95))   # absolute ceiling

    wd_patterns  = opt.get("weekday_hourly_load_w", {})
    solar_start  = int(opt.get("solar_start_hour", 7))
    avg_cons_kwh = opt.get("avg_daily_consumption_kwh", 5.0)
    fallback_w   = avg_cons_kwh / 24 * 1000  # average W per hour

    if not wd_patterns:
        # No pattern yet: estimate overnight need from avg consumption
        # (19:00–07:00 = 12h, ~50% of daily consumption)
        overnight_kwh = avg_cons_kwh * 0.55   # 55% of daily as overnight estimate
        target_soc = (overnight_kwh * 1.1 / BATTERY_KWH) * 100
        target_soc = max(float(min_soc), min(float(hard_max), target_soc))
        return round(target_soc, 1), f"overnight-estimate({overnight_kwh:.1f}kWh→{target_soc:.0f}%)"

    now_uk       = datetime.now(UK_TZ)
    total_kwh    = 0.0
    current      = now_uk.replace(minute=0, second=0, microsecond=0)
    steps        = 0

    while steps < 24:
        wd_key = str(current.weekday())
        hr_key = str(current.hour)
        load_w = (wd_patterns.get(wd_key) or {}).get(hr_key) or fallback_w
        total_kwh += load_w / 1000  # kWh this hour
        current += timedelta(hours=1)
        steps   += 1
        # Stop once we reach solar_start on the next (or a future) day
        if current.date() > now_uk.date() and current.hour >= solar_start:
            break

    needed_kwh = total_kwh * 1.10   # +10% margin (was 15%)
    target_soc = (needed_kwh / BATTERY_KWH) * 100
    # Cap at 75% max — don't speculate, solar will handle the rest tomorrow
    savings_max = min(float(hard_max), 75.0)
    target_soc = max(float(min_soc), min(savings_max, target_soc))

    tomorrow_name = (now_uk + timedelta(days=1)).strftime("%A")
    reason = (f"pattern({tomorrow_name},{steps}h,"
              f"{total_kwh:.1f}kWh+15%={needed_kwh:.1f}kWh→{target_soc:.0f}%)")
    print(f"[TARGET] Dynamic SOC target: {target_soc:.0f}% — {reason}")
    return round(target_soc, 1), reason


def compute_required_slots() -> int:
    """
    Decides how many cheap 30-min charging slots are needed.

    Phase 1 – No data yet (days < 2):
        Only live SOC is known. Just fill the battery to target_soc.
        slots = ceil((target_soc - soc_now) / kWh_per_slot)

    Phase 2 – Data available (days >= 2):
        Use learned consumption + learned PV + tomorrow weather forecast.
        gap = (target - current) + expected_consumption - expected_pv
        slots = ceil(gap / kWh_per_slot)
    """
    opt = load_optimizer()
    days = opt.get("days_of_data", 0)

    with telemetry_lock:
        soc_now = telemetry.get("soc") or 50

    with config_lock:
        min_soc  = int(config.get("min_soc", 20))
        hard_max = int(config.get("max_soc", 95))   # absolute ceiling, never exceeded

    soc_now_kwh     = BATTERY_KWH * (soc_now / 100.0)
    charge_per_slot = opt.get("charge_kwh_per_slot", 1.25)

    if days < 2:
        # ── Phase 1: no learned data — fill to hard_max as safe default ──
        target_kwh = BATTERY_KWH * (hard_max / 100.0)
        gap_kwh    = target_kwh - soc_now_kwh
        if gap_kwh <= 0:
            slots = 0
        else:
            slots = int(-(-gap_kwh // charge_per_slot))
        slots = max(0, min(16, slots))
        print(f"[OPT] Phase1 (no data): soc={soc_now}% → target={hard_max}% "
              f"gap={gap_kwh:.1f}kWh → {slots} slots")
        return slots

    # ── Phase 2: learned data available ──────────────────────────
    avg_cons = opt.get("avg_daily_consumption_kwh", 5.0)
    avg_pv   = opt.get("avg_daily_pv_kwh", 2.0)
    pv_scale = opt.get("pv_scale_factor", 0.35)

    # Dynamic target SOC based on tomorrow's day-of-week consumption pattern
    target_soc, target_reason = compute_dynamic_target_soc()
    target_kwh = BATTERY_KWH * (target_soc / 100.0)

    with weather_lock:
        tomorrow_pv      = weather_state.get("tomorrow_pv_estimate_kwh")
        tomorrow_cloud   = weather_state.get("tomorrow_cloud_avg")
        hourly_radiation = weather_state.get("hourly_radiation", {})

    # Priority: learned cloud-bucket yield > radiation-based forecast > rolling avg
    # Add MAE as a safety margin so the system is slightly conservative when uncertain
    mae = opt.get("pv_prediction_mae_kwh") or 0.0
    cloud_pv = (_cloud_based_pv_estimate(tomorrow_cloud, opt)
                if tomorrow_cloud is not None else None)
    if cloud_pv is not None:
        expected_pv = max(0.0, cloud_pv - mae * 0.5)
        pv_source   = f"cloud-bucket({_cloud_bucket(tomorrow_cloud)})"
    elif tomorrow_pv is not None:
        expected_pv = max(0.0, tomorrow_pv - mae * 0.5)
        pv_source   = "radiation-forecast"
    else:
        expected_pv = avg_pv
        pv_source   = "rolling-avg"

    # How much grid energy do we need?
    # = fill battery to dynamic target + cover tomorrow's net consumption
    net_tomorrow = avg_cons - expected_pv
    gap_kwh = (target_kwh - soc_now_kwh) + net_tomorrow

    # ── Today's remaining solar surplus ────────────────────────────────
    # If called during daylight, estimate how much the battery will charge
    # from solar before nightfall — subtract that from the grid gap.
    now_uk_r     = datetime.now(UK_TZ)
    today_str_r  = now_uk_r.strftime("%Y-%m-%d")
    solar_end_h  = 19           # useful solar until ~19:00
    remaining_pv_today = 0.0
    for h in range(now_uk_r.hour, solar_end_h):
        hr_key = f"{today_str_r}T{h:02d}:00"
        rad    = (hourly_radiation or {}).get(hr_key) or 0
        remaining_pv_today += rad * PANEL_KWP * pv_scale / 1000  # kWh per hour
    remaining_cons_today = avg_cons * max(0, solar_end_h - now_uk_r.hour) / 24
    net_solar_today      = max(0.0, remaining_pv_today - remaining_cons_today)
    if net_solar_today > 0:
        gap_kwh -= net_solar_today
        print(f"[OPT] Today solar surplus: pv={remaining_pv_today:.2f} kWh "
              f"cons={remaining_cons_today:.2f} kWh net={net_solar_today:.2f} kWh → gap reduced")
    # ───────────────────────────────────────────────────────────────────

    # ── Megtakarítás-alapú korrekció (register history) ──────────────────
    # Ha az inverter history szerint az elmúlt 7 napban keveset vettünk
    # a hálózatból, az azt jelenti hogy a rendszer már jól teljesít.
    # Ilyen esetben még konzervatívabb célértéket használunk.
    avg_mains   = opt.get('avg_mains_kwh_7d')
    self_suff   = opt.get('self_sufficiency_pct', 0.0)
    if avg_mains is not None and avg_mains < avg_cons * 0.5:
        # Elmúlt 7 nap: grid < 50% of consumption → rendszer jól teljesít
        # Csökkentjük a gap-et: nem kell annyit tölteni
        savings_reduction = min(gap_kwh * 0.4, 0.8)  # max 0.8 kWh csökkentés
        gap_kwh -= savings_reduction
        print(f"[OPT] SAVINGS MODE: avg_mains={avg_mains:.2f} kWh < 50% of cons → "
              f"gap reduced by {savings_reduction:.2f} kWh (self-suff={self_suff:.0f}%)")
    # ────────────────────────────────────────────────────────────────────

    # ── Safety floor ────────────────────────────────────────────────────
    # Csak akkor aktiválódik ha az akku valóban kritikusan alacsony ÉJJEL
    # és a számítások valamiért 0-t adtak.
    # 35%-ra csökkentve (volt: 60%) — az éjszakai igény ~0.7 kWh = 17%,
    # 35% (1.4 kWh) bőven elég a reggelig + kis tartalék.
    SAFETY_SOC_PCT = 35
    is_daytime = 7 <= now_uk_r.hour < 19
    # Safety floor: csak az éjszakai igényre tölt (nem hard_max-ra!)
    safety_target_kwh = BATTERY_KWH * (min(hard_max, 60) / 100.0)
    if gap_kwh <= 0 and soc_now < SAFETY_SOC_PCT and not is_daytime:
        gap_kwh = safety_target_kwh - soc_now_kwh
        print(f"[OPT] SAFETY FLOOR (night): soc={soc_now}% < {SAFETY_SOC_PCT}% → "
              f"charge to 60%: gap={gap_kwh:.2f}kWh")
    # ────────────────────────────────────────────────────────────────────

    # Minimum küszöb: ha a gap < fél slot, nem éri meg tölteni
    if 0 < gap_kwh < charge_per_slot * 0.5:
        print(f"[OPT] Gap {gap_kwh:.2f} kWh < 0.5 slot → 0 slots (not worth grid charging)")
        gap_kwh = 0

    if gap_kwh <= 0:
        slots = 0
        print(f"[OPT] Phase2: battery+PV covers tomorrow — 0 slots needed "
              f"(gap={gap_kwh:.1f}kWh  soc={soc_now}%  mains_avg={avg_mains})")
    else:
        slots = int(-(-gap_kwh // charge_per_slot))

    # Max slots korlát megtakarítás módban: ha self-suff magas, max 4 slot
    if self_suff > 60 and slots > 4:
        slots = 4
        print(f"[OPT] SAVINGS CAP: self-suff={self_suff:.0f}% → max 4 slots")

    slots = max(0, min(8, slots))   # abszolút max 8 (volt: 16)
    print(f"[OPT] Phase2 ({days}d data): soc={soc_now}%={soc_now_kwh:.1f}kWh "
          f"target={target_soc:.0f}%={target_kwh:.1f}kWh [{target_reason}] "
          f"cons={avg_cons:.2f} pv={expected_pv:.2f}({pv_source}) mae={mae:.2f} "
          f"mains_avg={avg_mains} self_suff={self_suff:.0f}% "
          f"net_tom={net_tomorrow:.2f} solar_today={net_solar_today:.2f} "
          f"gap={gap_kwh:.2f}kWh → {slots} slots")
    return slots

# -------------------------
# Nightly planning (22:00)
# -------------------------

_last_plan_date = None

def run_nightly_plan():
    """Full 22:00 planning cycle."""
    global _last_plan_date
    now_uk = datetime.now(UK_TZ)
    today = now_uk.date()

    if _last_plan_date == today:
        return  # Already ran today

    print(f"[PLAN] Starting nightly plan for {today}")

    # 1. Record today's summary
    record_daily_summary()

    # 2. Fetch fresh Agile prices (tomorrow's slots)
    update_prices()

    # 3. Fetch weather forecast
    fetch_weather()

    # 4. Compute required slots
    slots_needed = compute_required_slots()

    _last_plan_date = today

    # 6. Recompute cheap slots with new count
    cheap_slots = compute_cheap_slots()
    with ems_lock:
        ems_state["cheap_slots"] = [
            {"start": c["start"].astimezone(UK_TZ).isoformat(),
             "end":   c["end"].astimezone(UK_TZ).isoformat(),
             "price": c["price"]}
            for c in cheap_slots
        ]
        ems_state["last_action"] = (
            f"{datetime.now()}: Nightly plan → {slots_needed} slots "
            f"[PV est: {weather_state.get('tomorrow_pv_estimate_kwh','?')} kWh]"
        )

    print(f"[PLAN] Done: {slots_needed} slots scheduled for tonight/tomorrow")
    return slots_needed



# -------------------------
# EMS scheduler loop (enhanced with nightly planning)
# -------------------------

def _do_replan():
    new_slots = compute_cheap_slots()
    with ems_lock:
        ems_state["cheap_slots"] = [
            {"start": c2["start"].astimezone(UK_TZ).isoformat(),
             "end":   c2["end"].astimezone(UK_TZ).isoformat(),
             "price": c2["price"]}
            for c2 in new_slots
        ]
    sp = [str(round(s["price"],1))+"p" for s in new_slots]
    print("[EMS] Replan: "+str(len(new_slots))+" slots -> "+str(sp))
    return new_slots

_last_afternoon_fetch = None

def ems_scheduler_loop():
    global last_price_fetch, _last_plan_date, _last_afternoon_fetch
    last_midnight_check = None
    last_validation     = None   # 10-perces validáció időbélyege

    while True:
        time.sleep(60)

        with ems_lock:
            control_mode = ems_state.get("control_mode", "auto")
        if control_mode == "manual":
            continue

        with config_lock:
            enabled = config.get("automation_enabled", True)

        if not enabled:
            continue

        now_ts = time.time()

        now_utc = datetime.now(timezone.utc)
        now_uk  = now_utc.astimezone(UK_TZ)

        # 22:00 Nightly planning
        if now_uk.hour == 22 and now_uk.minute < 5:
            run_nightly_plan()

        # 16:30 Afternoon price pre-fetch + REPLAN
        # Octopus publishes tomorrow's Agile prices at ~16:00
        # After fetching, recompute slots - tonight's expensive slots might be
        # replaceable with cheaper overnight/early-morning slots tomorrow
        today_date = now_uk.date()
        if now_uk.hour == 16 and _last_afternoon_fetch != today_date:
            print(f"[EMS] 16:xx fetch")
            update_prices()
            fetch_weather()
            _last_afternoon_fetch = today_date
            _do_replan()

        # Weather refresh every 3 hours (so slot count adjusts to forecast changes)
        with weather_lock:
            last_wx = weather_state.get("last_fetch")
        if last_wx:
            try:
                last_wx_dt = datetime.fromisoformat(last_wx)
                if (now_utc - last_wx_dt.astimezone(timezone.utc)) > timedelta(hours=3):
                    print("[EMS] 3hr weather refresh")
                    threading.Thread(target=fetch_weather, daemon=True).start()
                    # Only re-detect location if no manual override
                    with config_lock:
                        _has_manual = bool(config.get("manual_lat")) and bool(config.get("manual_lon"))
                    if not _has_manual:
                        threading.Thread(target=detect_location, daemon=True).start()
            except Exception:
                pass

        # Midnight safety refresh
        current_date = now_uk.date()
        if last_midnight_check != current_date and now_uk.hour == 0 and now_uk.minute <= 5:
            print(f"[EMS] Midnight refresh at {now_uk}")
            last_midnight_check = current_date
            update_prices()
            time.sleep(10)

        # ── 10-perces terv-validáció ──────────────────────────────────────
        # Percenként fut a scheduler, de maga a terv (hány slot szükséges?)
        # csak ritkán számolódik újra. Ha közben:
        #   - nagyfogyasztású készülék kapcsol be (az SOC gyorsabban esik)
        #   - az időjárás romlik → várható napenergia csökken
        #   - az akkumulátor szintje eltér a várttól
        # → a régi terv elavult. Ez a blokk 10 percenként összehasonlítja
        #   a jelenlegi állapot alapján szükséges slot-ok számát a tervezett
        #   slot-okkal, és ha eltérés van, újratervez.
        if last_validation is None or (now_utc - last_validation) > timedelta(minutes=10):
            last_validation = now_utc
            try:
                n_needed = compute_required_slots()
                with ems_lock:
                    n_planned = len(ems_state.get("cheap_slots", []))
                with telemetry_lock:
                    soc_check = telemetry.get("soc", "?")
                with weather_lock:
                    cloud_now = weather_state.get("current_cloud", "?")

                # Ha az akku kritikusan alacsony, mindig repláneolunk
                # (nem elegendő hogy n_needed == n_planned ha az is kevés)
                with config_lock:
                    _min_soc_v = int(config.get("min_soc", 20))
                soc_critical = (isinstance(soc_check, (int, float))
                                and soc_check <= _min_soc_v + 15)

                if n_needed > n_planned + 1 or (soc_critical and n_needed > n_planned):
                    # Szignifikánsan több slot kell mint amennyi tervezett,
                    # VAGY az akku alacsony és egyáltalán több kell
                    print(f"[VALID] Replan needed: planned={n_planned} slots, "
                          f"needed={n_needed} slots | soc={soc_check}% cloud={cloud_now}% "
                          f"critical={soc_critical}")
                    _do_replan()
                elif n_planned > 0 and n_needed == 0:
                    # A terv szerint kellene slot, de újraszámolva már nem kell
                    # (pl. közben napelem feltöltötte az akkut)
                    print(f"[VALID] Replan: conditions improved, no slots needed "
                          f"| soc={soc_check}%")
                    _do_replan()
                else:
                    print(f"[VALID] OK: planned={n_planned}, needed={n_needed} slots "
                          f"| soc={soc_check}% cloud={cloud_now}%")
            except Exception as _val_err:
                print(f"[VALID] Hiba a validáció során: {_val_err}")
        # ─────────────────────────────────────────────────────────────────

        # Regular 30-min price refresh
        if last_price_fetch is None or (now_utc - last_price_fetch) > timedelta(minutes=30):
            update_prices()

        now       = datetime.now(timezone.utc)
        price_now = get_price_now()   # korai beolvasás — should_charge_now() és a szabályok is használják

        try:
            cheap_slots = compute_cheap_slots()
        except Exception as _slots_err:
            import traceback
            print(f"[SLOTS] ERROR in compute_cheap_slots: {_slots_err}")
            traceback.print_exc()
            cheap_slots = []
            with ems_lock:
                ems_state["slots_status"] = f"error: {_slots_err}"

        with ems_lock:
            ems_state["cheap_slots"] = [
                {"start": c["start"].astimezone(UK_TZ).isoformat(),
                 "end":   c["end"].astimezone(UK_TZ).isoformat(),
                 "price": c["price"]}
                for c in cheap_slots
            ]

        # in_cheap: csak akkor True ha most éppen valamelyik kiválasztott slot aktív
        in_cheap     = any(c["start"] <= now <= c["end"] for c in cheap_slots)
        _pn_str      = f"{price_now:.1f}p" if price_now is not None else "?p"
        cheap_reason = f"cheap_slot:{_pn_str}" if in_cheap else f"outside_slot:{_pn_str}"
        next_slot = next((c for c in cheap_slots if c["start"] > now), None)

        with ems_lock:
            ems_state["next_cheap_slot"] = (
                {"start": next_slot["start"].astimezone(UK_TZ).isoformat(),
                 "end":   next_slot["end"].astimezone(UK_TZ).isoformat(),
                 "price": next_slot["price"]}
                if next_slot else None
            )
            ems_state["next_switch_time"] = next_slot["start"].astimezone(UK_TZ).isoformat() if next_slot else None

        with telemetry_lock:
            fault1    = telemetry["fault_bits_1"]
            dev_state = telemetry["device_state"]
            bat_temp  = telemetry["battery_temp"]
            ctrl_temp = telemetry["controller_temp"]

        try:
            with telemetry_lock:
                telemetry["price_now"] = price_now

            if fault1 and fault1 > 0:
                with ems_lock:
                    ems_state["last_error"] = f"Fault: bits_1={fault1}"
                time.sleep(300)
                continue
            if bat_temp and bat_temp > 50:
                with ems_lock:
                    ems_state["last_error"] = f"High battery temp: {bat_temp}°C"
                set_mode_expensive("high_bat_temp")
                time.sleep(300)
                continue
            if ctrl_temp and ctrl_temp > 70:
                with ems_lock:
                    ems_state["last_error"] = f"High controller temp: {ctrl_temp}°C"
                set_mode_expensive("high_ctrl_temp")
                time.sleep(300)
                continue
            if dev_state in [9, 10]:
                with ems_lock:
                    ems_state["last_error"] = f"Device error state: {dev_state}"
                time.sleep(300)
                continue

            # --- Live telemetry for protection rules ---
            with telemetry_lock:
                soc_live       = telemetry.get("soc") or 0
                bat_p_live     = telemetry.get("bat_p") or 0
                load_p_live    = telemetry.get("load_p") or 0
                chg_state_live = telemetry.get("charge_state")

            with ems_lock:
                hc_active      = ems_state.get("high_consumer_active", False)
                hc_entry_load  = ems_state.get("high_consumer_entry_load", 0)

            # Rule 1: high consumer protection
            # Entry: battery discharging hard + SOC low (in SBU mode, before switch)
            HIGH_CONSUMER_ENTER = bat_p_live < -1200 and soc_live < 30
            # Exit: SOC recovered OR load dropped to <50% of what triggered entry
            # (bat_p is NOT used here — in SUB mode grid supplies load, bat_p won't be negative)
            HIGH_CONSUMER_EXIT = (
                soc_live >= 35
                or (hc_entry_load > 0 and load_p_live < hc_entry_load * 0.5)
            )

            if not hc_active and HIGH_CONSUMER_ENTER:
                with ems_lock:
                    ems_state["high_consumer_active"]     = True
                    ems_state["high_consumer_entry_load"] = load_p_live
                    ems_state["last_error"] = f"High consumer: soc={soc_live}% bat_p={bat_p_live}W load={load_p_live}W"
                print(f"[HC] High consumer protection active: soc={soc_live}% bat_p={bat_p_live}W load={load_p_live}W")
                write_register(REG_OUTPUT_PRI, OUTPUT_SUB)   # E204: grid supplies load
                time.sleep(5)
                if in_cheap:
                    set_charge_mode(MODE_HYBRID, "high_consumer_cheap")   # E20F=2
                else:
                    set_charge_mode(MODE_PV_ONLY, "high_consumer_expensive")   # E20F=3

            elif hc_active and HIGH_CONSUMER_EXIT:
                with ems_lock:
                    ems_state["high_consumer_active"]     = False
                    ems_state["high_consumer_entry_load"] = 0
                    ems_state["last_error"] = None
                print(f"[HC] High consumer cleared: soc={soc_live}% load={load_p_live}W (was {hc_entry_load}W) — reverting")
                write_register(REG_OUTPUT_PRI, OUTPUT_SBU)   # E204: back to SBU
                time.sleep(5)
                set_charge_mode(MODE_HYBRID, "high_consumer_cleared")   # E20F=2

            elif hc_active:
                pass   # still in high-consumer protection, maintain current registers

            else:
                with config_lock:
                    min_soc_cfg = int(config.get("min_soc", 20))
                with ems_lock:
                    bp_active = ems_state.get("bat_protect_active", False)

                if in_cheap:
                    # Olcsó slot: töltünk (SUB+Hybrid)
                    if bp_active:
                        with ems_lock:
                            ems_state["bat_protect_active"] = False
                    # Ha az akku már tele van (chg_state=8=Full) → nincs mit tölteni →
                    # SBU-ba váltunk: nap/akku adja a terhelést, nem húzunk gridről
                    if chg_state_live == 8:
                        print(f"[EMS] Battery Full (chg=8) during cheap slot → SBU (grid saved) soc={soc_live}%")
                        set_mode_expensive(f"bat_full_in_cheap:soc={soc_live}%")
                    else:
                        set_mode_cheap(cheap_reason)
                    with ems_lock:
                        ems_state["last_error"] = None

                elif soc_live <= min_soc_cfg and not bp_active:
                    # SOC leesett a minimum alá → akkuvédelem: grid adja a terhelést, nem tölt
                    with ems_lock:
                        ems_state["bat_protect_active"] = True
                        ems_state["last_error"] = None   # protect is normal operation, not an error
                    print(f"[PROTECT] SOC={soc_live}% <= min={min_soc_cfg}% → SUB+PV-only (grid for load, no charging)")
                    set_mode_protect(f"low_soc:{soc_live}%")

                elif bp_active and soc_live >= 50:
                    # Felépült az akku → vissza SBU
                    with ems_lock:
                        ems_state["bat_protect_active"] = False
                        ems_state["last_error"] = None
                    print(f"[PROTECT] SOC={soc_live}% >= 50% → clearing protection, back to SBU")
                    set_mode_expensive(f"soc_recovered:{soc_live}%")

                elif bp_active:
                    # Még védelmi módban, SOC 20-50% között → maradunk SUB+PV-only
                    pass

                else:
                    # Normál drága üzem: SBU+PV-only
                    set_mode_expensive(cheap_reason)

        except Exception as e:
            with ems_lock:
                ems_state["last_error"] = f"EMS error: {e}"


# -------------------------
# Flask app + HTML
# -------------------------

app = Flask(__name__)

HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flux EMS Pro</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@400;600;700;800&display=swap');
:root{
  --bg:#050a0f;--bg2:#080f17;--bg3:#0d1829;
  --card:#0b1520;--card2:#0f1e30;
  --border:#1a2d44;--border2:#243d58;
  --text:#d4e8f7;--muted:#5a7fa0;--dim:#2a4560;
  --green:#22c55e;--amber:#f59e0b;--red:#ef4444;--blue:#38bdf8;--violet:#a78bfa;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'DM Mono',monospace;min-height:100vh;overflow-x:hidden;}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 20% 0%,rgba(14,30,55,0.8),transparent),radial-gradient(ellipse 60% 40% at 80% 100%,rgba(7,20,40,0.6),transparent);pointer-events:none;z-index:0;}
header{position:relative;z-index:10;padding:14px 20px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);background:rgba(5,10,15,0.9);backdrop-filter:blur(10px);}
.logo{display:flex;align-items:baseline;gap:10px;}
.logo-text{font-family:'Syne',sans-serif;font-weight:800;font-size:19px;letter-spacing:-0.5px;background:linear-gradient(135deg,var(--blue),var(--green));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.logo-ver{font-size:10px;color:var(--muted);letter-spacing:1px;}
.header-right{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.conn-dot{width:8px;height:8px;border-radius:50%;background:var(--muted);transition:all 0.5s;}
.conn-dot.ok{background:var(--green);box-shadow:0 0 8px var(--green);}
.conn-dot.err{background:var(--red);box-shadow:0 0 8px var(--red);}
.conn-label{font-size:11px;color:var(--muted);}
.price-badge{font-family:'Syne',sans-serif;font-size:13px;font-weight:700;padding:4px 12px;border-radius:999px;border:1px solid var(--border2);background:var(--card2);color:var(--amber);}
.mode-badge{font-size:10px;padding:3px 10px;border-radius:999px;border:1px solid var(--border);background:var(--card);color:var(--muted);font-family:'Syne',sans-serif;font-weight:600;}
.mode-badge.cheap{border-color:var(--green);color:var(--green);}
.mode-badge.expensive{border-color:var(--amber);color:var(--amber);}
.mode-badge.manual{border-color:var(--violet);color:var(--violet);}
nav{position:relative;z-index:10;display:flex;gap:2px;padding:0 20px;border-bottom:1px solid var(--border);background:rgba(5,10,15,0.7);overflow-x:auto;}
.tab{padding:10px 16px;font-size:11px;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all 0.2s;font-family:'Syne',sans-serif;font-weight:600;white-space:nowrap;}
.tab.active{color:var(--blue);border-bottom-color:var(--blue);}
.tab:hover:not(.active){color:var(--text);}
main{position:relative;z-index:1;padding:18px 20px 40px;}
.grid-4{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:12px;}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px;}
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:12px;}
@media(min-width:640px){.grid-4{grid-template-columns:repeat(4,1fr);}}
@media(max-width:480px){.grid-3{grid-template-columns:repeat(2,1fr);}.grid-2{grid-template-columns:1fr;}}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px;position:relative;overflow:hidden;transition:border-color 0.2s;}
.card::before{content:'';position:absolute;inset:0;background:radial-gradient(circle at top left,rgba(56,189,248,0.03),transparent 60%);pointer-events:none;}
.card-sm{padding:11px 14px;}
.card-title{font-family:'Syne',sans-serif;font-size:10px;font-weight:600;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.card-val{font-family:'Syne',sans-serif;font-size:clamp(20px,4vw,28px);font-weight:700;line-height:1;letter-spacing:-1px;}
.card-unit{font-size:12px;color:var(--muted);margin-left:3px;font-weight:400;}
.card-sub{font-size:10px;color:var(--muted);margin-top:4px;}
.stat-green .card-val{color:var(--green);}
.stat-amber .card-val{color:var(--amber);}
.stat-blue  .card-val{color:var(--blue);}
.stat-red   .card-val{color:var(--red);}
.stat-violet .card-val{color:var(--violet);}
.stat-green::after,.stat-amber::after,.stat-blue::after,.stat-red::after,.stat-violet::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;}
.stat-green::after{background:linear-gradient(90deg,transparent,var(--green),transparent);}
.stat-amber::after{background:linear-gradient(90deg,transparent,var(--amber),transparent);}
.stat-blue::after{background:linear-gradient(90deg,transparent,var(--blue),transparent);}
.stat-red::after{background:linear-gradient(90deg,transparent,var(--red),transparent);}
.stat-violet::after{background:linear-gradient(90deg,transparent,var(--violet),transparent);}
.metric-row{display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid rgba(26,45,68,0.5);font-size:11px;}
.metric-row:last-child{border-bottom:none;}
.metric-row .label{color:var(--muted);}
.metric-row .value{font-weight:500;color:var(--text);}
.soc-bar-bg{height:6px;background:var(--dim);border-radius:3px;overflow:hidden;margin:8px 0 4px;}
.soc-bar-fill{height:100%;border-radius:3px;transition:width 1s ease;background:linear-gradient(90deg,var(--green),#16a34a);}
.soc-bar-fill.low{background:linear-gradient(90deg,var(--red),#b91c1c);}
.soc-bar-fill.mid{background:linear-gradient(90deg,var(--amber),#d97706);}
.chart-wrap{position:relative;width:100%;margin:8px 0;}
canvas.chart{width:100%;display:block;}
.chart-legend{display:flex;gap:12px;flex-wrap:wrap;margin-top:6px;}
.legend-item{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--muted);}
.legend-dot{width:8px;height:8px;border-radius:50%;}
.slot-item{display:flex;justify-content:space-between;align-items:center;padding:7px 10px;border-radius:8px;border:1px solid var(--border);background:var(--bg2);margin-bottom:5px;font-size:11px;}
.slot-item.active{background:#0a1f0a;box-shadow:0 0 0 1px var(--green);}
.slot-item.past{opacity:0.35;}
.slot-day-hdr{font-size:10px;color:var(--dim);padding:6px 2px 2px;font-weight:600;letter-spacing:.5px;}
.btn{border-radius:8px;border:1px solid var(--border);background:var(--card2);color:var(--text);padding:7px 14px;font-size:11px;cursor:pointer;font-family:'Syne',sans-serif;font-weight:600;letter-spacing:.5px;transition:all 0.15s;}
.btn:hover{border-color:var(--blue);color:var(--blue);}
.btn-sm{padding:3px 10px;font-size:10px;}
.btn-primary{background:linear-gradient(135deg,#1d4ed8,#0891b2);border:none;color:white;}
.btn-primary:hover{opacity:0.9;color:white;}
.btn-green{background:rgba(34,197,94,0.15);border-color:var(--green);color:var(--green);}
.btn-amber{background:rgba(245,158,11,0.15);border-color:var(--amber);color:var(--amber);}
.btn-violet{background:rgba(167,139,250,0.15);border-color:var(--violet);color:var(--violet);}
.ctrl-row{display:flex;gap:8px;margin-bottom:10px;}
.ctrl-row .btn{flex:1;padding:11px;text-align:center;}
.mode-btn{flex:1;padding:12px 8px;border-radius:8px;border:2px solid var(--border);background:var(--bg2);color:var(--muted);font-family:'Syne',sans-serif;font-weight:700;font-size:12px;cursor:pointer;text-align:center;transition:all 0.2s;}
.mode-btn.active-auto{border-color:var(--green);color:var(--green);background:rgba(34,197,94,0.08);}
.mode-btn.active-manual{border-color:var(--violet);color:var(--violet);background:rgba(167,139,250,0.08);}
.manual-actions{margin-top:10px;}
.manual-actions.disabled{opacity:0.4;pointer-events:none;}
.forecast-pill{background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;flex:1;min-width:80px;text-align:center;}
.forecast-pill .date{font-size:9px;color:var(--muted);margin-bottom:4px;}
.forecast-pill .pv{font-family:'Syne',sans-serif;font-size:14px;font-weight:700;color:var(--amber);}
.forecast-pill .cloud{font-size:10px;color:var(--muted);}
.daily-row{display:grid;grid-template-columns:72px 1fr 1fr 1fr 1fr 1fr;gap:4px;padding:5px 0;border-bottom:1px solid rgba(26,45,68,0.4);font-size:11px;align-items:center;}
.daily-row:last-child{border-bottom:none;}
.daily-hdr{color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.5px;}
.mini-bar{height:6px;border-radius:3px;min-width:2px;display:inline-block;}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(5,10,15,0.88);z-index:2000;align-items:center;justify-content:center;backdrop-filter:blur(4px);}
.modal-bg.open{display:flex;}
.modal{background:var(--bg2);border:1px solid var(--border2);border-radius:16px;padding:26px 28px;width:min(520px,94vw);max-height:90vh;overflow-y:auto;box-shadow:0 40px 80px rgba(0,0,0,0.7);}
.modal-title{font-family:'Syne',sans-serif;font-weight:700;font-size:16px;margin-bottom:18px;display:flex;justify-content:space-between;align-items:center;}
.field-group{display:flex;flex-direction:column;gap:4px;margin-bottom:11px;}
.field-label{font-size:10px;color:var(--muted);letter-spacing:.8px;text-transform:uppercase;}
input,select{background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:8px 11px;font-size:12px;font-family:'DM Mono',monospace;width:100%;}
input:focus,select:focus{outline:none;border-color:var(--blue);}
.row-btns{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap;}
.tab-content{display:none;}.tab-content.active{display:block;}
.toast{position:fixed;bottom:16px;right:16px;background:var(--card2);border:1px solid var(--border2);border-radius:999px;padding:8px 16px;font-size:12px;display:none;z-index:9999;}
.toast.ok{border-color:var(--green);color:var(--green);}
.toast.err{border-color:var(--red);color:var(--red);}
.wizard-bg{position:fixed;inset:0;background:rgba(5,10,15,0.97);z-index:3000;align-items:center;justify-content:center;backdrop-filter:blur(8px);}
.wizard{background:var(--bg2);border:1px solid var(--border2);border-radius:20px;padding:32px 28px;width:min(480px,94vw);max-height:92vh;overflow-y:auto;box-shadow:0 50px 100px rgba(0,0,0,0.8);}
.wizard-logo-text{font-family:'Syne',sans-serif;font-weight:800;font-size:24px;background:linear-gradient(135deg,var(--blue),var(--green));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
header{padding:12px 20px;display:flex;justify-content:space-between;align-items:center;background:radial-gradient(circle at top left,#1f2937,#020617);border-bottom:1px solid #111827;}
.title{font-size:18px;font-weight:600;}.sub{font-size:11px;color:#9ca3af;}
.container{padding:18px 20px 30px;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;}
.card{background:radial-gradient(circle at top left,#111827,#020617);border-radius:14px;padding:12px 14px 14px;border:1px solid #1f2937;box-shadow:0 18px 40px rgba(0,0,0,0.55);}
.card-header{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px;}
.card-title{font-size:14px;font-weight:600;}.card-sub{font-size:11px;color:#9ca3af;}
.pill{font-size:10px;padding:2px 8px;border-radius:999px;border:1px solid #4b5563;color:#9ca3af;}
.row{display:flex;gap:8px;flex-wrap:wrap;}
.metric{font-size:11px;margin:2px 0;}.metric span.label{color:#9ca3af;}
input{background:#020617;border:1px solid #374151;border-radius:8px;color:#e5e7eb;padding:5px 7px;font-size:11px;width:100%;box-sizing:border-box;}
label{font-size:11px;color:#9ca3af;}
button{border-radius:999px;border:1px solid #374151;background:rgba(15,23,42,0.95);color:#e5e7eb;padding:5px 10px;font-size:11px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:all 0.15s ease;}
button span.dot{width:6px;height:6px;border-radius:999px;background:#22c55e;}
button:hover{border-color:#60a5fa;box-shadow:0 0 0 1px rgba(37,99,235,0.4);transform:translateY(-1px);}
.toast{position:fixed;bottom:12px;right:12px;background:#020617;border-radius:999px;border:1px solid #374151;padding:8px 14px;font-size:12px;display:none;}
.toast.ok{border-color:#22c55e;}.toast.err{border-color:#ef4444;}
pre{font-size:10px;background:#020617;border-radius:8px;padding:8px;border:1px solid #1f2937;max-height:160px;overflow:auto;}
.gauge-set{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px;}
.gauge{width:84px;height:84px;border-radius:50%;background:conic-gradient(#1f2937 0deg,#1f2937 360deg);display:flex;align-items:center;justify-content:center;position:relative;}
.gauge-inner{width:66px;height:66px;border-radius:50%;background:linear-gradient(#020617,#071025);display:flex;align-items:center;justify-content:center;flex-direction:column;border:1px solid rgba(255,255,255,0.04);}
.gauge-value{font-size:13px;font-weight:600;}.gauge-label{font-size:10px;color:#9ca3af;margin-top:2px;}
.spark{width:100%;height:60px;background:#020617;border:1px solid #1f2937;border-radius:8px;}
.spark-wrap{position:relative;margin-bottom:4px;}
.spark-label{position:absolute;top:4px;left:8px;font-size:10px;color:#9ca3af;z-index:1;pointer-events:none;}
.spark-val{position:absolute;top:4px;right:8px;font-size:11px;font-weight:600;z-index:1;pointer-events:none;}
@media(max-width:768px){.hide-mobile{display:none!important;}}
.timeline{display:flex;flex-direction:column;gap:8px;margin-top:6px;padding-bottom:6px;}
.slot{width:100%;padding:8px 10px;border-radius:8px;border:1px solid #1f2937;background:#0b1220;display:flex;flex-direction:row;align-items:center;justify-content:space-between;box-sizing:border-box;}
.slot .label{font-size:11px;color:#e5e7eb;}.slot .price{font-size:10px;color:#9ca3af;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-text">Flux EMS Pro</div>
    <div class="logo-ver" id="ver-label">v{{ version if version is defined else '' }}</div>
  </div>
  <div class="header-right">
    <div style="display:flex;align-items:center;gap:6px;">
      <div class="conn-dot" id="conn-dot"></div>
      <span class="conn-label" id="conn-label">connecting...</span>
    </div>
    <div class="price-badge" id="price-badge">--</div>
    <div class="mode-badge" id="mode-badge">--</div>
    <div id="trial-badge" style="display:none;padding:6px 10px;background:linear-gradient(135deg,#f97316,#ea580c);border-radius:6px;font-size:11px;font-weight:600;color:white;font-family:'Syne',sans-serif;white-space:nowrap;">
      🔔 Trial: <span id="trial-days">14</span>d
    </div>
    <button id="manage-btn" class="btn btn-sm" style="display:none;border-color:#1d4ed8;color:#1d4ed8;" onclick="document.getElementById('manage-sub-section').style.display='flex'">💳 Manage</button>
    <button class="btn btn-sm" onclick="openSettings()">⚙ Settings</button>
    <button class="btn btn-sm" style="border-color:var(--red);color:var(--red);" onclick="stopApp()">■ Stop</button>
  </div>
</header>

<nav>
  <div class="tab active" onclick="switchTab('live')">Live</div>
  <div class="tab" onclick="switchTab('ems')">EMS</div>
  <div class="tab" onclick="switchTab('history')">History</div>
  <div class="tab" onclick="switchTab('daily')">Daily</div>
  <div class="tab" onclick="switchTab('weather')">Weather</div>
</nav>

<main>

<!-- ── LIVE TAB ──────────────────────────────────── -->
<div id="tab-live" class="tab-content active">
  <div class="grid-4">
    <div class="card stat-green">
      <div class="card-title">Battery SOC</div>
      <div><span class="card-val" id="m-soc">--</span><span class="card-unit">%</span></div>
      <div class="soc-bar-bg"><div class="soc-bar-fill" id="soc-bar" style="width:0%"></div></div>
      <div class="card-sub" id="m-bat-status">--</div>
    </div>
    <div class="card stat-amber">
      <div class="card-title">☀️ Solar Power</div>
      <div><span class="card-val" id="m-pv">--</span><span class="card-unit">W</span></div>
      <div class="card-sub" id="m-pv-today">Today: -- kWh</div>
    </div>
    <div class="card stat-red">
      <div class="card-title">🏠 House Load</div>
      <div><span class="card-val" id="m-load">--</span><span class="card-unit">W</span></div>
      <div class="card-sub" id="m-load-today">Today: -- kWh</div>
    </div>
    <div class="card stat-blue">
      <div class="card-title">⚡ Battery Power</div>
      <div><span class="card-val" id="m-bat-p">--</span><span class="card-unit">W</span></div>
      <div class="card-sub" id="m-bat-dir">--</div>
    </div>
  </div>

  <div class="grid-3">
    <div class="card card-sm">
      <div class="card-title">Battery</div>
      <div class="metric-row"><span class="label">Voltage</span><span class="value" id="d-bat-v">--</span></div>
      <div class="metric-row"><span class="label">Current</span><span class="value" id="d-bat-i">--</span></div>
      <div class="metric-row"><span class="label">Temp</span><span class="value" id="d-bat-t">--</span></div>
    </div>
    <div class="card card-sm">
      <div class="card-title">Grid / Inverter</div>
      <div class="metric-row"><span class="label">Grid V</span><span class="value" id="d-grid-v">--</span></div>
      <div class="metric-row"><span class="label">Grid Hz</span><span class="value" id="d-grid-hz">--</span></div>
      <div class="metric-row"><span class="label">Load PF</span><span class="value" id="d-load-pf">--</span></div>
    </div>
    <div class="card card-sm">
      <div class="card-title">System</div>
      <div class="metric-row"><span class="label">Output pri</span><span class="value" id="d-out-pri">--</span></div>
      <div class="metric-row"><span class="label">Charge mode</span><span class="value" id="d-chg-mode">--</span></div>
      <div class="metric-row"><span class="label">Running</span><span class="value" id="d-run">--</span></div>
    </div>
  </div>

  <div class="card" style="margin-bottom:12px;">
    <div class="card-title" style="margin-bottom:10px;">Statistics · Today</div>
    <div class="grid-2" style="margin-bottom:0;">
      <div>
        <div class="metric-row"><span class="label">☀️ PV generation</span><span class="value" id="s-pv-today" style="color:var(--amber)">--</span></div>
        <div class="metric-row"><span class="label">🔌 From grid</span><span class="value" id="s-load-today" style="color:var(--red)">--</span></div>
      </div>
      <div>
        <div class="metric-row"><span class="label">🔋 Bat charged</span><span class="value" id="s-chg-today" style="color:var(--green)">--</span></div>
        <div class="metric-row"><span class="label">🔋 Bat discharged</span><span class="value" id="s-run-days" style="color:var(--violet)">--</span></div>
      </div>
    </div>
  </div>
</div>

<!-- ── EMS TAB ──────────────────────────────────── -->
<div id="tab-ems" class="tab-content">

  <div class="card" style="margin-bottom:12px;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <div class="card-title" style="margin-bottom:0;">Control Mode</div>
      <div style="display:flex;gap:6px;">
        <button class="btn btn-sm" onclick="forceFetch()">↺ Fetch Now</button>
      </div>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:12px;">
      <button class="mode-btn active-auto" id="btn-auto" onclick="setControlMode('auto')">🤖 AUTO</button>
      <button class="mode-btn" id="btn-manual" onclick="setControlMode('manual')">✋ MANUAL</button>
    </div>
    <div id="manual-actions" class="manual-actions disabled">
      <div class="card-title">Output priority</div>
      <div style="display:flex;gap:8px;margin-bottom:10px;">
        <button class="btn btn-green" style="flex:1;" onclick="manualMode('cheap')">🔋⚡ Grid Charging<br><small style="opacity:.7">SUB · grid charges battery</small></button>
        <button class="btn btn-amber" style="flex:1;" onclick="manualMode('expensive')">☀️🔋 Solar / Battery<br><small style="opacity:.7">SBU · grid does not charge</small></button>
      </div>
      <div class="card-title">Charge priority</div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-violet" style="flex:1;" onclick="setChargeMode(2)">⚡ Hybrid<br><small style="opacity:.7">PV + Grid</small></button>
        <button class="btn btn-amber" style="flex:1;" onclick="setChargeMode(3)">☀️ PV Only<br><small style="opacity:.7">No mains</small></button>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:12px;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <div class="card-title" style="margin-bottom:0;">EMS Status</div>
    </div>
    <div id="ems-status-detail"></div>
  </div>

  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <div class="card-title" style="margin-bottom:0;">Cheap Slots</div>
      <span id="slots-count-badge" style="font-size:10px;color:var(--muted);"></span>
    </div>
    <div id="slots-timeline"></div>
  </div>
</div>

<!-- ── HISTORY TAB ──────────────────────────────────── -->
<div id="tab-history" class="tab-content">
  <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center;">
    <span style="font-size:11px;color:var(--muted);">Show last:</span>
    <button class="btn btn-sm" onclick="loadHistory(6)">6h</button>
    <button class="btn btn-sm" onclick="loadHistory(24)">24h</button>
    <button class="btn btn-sm" onclick="loadHistory(72)">3d</button>
    <button class="btn btn-sm" onclick="loadHistory(168)">7d</button>
  </div>
  <div class="card" style="margin-bottom:12px;">
    <div class="card-title">PV / Load / Battery Power</div>
    <div class="chart-wrap" style="height:220px"><canvas id="chart-main"></canvas></div>
    <div class="chart-legend">
      <div class="legend-item"><div class="legend-dot" style="background:var(--amber)"></div>Solar W</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--red)"></div>Load W</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--blue)"></div>Battery W</div>
    </div>
  </div>
  <div class="card" style="margin-bottom:12px;">
    <div class="card-title">Battery SOC %</div>
    <div class="chart-wrap" style="height:160px"><canvas id="chart-soc"></canvas></div>
  </div>
  <div class="card">
    <div class="card-title">Electricity Price (p/kWh)</div>
    <div class="chart-wrap" style="height:160px"><canvas id="chart-price"></canvas></div>
  </div>
</div>

<!-- ── DAILY TAB ──────────────────────────────────── -->
<div id="tab-daily" class="tab-content">
  <div class="grid-3" style="margin-bottom:8px;">
    <div class="card stat-amber"><div class="card-title">Avg daily PV</div><div><span class="card-val" id="ds-avg-pv">--</span><span class="card-unit">kWh</span></div></div>
    <div class="card stat-red"><div class="card-title">Avg daily grid</div><div><span class="card-val" id="ds-avg-grid">--</span><span class="card-unit">kWh</span></div></div>
    <div class="card stat-green"><div class="card-title">Avg daily load</div><div><span class="card-val" id="ds-avg-load">--</span><span class="card-unit">kWh</span></div></div>
  </div>
  <div id="ds-data-days" style="font-size:10px;color:var(--muted);margin-bottom:12px;"></div>
  <div class="card" style="margin-bottom:12px;">
    <div class="card-title">Daily records (inverter registers)</div>
    <div style="display:grid;grid-template-columns:72px 1fr 1fr 1fr 1fr 1fr;gap:4px;padding:5px 0 8px;font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);">
      <div>Date</div><div>PV kWh</div><div>Inv load kWh</div><div>Mains total kWh</div><div>Bat ch AH</div><div>SOC</div>
    </div>
    <div id="daily-records"></div>
  </div>
</div>

<!-- ── WEATHER TAB ──────────────────────────────────── -->
<div id="tab-weather" class="tab-content">
  <div class="card" style="margin-bottom:12px;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <div class="card-title" style="margin-bottom:0;">Location & Weather</div>
      <button class="btn btn-sm" onclick="forceRefreshWeather()">↻ Refresh</button>
    </div>
    <div id="wx-location" style="font-size:12px;color:var(--blue);margin-bottom:8px;">--</div>
    <div class="metric-row"><span class="label">☁️ Now</span><span class="value" id="wx-cloud-now">--</span></div>
    <div class="metric-row"><span class="label">Today avg cloud</span><span class="value" id="wx-cloud-today">--</span></div>
    <div class="metric-row"><span class="label">Last fetch</span><span class="value" id="wx-fetched">--</span></div>
  </div>

  <div class="card" style="margin-bottom:12px;">
    <div class="card-title" style="margin-bottom:10px;">3-day PV forecast</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;" id="wx-forecast"></div>
  </div>

  <div class="card" style="margin-bottom:12px;">
    <div class="card-title" style="margin-bottom:10px;">Optimizer</div>
    <div id="optimizer-status"></div>
  </div>

  <div class="card">
    <div class="card-title" style="margin-bottom:10px;">Fault Status</div>
    <div id="fault-status"></div>
  </div>
</div>

</main>

<!-- ── SETTINGS MODAL ──────────────────────────────────── -->
<div class="modal-bg" id="modal-bg" onclick="if(event.target===this)closeSettings()">
  <div class="modal">
    <div class="modal-title">
      ⚙ Settings
      <button class="btn btn-sm" onclick="closeSettings()">✕</button>
    </div>
    <div class="field-group">
      <div class="field-label">🔑 Octopus API Key</div>
      <input id="s-api-key" type="password" placeholder="sk_live_... (leave blank to keep current)">
    </div>
    <div class="field-group">
      <div class="field-label">⚡ Tariff type</div>
      <select id="s-tariff-type" onchange="toggleTariffFields()">
        <option value="agile">Octopus Agile (dynamic pricing)</option>
        <option value="tibber">Tibber (DE / NL / NO / SE / FI / DK)</option>
        <option value="pvpc">PVPC – Spain (free API)</option>
        <option value="fixed">Fixed cheap window (Economy7 / Octopus Go / E.ON etc.)</option>
        <option value="flat">Flat rate (no time-of-use)</option>
      </select>
    </div>
    <div id="s-tibber-fields" style="display:none;">
    <div class="field-group">
      <div class="field-label">🔑 Tibber API Key</div>
      <input id="s-tibber-key" type="password" placeholder="leave blank to keep current">
      <div style="font-size:9px;color:var(--muted);margin-top:3px;">Get yours at tibber.com/developer</div>
    </div>
    </div>
    <div id="s-agile-fields">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
      <div class="field-group">
        <div class="field-label">Product code</div>
        <input id="s-product" placeholder="AGILE-24-10-01">
      </div>
      <div class="field-group">
        <div class="field-label">Tariff code</div>
        <input id="s-tariff-code" placeholder="E-1R-AGILE-24-10-01-B">
      </div>
    </div>
    </div>
    <div id="s-fixed-fields" style="display:none;">
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;">
      <div class="field-group">
        <div class="field-label">Cheap from (hour)</div>
        <input id="s-win-start" type="number" min="0" max="23" placeholder="0">
      </div>
      <div class="field-group">
        <div class="field-label">Cheap until (hour)</div>
        <input id="s-win-end" type="number" min="0" max="23" placeholder="7">
      </div>
      <div class="field-group">
        <div class="field-label">Cheap rate (p/kWh)</div>
        <input id="s-fixed-price" type="number" step="0.1" placeholder="9.0">
      </div>
    </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;">
      <div class="field-group">
        <div class="field-label">Min SOC (%)</div>
        <input id="s-min-soc" type="number" min="10" max="50">
      </div>
      <div class="field-group">
        <div class="field-label">Max SOC (%)</div>
        <input id="s-max-soc" type="number" min="50" max="100">
      </div>
      <div class="field-group">
        <div class="field-label">Peak threshold (p)</div>
        <input id="s-threshold" type="number" step="0.5">
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
      <div class="field-group">
        <div class="field-label">🌍 Timezone (IANA)</div>
        <input id="s-timezone" placeholder="Europe/London">
        <div style="font-size:9px;color:var(--muted);margin-top:3px;">e.g. America/New_York · America/Los_Angeles · Europe/Berlin</div>
      </div>
      <div class="field-group">
        <div class="field-label">💱 Currency symbol</div>
        <input id="s-currency" placeholder="p" style="max-width:80px;">
        <div style="font-size:9px;color:var(--muted);margin-top:3px;">p · ¢ · ct · €</div>
      </div>
    </div>
    <div class="field-group" style="flex-direction:row;align-items:center;gap:10px;">
      <input id="s-auto-enabled" type="checkbox" style="width:auto;">
      <label for="s-auto-enabled" style="font-size:12px;color:var(--text);cursor:pointer;">Automation enabled</label>
    </div>
    <div style="border:1px solid var(--border);border-radius:8px;padding:12px;background:var(--bg3);margin-bottom:10px;">
      <div class="field-label" style="margin-bottom:10px;">📍 Location (blank = auto)</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
        <div class="field-group" style="margin-bottom:0;">
          <div class="field-label">Latitude</div>
          <input id="s-lat" type="number" step="0.001" placeholder="53.076">
        </div>
        <div class="field-group" style="margin-bottom:0;">
          <div class="field-label">Longitude</div>
          <input id="s-lon" type="number" step="0.001" placeholder="-0.812">
        </div>
        <div class="field-group" style="margin-bottom:0;">
          <div class="field-label">City</div>
          <input id="s-city" placeholder="Newark">
        </div>
      </div>
      <div style="font-size:10px;color:var(--muted);margin-top:6px;">Current: <span id="s-loc-hint" style="color:var(--blue)">--</span></div>
    </div>
    <div class="row-btns">
      <button class="btn btn-primary" onclick="saveSettings()">💾 Save</button>
      <button class="btn" id="btn-test-octopus" onclick="testOctopus()">🧪 Test Octopus</button>
      <button class="btn" id="btn-test-tibber" style="display:none;" onclick="testTibber()">🧪 Test Tibber</button>
      <button class="btn" onclick="closeSettings()">Cancel</button>
    </div>
    <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
      <span style="font-size:10px;color:var(--dim);" id="s-ver-label">Flux EMS Pro</span>
      <button class="btn btn-sm" onclick="toggleAutostart()" id="autostart-btn">⚙ Autostart: checking...</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
// ── Utils ──────────────────────────────────────────────────
function showToast(msg,ok=true){const t=document.getElementById('toast');t.textContent=msg;t.className='toast '+(ok?'ok':'err');t.style.display='block';setTimeout(()=>t.style.display='none',2800);}
function fmt(v,dec=0,suf=''){return v===null||v===undefined?'--':(+v).toFixed(dec)+suf;}
function safe(fn){return async function(){try{await fn();}catch(e){console.warn(fn.name,e.message);}}}
// ── Localisation globals (loaded from config) ───────────────
let _TZ='Europe/London';
let _CUR='p';
async function loadLocale(){
  try{
    const c=await fetch('/api/get_config').then(r=>r.json());
    _TZ=c.timezone||'Europe/London';
    _CUR=c.currency_symbol||'p';
  }catch(e){}
}
function fmtPrice(p){return p!=null?p.toFixed(2)+_CUR:'--';}
function fmtTime(isoStr){
  try{return new Intl.DateTimeFormat('en-GB',{hour:'2-digit',minute:'2-digit',timeZone:_TZ}).format(new Date(isoStr));}catch(e){return isoStr;}
}
function fmtDay(isoStr){
  try{return new Intl.DateTimeFormat('en-GB',{timeZone:_TZ,day:'2-digit',month:'2-digit'}).format(new Date(isoStr));}catch(e){return isoStr;}
}

// ── Tab switching ───────────────────────────────────────────
let activeTab='live';
function switchTab(id){
  document.querySelectorAll('.tab').forEach((t,i)=>{const ids=['live','ems','history','daily','weather'];t.classList.toggle('active',ids[i]===id);});
  document.querySelectorAll('.tab-content').forEach(c=>c.classList.toggle('active',c.id==='tab-'+id));
  activeTab=id;
  if(id==='history') loadHistory(24);
  if(id==='daily') loadDailyTab();
  if(id==='weather') loadWeatherTab();
}

// ── Live tab refresh ────────────────────────────────────────
const DEV_STATES={0:'Power-up',1:'Waiting',2:'Init',3:'Soft start',4:'Mains ⚡',5:'Inverter 🔋',6:'→Mains',7:'→Inverter',8:'Bat activate',9:'Shutdown',10:'Fault ⚠'};
const CHG_STATES={0:'Off',1:'Quick charge',2:'Const V',4:'Float',6:'Li activate',8:'Full ✓'};
const OP_LABELS={0:'Solar Only',1:'Grid Priority',2:'SBU',3:'SUB'};

async function refreshLive(){
  const d=await fetch('/api/telemetry').then(r=>r.json());
  const dot=document.getElementById('conn-dot'), lbl=document.getElementById('conn-label');
  const ok=d.poll_errors===0 && d.last_good_poll;
  dot.className='conn-dot '+(ok?'ok':'err');
  lbl.textContent=ok?('Last: '+d.last_good_poll):'No data';
  // Price badge
  const pb=document.getElementById('price-badge');
  pb.textContent=d.price_now!=null?fmtPrice(d.price_now):'--';
  pb.style.color=d.price_now!=null?(d.price_now>30?'var(--red)':d.price_now>20?'var(--amber)':'var(--green)'):'var(--amber)';
  // SOC
  const soc=d.soc;
  document.getElementById('m-soc').textContent=fmt(soc);
  const bar=document.getElementById('soc-bar');
  bar.style.width=(soc||0)+'%';
  bar.className='soc-bar-fill'+(soc<20?' low':soc<40?' mid':'');
  const bp=d.bat_p;
  const bst=document.getElementById('m-bat-status');
  if(bp!=null){bst.textContent=bp>50?'▲ Charging':bp<-50?'▼ Discharging':'◆ Idle';bst.style.color=bp>50?'var(--green)':bp<-50?'var(--amber)':'var(--muted)';}
  // Big cards
  document.getElementById('m-pv').textContent=fmt(d.pv1_p);
  document.getElementById('m-load').textContent=fmt(d.load_p);
  document.getElementById('m-bat-p').textContent=fmt(bp);
  document.getElementById('m-pv-today').textContent='Today: '+(d.total_pv_generation!=null?d.total_pv_generation.toFixed(2):'-')+' kWh';
  document.getElementById('m-load-today').textContent='Today: '+(d.total_load_consumption!=null?d.total_load_consumption.toFixed(2):'-')+' kWh';
  const bdir=document.getElementById('m-bat-dir');
  if(bp!=null){bdir.textContent=bp>50?'▲ Grid/Solar → Battery':bp<-50?'▼ Battery → House':'◆ Idle';bdir.style.color=bp>50?'var(--green)':bp<-50?'var(--amber)':'var(--muted)';}
  // Secondary
  document.getElementById('d-bat-v').textContent=fmt(d.bat_v,1)+' V';
  document.getElementById('d-bat-i').textContent=fmt(d.bat_i,1)+' A';
  document.getElementById('d-bat-t').textContent=fmt(d.controller_temp)+'°C';
  document.getElementById('d-grid-v').textContent=fmt(d.grid_v,1)+' V';
  document.getElementById('d-grid-hz').textContent=fmt(d.grid_freq,2)+' Hz';
  document.getElementById('d-load-pf').textContent=fmt(d.load_pf,2);
  document.getElementById('d-out-pri').textContent=OP_LABELS[d.output_priority]||fmt(d.output_priority);
  document.getElementById('d-run').textContent=d.uptime||'--';
}

// ── EMS tab refresh ─────────────────────────────────────────
let currentControlMode='auto';
async function refreshEMS(){
  const d=await fetch('/api/ems_status').then(r=>r.json());
  // Header mode badge
  const mb=document.getElementById('mode-badge');
  if(d.control_mode==='manual'){mb.textContent='MANUAL';mb.className='mode-badge manual';}
  else if(d.current_mode&&d.current_mode.includes('Cheap')){mb.textContent='CHEAP';mb.className='mode-badge cheap';}
  else if(d.current_mode&&d.current_mode.includes('Protect')){mb.textContent='PROTECT';mb.className='mode-badge';}
  else{mb.textContent='SBU';mb.className='mode-badge expensive';}
  // Charge mode
  document.getElementById('d-chg-mode').textContent=d.charge_mode||'--';
  // Status detail
  const div=document.getElementById('ems-status-detail');div.innerHTML='';
  const row=(l,v,col='')=>{
    const p=document.createElement('div');p.className='metric-row';
    p.innerHTML=`<span class="label">${l}</span><span class="value" style="color:${col||'var(--text)'}">${v??'--'}</span>`;
    div.appendChild(p);
  };
  const isCheap=d.current_mode&&d.current_mode.includes('Cheap');
  const isProtect=d.current_mode&&d.current_mode.includes('Protect');
  const modeLabel=isCheap?'🔋⚡ Grid Charging':isProtect?'⚠️ Battery Protect (Grid Load)':'☀️🔋 Solar/Battery';
  const modeCol=isCheap?'var(--green)':isProtect?'var(--red)':'var(--amber)';
  row('Mode', modeLabel, modeCol);
  row('Charge mode', d.charge_mode, d.charge_mode==='Hybrid'?'var(--green)':d.charge_mode==='PV-only'?'var(--amber)':'var(--muted)');
  if(d.last_mode_change) row('Last mode change', d.last_mode_change, 'var(--muted)');
  if(d.last_error) row('⚠️ Error', d.last_error, 'var(--red)');
  if(d.next_cheap_slot){
    const dt=new Date(d.next_cheap_slot.start);
    const ts=fmtTime(d.next_cheap_slot.start);
    row('Next cheap slot', ts+' · '+fmtPrice(d.next_cheap_slot.price), 'var(--green)');
  } else row('Next cheap slot', 'None today', 'var(--muted)');
  row('Slots planned', (d.cheap_slots?d.cheap_slots.length:0)+' slots', 'var(--blue)');
  if(d.high_consumer_active) row('⚡ High consumer', 'Protection active', 'var(--red)');
  if(d.slots_status) row('Status', d.slots_status, 'var(--muted)');
  // Control mode buttons
  if(d.control_mode&&d.control_mode!==currentControlMode){
    currentControlMode=d.control_mode;
    _syncControlBtns(currentControlMode);
  }
  // Slots timeline
  renderSlotsTimeline(d.cheap_slots, d.slots_status);
  const sb=document.getElementById('slots-count-badge');
  if(sb) sb.textContent=d.cheap_slots?d.cheap_slots.length+' slots':'';
}

function _syncControlBtns(mode){
  const ba=document.getElementById('btn-auto'), bm=document.getElementById('btn-manual');
  const ma=document.getElementById('manual-actions');
  if(mode==='auto'){
    ba.className='mode-btn active-auto';bm.className='mode-btn';
    if(ma)ma.classList.add('disabled');
  } else {
    ba.className='mode-btn';bm.className='mode-btn active-manual';
    if(ma)ma.classList.remove('disabled');
  }
}

function setControlMode(mode){
  currentControlMode=mode;
  _syncControlBtns(mode);
  fetch('/api/set_control_mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})})
    .then(r=>r.json()).then(d=>showToast(d.message||mode,d.success));
}
function manualMode(mode){
  if(currentControlMode!=='manual'){showToast('❌ Switch to MANUAL first!',false);return;}
  fetch('/api/set_mode_manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})})
    .then(r=>r.json()).then(d=>showToast(d.message||mode,d.success));
}
async function setChargeMode(mode){
  if(currentControlMode!=='manual'){showToast('❌ Switch to MANUAL first!',false);return;}
  const d=await fetch('/api/set_charge_mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})}).then(r=>r.json());
  showToast(d.message||'Charge mode set',d.success);
}

function renderSlotsTimeline(slots, slotsStatus){
  const cont=document.getElementById('slots-timeline');if(!cont)return;
  cont.innerHTML='';
  if(!slots||!slots.length){
    const msg=slotsStatus||'No cheap slots';
    const isErr=msg.startsWith('error:')||msg.includes('check API key');
    cont.innerHTML=`<div style="color:${isErr?'var(--red)':'var(--muted)'};font-size:11px;padding:8px 0;">${msg}</div>`;
    return;
  }
  const prices=slots.map(s=>s.price);
  const pmin=Math.min(...prices),pmax=Math.max(...prices);
  const nowMs=Date.now();
  let lastDay='';
  for(const s of slots){
    const dt=new Date(s.start), dtEnd=new Date(s.end);
    const dayStr=fmtDay(s.start);
    const timeStr=fmtTime(s.start);
    const isActive=dt.getTime()<=nowMs&&nowMs<dtEnd.getTime();
    const isPast=dtEnd.getTime()<nowMs;
    const ratio=pmax===pmin?0.5:(s.price-pmin)/(pmax-pmin);
    const col=ratio>0.66?'var(--red)':ratio>0.33?'var(--amber)':'var(--green)';
    if(dayStr!==lastDay){
      lastDay=dayStr;
      const hdr=document.createElement('div');
      hdr.className='slot-day-hdr';hdr.textContent='── '+dayStr+' ──';
      cont.appendChild(hdr);
    }
    const div=document.createElement('div');
    div.className='slot-item'+(isPast?' past':isActive?' active':'');
    div.style.borderColor=col;
    div.innerHTML=`
      <div style="display:flex;align-items:center;gap:6px;">
        ${isActive?'<span style="width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block;box-shadow:0 0 6px var(--green)"></span>':''}
        <span>${timeStr}</span>
        ${isActive?'<span style="font-size:9px;color:var(--green);">ACTIVE</span>':''}
      </div>
      <span style="color:${col};font-weight:600;">${fmtPrice(s.price)}</span>`;
    cont.appendChild(div);
  }
}

// ── Chart.js helpers ────────────────────────────────────────
const CHART_DEFAULTS={
  responsive:true,maintainAspectRatio:false,
  animation:{duration:300},
  interaction:{mode:'index',intersect:false},
  plugins:{
    legend:{display:false},
    tooltip:{
      backgroundColor:'#0f1e30',borderColor:'#243d58',borderWidth:1,
      titleColor:'#5a7fa0',bodyColor:'#d4e8f7',
      titleFont:{family:'DM Mono',size:10},bodyFont:{family:'DM Mono',size:11},
    }
  },
  scales:{
    x:{grid:{color:'rgba(26,45,68,0.5)'},ticks:{color:'#5a7fa0',font:{family:'DM Mono',size:9},maxRotation:0,callback:function(val,i){return this.getLabelForValue(i)||null;}}},
    y:{grid:{color:'rgba(26,45,68,0.5)'},ticks:{color:'#5a7fa0',font:{family:'DM Mono',size:9},maxTicksLimit:8}}
  }
};
const _charts={};
function rebuildChart(id,cfg){
  if(_charts[id]){_charts[id].destroy();delete _charts[id];}
  const cv=document.getElementById(id);if(!cv)return;
  _charts[id]=new Chart(cv,cfg);
}
// alias a régi hívásokhoz
function getOrCreateChart(id,cfg){rebuildChart(id,cfg);return _charts[id]||null;}
function subsample(rows,max=200){if(rows.length<=max)return rows;const step=Math.ceil(rows.length/max);return rows.filter((_,i)=>i%step===0);}
function makeXLabels(rows){return rows.map(r=>{try{const d=new Date(r.t);const m=d.getMinutes();if(m===0||m===30)return d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});return '';}catch{return '';}});}
function smartYMax(data,minMax=200){const vals=data.filter(v=>v!=null);if(!vals.length)return minMax;const mx=Math.max(...vals.map(Math.abs));return Math.max(Math.ceil((mx+50)/50)*50,minMax);}
function fmtLabel(ts){try{return new Date(ts).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});}catch{return ts;}}

let _histHours=24;
async function loadHistory(hours){
  if(hours!=null) _histHours=hours;
  const d=await fetch('/api/history?hours='+_histHours).then(r=>r.json());
  if(!d.ok||!d.rows||!d.rows.length){
    ['chart-main','chart-soc','chart-price'].forEach(id=>{
      if(_charts[id]){_charts[id].destroy();delete _charts[id];}
      const cv=document.getElementById(id);if(!cv)return;
      const ctx=cv.getContext('2d');cv.width=cv.clientWidth;cv.height=cv.clientHeight;
      ctx.fillStyle='#080f17';ctx.fillRect(0,0,cv.width,cv.height);
      ctx.fillStyle='#5a7fa0';ctx.font='12px DM Mono,monospace';ctx.textAlign='center';
      ctx.fillText('No history yet — records every 5 min',cv.width/2,cv.height/2);
    });return;
  }
  const rows=subsample(d.rows);
  const labels=makeXLabels(rows);
  const pvData=rows.map(r=>r.pv);
  const loadData=rows.map(r=>r.load);
  const batData=rows.map(r=>r.bat_p);
  const yMax=smartYMax([...pvData,...loadData,...batData],200);
  getOrCreateChart('chart-main',{type:'line',data:{labels,datasets:[
    {label:'Solar W',data:pvData,borderColor:'#f59e0b',backgroundColor:'rgba(245,158,11,0.08)',borderWidth:1.5,pointRadius:0,tension:0.2,fill:true,spanGaps:true},
    {label:'Load W',data:loadData,borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,0.06)',borderWidth:1.5,pointRadius:0,tension:0.2,fill:true,spanGaps:true},
    {label:'Battery W',data:batData,borderColor:'#38bdf8',backgroundColor:'rgba(56,189,248,0.06)',borderWidth:1.5,pointRadius:0,tension:0.2,fill:true,spanGaps:true},
  ]},options:{...CHART_DEFAULTS,plugins:{...CHART_DEFAULTS.plugins,tooltip:{...CHART_DEFAULTS.plugins.tooltip,callbacks:{title:items=>'⏱ '+fmtLabel(rows[items[0]?.dataIndex]?.t||''),label:item=>` ${item.dataset.label}: ${item.parsed.y!=null?Math.round(item.parsed.y):'--'} W`}}},scales:{x:{...CHART_DEFAULTS.scales.x},y:{...CHART_DEFAULTS.scales.y,min:-yMax,max:yMax,title:{display:true,text:'Watts',color:'#5a7fa0',font:{size:9}}}}}});
  getOrCreateChart('chart-soc',{type:'line',data:{labels,datasets:[{label:'SOC %',data:rows.map(r=>r.soc),borderColor:'#22c55e',backgroundColor:'rgba(34,197,94,0.1)',borderWidth:1.5,pointRadius:0,tension:0.3,fill:true,spanGaps:true}]},options:{...CHART_DEFAULTS,plugins:{...CHART_DEFAULTS.plugins,tooltip:{...CHART_DEFAULTS.plugins.tooltip,callbacks:{title:items=>'⏱ '+fmtLabel(rows[items[0]?.dataIndex]?.t||''),label:item=>` SOC: ${item.parsed.y!=null?item.parsed.y.toFixed(0):'--'}%`}}},scales:{x:{...CHART_DEFAULTS.scales.x},y:{...CHART_DEFAULTS.scales.y,min:0,max:100}}}});
  const prVals=rows.map(r=>r.price).filter(v=>v!=null);
  if(prVals.length>1){
    const prMin=Math.floor(Math.min(...prVals)/5)*5,prMax=Math.ceil(Math.max(...prVals)/5)*5+5;
    getOrCreateChart('chart-price',{type:'line',data:{labels,datasets:[{label:'p/kWh',data:rows.map(r=>r.price),borderColor:'#a78bfa',backgroundColor:'rgba(167,139,250,0.08)',borderWidth:1.5,pointRadius:0,tension:0.1,fill:true,spanGaps:true}]},options:{...CHART_DEFAULTS,plugins:{...CHART_DEFAULTS.plugins,tooltip:{...CHART_DEFAULTS.plugins.tooltip,callbacks:{title:items=>'⏱ '+fmtLabel(rows[items[0]?.dataIndex]?.t||''),label:item=>` Price: ${item.parsed.y!=null?item.parsed.y.toFixed(2):'--'} p/kWh`}}},scales:{x:{...CHART_DEFAULTS.scales.x},y:{...CHART_DEFAULTS.scales.y,min:prMin,max:prMax}}}});
  }
}

// ── Daily tab ───────────────────────────────────────────────
async function loadDailyTab(){
  // Primary source: inverter history registers (always 7+1 days, no CSV needed)
  const d=await fetch('/api/inverter_history').then(r=>r.json());
  const days=d.days||[];
  const validDays=days.filter(r=>r.pv_kwh!=null&&r.pv_kwh>0);
  if(validDays.length>0){
    const avgPv=validDays.reduce((s,r)=>s+(r.pv_kwh||0),0)/validDays.length;
    const avgGrid=validDays.reduce((s,r)=>s+(r.mains_load_kwh||0),0)/validDays.length;
    const avgLoad=validDays.reduce((s,r)=>s+(r.load_kwh||0),0)/validDays.length;
    document.getElementById('ds-avg-pv').textContent=avgPv.toFixed(2);
    document.getElementById('ds-avg-grid').textContent=avgGrid.toFixed(2);
    document.getElementById('ds-avg-load').textContent=avgLoad>0?avgLoad.toFixed(2):'?';
  }
  const fetchedEl=document.getElementById('ds-data-days');
  if(fetchedEl&&d.fetched) fetchedEl.textContent=validDays.length+' days of data (last 8) — '+new Date(d.fetched).toLocaleTimeString();
  const tbl=document.getElementById('daily-records');tbl.innerHTML='';
  for(const r of [...days].reverse()){
    const row=document.createElement('div');row.className='daily-row';
    const pv=r.pv_kwh,ld=r.load_kwh,grid=r.mains_load_kwh,bch=r.bat_charge_ah;
    const pvW=pv!=null?Math.round(Math.min(pv/6*60,60)):0;
    const pvCol=pv>3?'var(--green)':pv>1?'var(--amber)':'var(--red)';
    const gridCol=grid>2?'var(--red)':grid>0.5?'var(--amber)':'var(--green)';
    const isToday=r.date===new Date().toISOString().slice(0,10);
    row.innerHTML=`
      <div style="color:${isToday?'var(--green)':'var(--muted)'};font-size:10px;">${r.date?r.date.slice(5):'-'}${isToday?' ★':''}</div>
      <div><span class="mini-bar" style="width:${pvW}px;background:${pvCol};"></span><span style="color:${pvCol};margin-left:4px;">${pv!=null?pv.toFixed(1):'-'}</span></div>
      <div style="color:var(--text)">${ld!=null?ld.toFixed(1):'-'}</div>
      <div style="color:${gridCol}">${grid!=null?grid.toFixed(1):'-'}</div>
      <div style="color:var(--blue)">${bch!=null?bch+' AH':'-'}</div>
      <div style="color:var(--violet)">${r.evening_soc!=null?r.evening_soc+'%':'-'}</div>`;
    tbl.appendChild(row);
  }
}

// ── Weather tab ─────────────────────────────────────────────
async function loadWeatherTab(){
  const d=await fetch('/api/optimizer').then(r=>r.json());
  document.getElementById('wx-location').textContent=d.location||'--';
  const w=d.weather||{};
  const cc=w.current_cloud;
  document.getElementById('wx-cloud-now').textContent=cc!=null?cc+'% ('+w.current_radiation+' W/m²)':'--';
  document.getElementById('wx-cloud-today').textContent=w.today_cloud_avg!=null?w.today_cloud_avg+'%':'--';
  document.getElementById('wx-fetched').textContent=w.last_fetch?new Date(w.last_fetch).toLocaleTimeString():'--';
  // Forecast pills
  const fc=document.getElementById('wx-forecast');fc.innerHTML='';
  for(const day of (w.forecast_days||[])){
    const cloudCol=day.cloud_avg>70?'var(--red)':day.cloud_avg>40?'var(--amber)':'var(--green)';
    fc.innerHTML+=`<div class="forecast-pill">
      <div class="date">${day.date.slice(5)}</div>
      <div class="pv">${day.pv_estimate_kwh} kWh</div>
      <div class="cloud" style="color:${cloudCol}">☁ ${day.cloud_avg}%</div>
    </div>`;
  }
  // Optimizer
  const opt=d.optimizer||{};
  const odiv=document.getElementById('optimizer-status');odiv.innerHTML='';
  const orow=(l,v,col='')=>{const p=document.createElement('div');p.className='metric-row';p.innerHTML=`<span class="label">${l}</span><span class="value" style="color:${col||'var(--text)'}">${v??'--'}</span>`;odiv.appendChild(p);};
  orow('Data days', opt.days_of_data+' days');
  orow('Avg daily PV', (opt.avg_daily_pv_kwh||0)+' kWh', 'var(--amber)');
  orow('Avg daily load', (opt.avg_daily_consumption_kwh||0)+' kWh', 'var(--red)');
  orow('Slots tonight', d.slots_tonight, 'var(--green)');
  if(d.hourly_patterns && d.hourly_patterns.data_points>0){
    const hp=d.hourly_patterns;
    orow('Solar window', hp.solar_start+':00 – '+hp.solar_end+':00', 'var(--amber)');
    orow('History points', hp.data_points+' readings', 'var(--muted)');
  }
  if(w.error) orow('Weather error', w.error.substring(0,80), 'var(--red)');
  // Faults
  await refreshFaultStatus();
}

async function refreshFaultStatus(){
  try{
    const d=await fetch('/api/fault_status').then(r=>r.json());
    const div=document.getElementById('fault-status');div.innerHTML='';
    if(!d.ok){div.innerHTML='<div style="color:var(--red);font-size:11px;">'+d.error+'</div>';return;}
    const f=d.faults;
    const frow=(l,v)=>{const p=document.createElement('div');p.className='metric-row';p.innerHTML=`<span class="label">${l}</span><span class="value" style="color:${v&&v>0?'var(--red)':'var(--muted)'}">${v??'--'}</span>`;div.appendChild(p);};
    frow('Fault Bits 1',f.fault_bits_1);frow('Fault Bits 2',f.fault_bits_2);
    frow('Fault Code 1',f.fault_code_1);frow('Fault Code 2',f.fault_code_2);
  }catch(e){}
}

async function refreshStatistics(){
  try{
    // CSV-alapú értékek (V*I, megbízható minden módban)
    const e=await fetch('/api/today_energy').then(r=>r.json());
    const kw=v=>v!=null?v.toFixed(2)+' kWh':'--';
    document.getElementById('s-pv-today').textContent=kw(e.pv_kwh);
    document.getElementById('s-chg-today').textContent=kw(e.bat_charge_kwh);
    document.getElementById('s-load-today').textContent=kw(e.grid_kwh);
    document.getElementById('s-run-days').textContent=kw(e.bat_discharge_kwh);
  }catch(e){}
}

async function forceRefreshWeather(){
  showToast('Refreshing weather…',true);
  await fetch('/api/refresh_weather',{method:'POST'}).catch(()=>{});
  setTimeout(loadWeatherTab,2000);
}

async function forceFetch(){
  const btn=event.currentTarget;btn.disabled=true;btn.textContent='…';
  try{
    const d=await fetch('/api/force_fetch',{method:'POST'}).then(r=>r.json());
    if(d.ok)showToast('OK: '+d.msg,true); else showToast('ERR: '+d.error,false);
  }catch(e){showToast(e.message,false);}
  btn.disabled=false;btn.textContent='↺ Fetch Now';
  safeEMS();
}

// ── Settings modal ──────────────────────────────────────────
function toggleTariffFields(){
  const t=document.getElementById('s-tariff-type').value;
  document.getElementById('s-agile-fields').style.display=t==='agile'?'':'none';
  document.getElementById('s-tibber-fields').style.display=t==='tibber'?'':'none';
  document.getElementById('s-fixed-fields').style.display=t==='fixed'?'':'none';
  const btnO=document.getElementById('btn-test-octopus');
  const btnT=document.getElementById('btn-test-tibber');
  if(btnO) btnO.style.display=t==='agile'?'':'none';
  if(btnT) btnT.style.display=t==='tibber'?'':'none';
}
async function openSettings(){
  const c=await fetch('/api/get_config').then(r=>r.json());
  const s=id=>document.getElementById(id);
  s('s-tariff-type').value=c.tariff_type||'agile';
  toggleTariffFields();
  s('s-timezone').value=c.timezone||'Europe/London';
  s('s-currency').value=c.currency_symbol||'p';
  s('s-tibber-key').value='';  // never pre-fill password fields
  s('s-product').value=c.product_code||'';
  s('s-tariff-code').value=c.tariff_code||'';
  s('s-win-start').value=c.cheap_window_start??0;
  s('s-win-end').value=c.cheap_window_end??7;
  s('s-fixed-price').value=c.cheap_price_fixed||9.0;
  s('s-min-soc').value=c.min_soc||20;
  s('s-max-soc').value=c.max_soc||90;
  s('s-threshold').value=c.expensive_threshold||25;
  s('s-auto-enabled').checked=!!c.automation_enabled;
  s('s-lat').value=c.manual_lat!=null?c.manual_lat:'';
  s('s-lon').value=c.manual_lon!=null?c.manual_lon:'';
  s('s-city').value=c.manual_city||'';
  const verEl=document.getElementById('s-ver-label');
  try{const vd=await fetch('/api/version').then(r=>r.json());if(verEl)verEl.textContent=vd.name+' v'+vd.version+' ('+vd.build_date+')';}catch(e){}
  const hint=document.getElementById('s-loc-hint');
  if(hint){try{const od=await fetch('/api/optimizer').then(r=>r.json()).catch(()=>({}));hint.textContent=od.location||'unknown';}catch(e){}}
  document.getElementById('modal-bg').classList.add('open');
}
function closeSettings(){document.getElementById('modal-bg').classList.remove('open');}
async function saveSettings(){
  const v=id=>document.getElementById(id)?.value;
  const mlat=v('s-lat'),mlon=v('s-lon');
  const tariffType=v('s-tariff-type')||'agile';
  const payload={
    octopus_api_key: v('s-api-key'),
    tibber_api_key: v('s-tibber-key'),
    tariff_type: tariffType,
    timezone: v('s-timezone')||'Europe/London',
    currency_symbol: v('s-currency')||'p',
    product_code: v('s-product'),
    tariff_code: v('s-tariff-code'),
    cheap_window_start: parseInt(v('s-win-start')||'0'),
    cheap_window_end: parseInt(v('s-win-end')||'7'),
    cheap_price_fixed: parseFloat(v('s-fixed-price')||'9.0'),
    min_soc: parseInt(v('s-min-soc')||'20'),
    max_soc: parseInt(v('s-max-soc')||'90'),
    expensive_threshold: parseFloat(v('s-threshold')||'25'),
    automation_enabled: document.getElementById('s-auto-enabled').checked,
    manual_lat: mlat?parseFloat(mlat):null,
    manual_lon: mlon?parseFloat(mlon):null,
    manual_city: v('s-city')||null,
  };
  const d=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}).then(r=>r.json());
  if(d.ok){showToast('Settings saved ✅',true);closeSettings();loadLocale();}
  else showToast(d.error||'Save failed',false);
}
async function testOctopus(){
  const d=await fetch('/api/test_octopus').then(r=>r.json());
  if(d.ok)showToast('Octopus OK, '+d.count+' slots',true);
  else showToast(d.error||'Error',false);
}
async function testTibber(){
  const d=await fetch('/api/test_tibber').then(r=>r.json());
  if(d.ok)showToast('Tibber OK, '+d.count+' slots',true);
  else showToast(d.error||'Error',false);
}
async function toggleAutostart(){
  const btn=document.getElementById('autostart-btn');
  const isOn=btn.dataset.enabled==='true';
  btn.textContent='⚙ Autostart: …';
  try{
    const d=await fetch('/api/autostart',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:isOn?'disable':'enable'})}).then(r=>r.json());
    btn.dataset.enabled=(!isOn)?'true':'false';
    btn.textContent=(!isOn)?'⚙ Autostart: ON ✅':'⚙ Autostart: OFF';
    showToast((!isOn)?'Autostart enabled':'Autostart disabled',true);
  }catch(e){btn.textContent='⚙ Autostart: N/A';}
}
async function stopApp(){
  if(!confirm('Stop Flux EMS Pro?'))return;
  await fetch('/api/shutdown',{method:'POST'}).catch(()=>{});
  document.body.innerHTML='<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:var(--muted);font-size:14px;">Application stopped.</div>';
}

// ── Polling ─────────────────────────────────────────────────
function safe(fn){return async function(){try{await fn();}catch(e){console.warn(fn.name,e.message);}}}
const safeEMS=safe(refreshEMS), safeLive=safe(refreshLive);
const safeStats=safe(refreshStatistics);

setInterval(()=>{if(activeTab==='live'){safeLive();safeStats();}},5000);
setInterval(()=>{if(activeTab==='ems')safeEMS();},5000);
setInterval(()=>{if(activeTab==='history')loadHistory();},30000);
setInterval(()=>{if(activeTab==='daily')loadDailyTab();},60000);
setInterval(()=>{if(activeTab==='weather')loadWeatherTab();},120000);

loadLocale().then(()=>{safeLive();safeEMS();safeStats();});
</script>

<!-- ── PAYWALL ────────────────────────────────────────────────────── -->
<div id="paywall" style="display:none;position:fixed;inset:0;
     background:rgba(5,10,15,0.97);z-index:9000;
     align-items:center;justify-content:center;backdrop-filter:blur(8px);">
  <div style="background:var(--bg2);border:1px solid var(--border2);border-radius:20px;
       padding:36px 32px;width:min(420px,92vw);text-align:center;
       box-shadow:0 50px 100px rgba(0,0,0,0.8);">
    <div style="font-family:'Syne',sans-serif;font-weight:800;font-size:26px;
         background:linear-gradient(135deg,var(--blue),var(--green));
         -webkit-background-clip:text;-webkit-text-fill-color:transparent;
         margin-bottom:8px;">Flux EMS Pro</div>
    <div style="color:var(--muted);font-size:12px;margin-bottom:6px;" id="paywall-msg">
      Trial period expired</div>
    <div style="color:var(--dim);font-size:11px;margin-bottom:24px;" id="paywall-sub">
      Subscribe to keep your system fully automated</div>
    <a href="https://buy.stripe.com/28E3cnfCu8la4bTci60Ba00" target="_blank"
       style="display:block;background:linear-gradient(135deg,#1d4ed8,#0891b2);
       color:white;border-radius:10px;padding:14px;text-decoration:none;
       font-family:'Syne',sans-serif;font-weight:700;font-size:14px;
       margin-bottom:20px;letter-spacing:0.5px;">
      🛒 Subscribe — £15.00/month</a>
    <div style="font-size:10px;color:var(--muted);margin-bottom:8px;letter-spacing:1px;
         text-transform:uppercase;">Already have a license key?</div>
    <input id="p-key" placeholder="XXXX-XXXX-XXXX-XXXX"
           style="text-align:center;letter-spacing:3px;font-size:15px;
                  font-family:'DM Mono',monospace;margin-bottom:10px;
                  background:var(--bg);border:1px solid var(--border2);
                  border-radius:8px;color:var(--text);padding:10px;">
    <button onclick="activateLicense()"
            style="width:100%;background:linear-gradient(135deg,#16a34a,#15803d);
            border:none;color:white;border-radius:8px;padding:11px;
            font-family:'Syne',sans-serif;font-weight:700;font-size:13px;
            cursor:pointer;letter-spacing:0.5px;">
      ✓ Activate</button>
    <div id="p-error" style="color:var(--red);font-size:11px;margin-top:10px;
         min-height:16px;"></div>
    <div style="margin-top:16px;font-size:10px;color:var(--dim);">
      <a href="mailto:fluxsignals@gmail.com"
         style="color:var(--dim);">fluxsignals@gmail.com</a>
    </div>
  </div>
</div>

<!-- ── MANAGE SUBSCRIPTION ────────────────────────────────────────────────────── -->
<div id="manage-sub-section" style="display:none;position:fixed;inset:0;
     background:rgba(5,10,15,0.97);z-index:9000;
     align-items:center;justify-content:center;backdrop-filter:blur(8px);">
  <div style="background:var(--bg2);border:1px solid var(--border2);border-radius:20px;
       padding:36px 32px;width:min(420px,92vw);text-align:center;
       box-shadow:0 50px 100px rgba(0,0,0,0.8);">
    <div style="font-family:'Syne',sans-serif;font-weight:800;font-size:26px;
         background:linear-gradient(135deg,var(--blue),var(--green));
         -webkit-background-clip:text;-webkit-text-fill-color:transparent;
         margin-bottom:8px;">Manage Subscription</div>
    <div style="color:var(--dim);font-size:12px;margin-bottom:24px;">
      View invoices, update payment method, or cancel</div>
    <button onclick="openCustomerPortal()"
            style="width:100%;background:linear-gradient(135deg,#1d4ed8,#0891b2);
            border:none;color:white;border-radius:8px;padding:12px;
            font-family:'Syne',sans-serif;font-weight:700;font-size:14px;
            cursor:pointer;letter-spacing:0.5px;margin-bottom:12px;">
      📋 Open Stripe Portal</button>
    <button onclick="document.getElementById('manage-sub-section').style.display='none'"
            style="width:100%;background:var(--surface2);color:var(--fg);
            border:1px solid var(--border);border-radius:8px;padding:11px;
            font-family:'Syne',sans-serif;font-weight:600;font-size:13px;
            cursor:pointer;">
      Close</button>
  </div>
</div>

<script>
// ── License ─────────────────────────────────────────────────────────────────
async function checkLicenseStatus(){
  try{
    const d=await fetch('/api/license_status').then(r=>r.json());
    const trialBadge=document.getElementById('trial-badge');
    const trialDays=document.getElementById('trial-days');

    if(!d.valid){
      const pw=document.getElementById('paywall');
      const msg=document.getElementById('paywall-msg');
      const sub=document.getElementById('paywall-sub');
      if(d.reason==='trial_expired'){
        msg.textContent='Your 14-day trial has expired';
        sub.textContent='Subscribe to keep your system fully automated';
      } else if(d.reason==='subscription_cancelled'){
        msg.textContent='Subscription cancelled';
        sub.textContent='Re-subscribe to restore automation';
      } else {
        msg.textContent='License required';
        sub.textContent=d.reason||'';
      }
      pw.style.display='flex';
      document.getElementById('manage-sub-section').style.display='none';
      trialBadge.style.display='none';
    } else if(d.reason&&d.reason.startsWith('trial:')){
      const days=parseInt(d.reason.split(':')[1]);
      trialDays.textContent=days;
      trialBadge.style.display='block';
      if(days<=3) showToast('⏰ Trial: '+days+' day'+(days===1?'':'s')+' left',true);
      document.getElementById('manage-sub-section').style.display='none';
    } else {
      document.getElementById('paywall').style.display='none';
      trialBadge.style.display='none';
      if(d.has_license){
        document.getElementById('manage-btn').style.display='block';
      }
    }
  }catch(e){}
}

async function activateLicense(){
  const keyInput=document.getElementById('p-key');
  const errDiv=document.getElementById('p-error');
  const key=keyInput.value.trim().toUpperCase().replace(/[^A-Z0-9]/g,'').replace(/(.{4})(?=.)/g,'$1-');
  errDiv.textContent='';
  if(key.length<19){errDiv.textContent='Please enter the full key (XXXX-XXXX-XXXX-XXXX)';return;}
  const btn=event.currentTarget;btn.disabled=true;btn.textContent='Activating…';
  try{
    const d=await fetch('/api/activate_license',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({license_key:key})
    }).then(r=>r.json());
    if(d.ok){
      document.getElementById('paywall').style.display='none';
      showToast('✅ License activated!',true);
      await checkLicenseStatus();  // Refresh UI immediately
    } else {
      errDiv.textContent=d.error||'Activation failed';
    }
  }catch(e){errDiv.textContent='Network error — check your connection';}
  btn.disabled=false;btn.textContent='✓ Activate';
}

async function openCustomerPortal(){
  try{
    const r=await fetch('/api/customer_portal');
    const d=await r.json();
    if(d.url){
      window.open(d.url,'_blank');
    } else {
      showToast('❌ Error: '+(d.error||'Unknown error'),true);
    }
  }catch(e){
    showToast('❌ Network error: '+e.message,true);
  }
}

// Auto-format key input: XXXX-XXXX-XXXX-XXXX
document.addEventListener('DOMContentLoaded',()=>{
  const ki=document.getElementById('p-key');
  if(ki) ki.addEventListener('input',function(){
    let v=this.value.toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,16);
    this.value=v.replace(/(.{4})(?=.)/g,'$1-');
  });
});

checkLicenseStatus();
// Check license status every 5 minutes (detect subscription changes faster)
setInterval(checkLicenseStatus, 5*60*1000); // Every 5 minutes
// ────────────────────────────────────────────────────────────────────────────
</script>

</body>
</html>
"""


@app.route("/api/autostart", methods=["POST"])
def api_autostart():
    data = request.get_json(force=True)
    action = data.get("action", "enable")
    if action == "enable":
        ok = register_windows_autostart()
    else:
        ok = remove_windows_autostart()
    return jsonify({"ok": ok, "action": action})

@app.route("/api/license_status")
def api_license_status():
    valid, reason = check_license()
    with config_lock:
        has_license = bool(config.get("license_key", "").strip())
    return jsonify({"valid": valid, "reason": reason, "has_license": has_license})

@app.route("/api/activate_license", methods=["POST"])
def api_activate_license():
    data = request.get_json(force=True)
    key  = data.get("license_key", "").strip().upper()
    if not key:
        return jsonify({"ok": False, "error": "No license key provided"})
    mid = get_machine_id()
    code_hash = _get_code_hash()
    try:
        session = requests.Session()
        session.trust_env = False
        r = session.post(
            f"{LICENSE_API}/activate",
            json={"license_key": key, "machine_id": mid, "code_hash": code_hash},
            timeout=10,
        )
        d = r.json()
        if d.get("ok"):
            with config_lock:
                config["license_key"]          = key
                config["license_grace_until"]  = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
                config["license_last_ok"]      = datetime.now(timezone.utc).isoformat()
            save_config()
        return jsonify(d)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/customer_portal", methods=["GET"])
def api_customer_portal():
    with config_lock:
        key = config.get("license_key", "").strip()
    if not key:
        return jsonify({"error": "No active subscription"}), 400
    try:
        session = requests.Session()
        session.trust_env = False
        r = session.post(f"{LICENSE_API}/portal", json={"license_key": key}, timeout=10)
        data = r.json()
        if data.get("url"):
            return jsonify({"url": data["url"]})
        return jsonify({"error": data.get("error", "Portal unavailable")}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/shutdown", methods=["POST"])
def api_shutdown():
    def _stop():
        time.sleep(0.5)
        os._exit(0)
    threading.Thread(target=_stop, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/api/version")
def api_version():
    return jsonify({
        "version": APP_VERSION,
        "name": APP_NAME,
        "build_date": BUILD_DATE,
        "python": __import__('sys').version.split()[0],
    })

@app.route("/")
def index():
    now = datetime.now(UK_TZ).strftime("%Y-%m-%d %H:%M:%S")
    with config_lock:
        cfg = config.copy()
    has_api_key = bool(cfg.get("octopus_api_key","").strip())
    return render_template_string(HTML, version=APP_VERSION, serial_port=SERIAL_PORT, baud=BAUD,
                                  now=now, cfg=cfg, has_api_key=has_api_key)

@app.route("/api/ems_status")
def api_ems_status():
    with ems_lock:
        return jsonify(ems_state.copy())

@app.route("/api/telemetry")
def api_telemetry():
    with telemetry_lock:
        t = telemetry.copy()
    try:
        has_live = any(t.get(k) is not None for k in ("soc","bat_v","bat_i","bat_p"))
        if not has_live and os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE,"r",encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            if rows:
                last = rows[-1]
                def pf(name):
                    val = last.get(name)
                    try: return float(val) if val and val!='' else None
                    except: return None
                t = t.copy()
                for k in ("timestamp","soc","bat_v","bat_i","bat_p","pv1_v","pv1_i","pv1_p",
                          "inv_v","load_i","load_p","grid_v","grid_freq","price_now",
                          "controller_temp","battery_temp","total_pv_generation","total_load_consumption"):
                    t[k] = last.get(k) if k=="timestamp" else pf(k)
    except Exception as e:
        print("[API] telemetry fallback error:", e)
    # Add human-readable output_mode from output_priority register
    pri = t.get("output_priority")
    if pri is not None:
        try:
            pri_int = int(float(pri))
            t["output_mode"] = "SUB" if pri_int == 3 else "SBU"
        except:
            t["output_mode"] = str(pri)
    else:
        # Fallback from ems_state
        with ems_lock:
            cm = ems_state.get("current_mode","")
        if "SUB" in cm:
            t["output_mode"] = "SUB"
        elif "SBU" in cm:
            t["output_mode"] = "SBU"
        else:
            t["output_mode"] = "--"
    # Add price_now if missing
    if t.get("price_now") is None:
        t["price_now"] = get_price_now()
    # Add script uptime
    secs = int(_time.time() - _SCRIPT_START)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    t["uptime"] = f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"
    return jsonify(t)

@app.route("/api/settings", methods=["POST"])
def api_settings():
    data = request.get_json(force=True)
    with config_lock:
        # Only update API keys if a new non-empty value is provided
        new_key = data.get("octopus_api_key","").strip()
        if new_key:
            config["octopus_api_key"] = new_key
        new_tibber_key = data.get("tibber_api_key","").strip()
        if new_tibber_key:
            config["tibber_api_key"] = new_tibber_key
        config["tariff_type"]         = data.get("tariff_type", config.get("tariff_type", "agile"))
        config["cheap_window_start"]  = int(data.get("cheap_window_start", config.get("cheap_window_start", 0)))
        config["cheap_window_end"]    = int(data.get("cheap_window_end", config.get("cheap_window_end", 7)))
        config["cheap_price_fixed"]   = float(data.get("cheap_price_fixed", config.get("cheap_price_fixed", 9.0)))
        config["timezone"]            = data.get("timezone", config.get("timezone", "Europe/London")).strip() or "Europe/London"
        config["currency_symbol"]     = data.get("currency_symbol", config.get("currency_symbol", "p")).strip() or "p"
        config["product_code"]        = data.get("product_code", config.get("product_code", PRODUCT_CODE)).strip()
        config["tariff_code"]         = data.get("tariff_code", config.get("tariff_code", TARIFF_CODE)).strip()
        config["min_soc"]             = int(data.get("min_soc", config.get("min_soc", 20)))
        config["max_soc"]             = int(data.get("max_soc", config.get("max_soc", 90)))
        config["max_cheap_slots"]     = int(data.get("max_cheap_slots", config.get("max_cheap_slots", 8)))
        config["expensive_threshold"] = float(data.get("expensive_threshold", config.get("expensive_threshold", 25.0)))
        config["automation_enabled"]  = bool(data.get("automation_enabled", config.get("automation_enabled", True)))
        # Manual location override
        ml = data.get("manual_lat")
        mo = data.get("manual_lon")
        mc = data.get("manual_city")
        print(f"[SETTINGS] Location received: lat={ml!r} lon={mo!r} city={mc!r}")
        config["manual_lat"]  = float(ml) if ml is not None else None
        config["manual_lon"]  = float(mo) if mo is not None else None
        config["manual_city"] = str(mc).strip() if mc else None
        print(f"[SETTINGS] Location saved: lat={config['manual_lat']} lon={config['manual_lon']}")
    ok, err = save_config()
    if not ok:
        return jsonify({"ok": False, "error": "Save failed: " + (err or "unknown")}), 500
    _update_local_tz()
    # Re-detect location then immediately refresh weather with new coords
    def _relocate_and_refresh():
        detect_location()
        fetch_weather()
    threading.Thread(target=_relocate_and_refresh, daemon=True).start()
    # Always refresh prices after settings change
    print("[SETTINGS] Config saved, refreshing prices...")
    update_prices()
    cheap_slots = compute_cheap_slots()
    with ems_lock:
        ems_state["cheap_slots"] = [
            {"start": c["start"].astimezone(UK_TZ).isoformat(),
             "end":   c["end"].astimezone(UK_TZ).isoformat(),
             "price": c["price"]}
            for c in cheap_slots
        ]
    return jsonify({"ok": True})


@app.route("/api/get_config")
def api_get_config():
    """Return config for frontend (API key existence only, not value)."""
    with config_lock:
        c = config.copy()
    return jsonify({
        "has_api_key":          bool(c.get("octopus_api_key","").strip()),
        "octopus_api_key":      "●●●●●●●●" if c.get("octopus_api_key","").strip() else "",
        "has_tibber_key":       bool(c.get("tibber_api_key","").strip()),
        "tariff_type":          c.get("tariff_type", "agile"),
        "cheap_window_start":   c.get("cheap_window_start", 0),
        "cheap_window_end":     c.get("cheap_window_end", 7),
        "cheap_price_fixed":    c.get("cheap_price_fixed", 9.0),
        "timezone":             c.get("timezone", "Europe/London"),
        "currency_symbol":      c.get("currency_symbol", "p"),
        "product_code":         c.get("product_code", PRODUCT_CODE),
        "tariff_code":          c.get("tariff_code", TARIFF_CODE),
        "min_soc":              c.get("min_soc", 20),
        "max_soc":              c.get("max_soc", 90),
        "max_cheap_slots":      c.get("max_cheap_slots", 8),
        "expensive_threshold":  c.get("expensive_threshold", 25.0),
        "automation_enabled":   c.get("automation_enabled", True),
        "manual_lat":  c.get("manual_lat"),
        "manual_lon":  c.get("manual_lon"),
        "manual_city": c.get("manual_city", ""),
    })



@app.route("/api/test_octopus")
def api_test_octopus():
    try:
        update_prices()
        now_utc = datetime.now(timezone.utc)
        with prices_lock:
            future = [p for p in cached_prices if p['start'] >= now_utc]
            sample = sorted(future, key=lambda x: x['price'])[:5]
            cnt = len(future)
        return jsonify({"ok": True, "count": cnt, "sample": [
            {"start": s["start"].astimezone(UK_TZ).isoformat(),
             "end":   s["end"].astimezone(UK_TZ).isoformat(),
             "price": s["price"]} for s in sample]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/test_tibber")
def api_test_tibber():
    try:
        _update_prices_tibber()
        now_utc = datetime.now(timezone.utc)
        with prices_lock:
            future = [p for p in cached_prices if p['start'] >= now_utc]
            sample = sorted(future, key=lambda x: x['price'])[:5]
            cnt = len(future)
        return jsonify({"ok": True, "count": cnt, "sample": [
            {"start": s["start"].astimezone(UK_TZ).isoformat(),
             "end":   s["end"].astimezone(UK_TZ).isoformat(),
             "price": s["price"]} for s in sample]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/set_control_mode", methods=["POST"])
def api_set_control_mode():
    data = request.get_json(force=True)
    mode = data.get("mode")
    if mode not in ['auto','manual']:
        return jsonify({"success": False, "message": "Use 'auto' or 'manual'"})
    with ems_lock:
        ems_state["control_mode"] = mode
    msg = "✅ AUTO mode – EMS active" if mode=="auto" else "⚠️ MANUAL mode – EMS paused"
    return jsonify({"success": True, "message": msg})

@app.route("/api/set_mode_manual", methods=["POST"])
def api_set_mode_manual():
    data = request.get_json(force=True)
    mode = data.get("mode")
    with ems_lock:
        ctrl = ems_state.get("control_mode","auto")
    if ctrl != "manual":
        return jsonify({"success": False, "message": "❌ Switch to MANUAL first!"})
    try:
        if mode == "cheap":
            set_mode_cheap("manual override")
            return jsonify({"success": True, "message": "✅ E204=SUB(3) – Grid charges battery"})
        elif mode == "expensive":
            set_mode_expensive("manual override")
            return jsonify({"success": True, "message": "✅ E204=SBU(2) – Solar/Battery, grid does NOT charge"})
        else:
            return jsonify({"success": False, "message": f"Unknown mode: {mode}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/set_charge_mode", methods=["POST"])
def api_set_charge_mode():
    data = request.get_json(force=True)
    mode = int(data.get("mode", 2))
    if mode not in [0, 1, 2, 3]:
        return jsonify({"success": False, "message": "Invalid mode — must be 0,1,2,3"})
    with ems_lock:
        ctrl = ems_state.get("control_mode", "auto")
    if ctrl != "manual":
        return jsonify({"success": False, "message": "❌ Switch to MANUAL first!"})
    try:
        set_charge_mode(mode, "manual override")
        names = {0: 'PV-preferred', 1: 'Mains-preferred', 2: 'Hybrid', 3: 'PV-only'}
        return jsonify({"success": True, "message": f"✅ E20F={names[mode]} charge mode set"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/system_info")
def api_system_info():
    info = {}
    try:
        pt = read_register(REGISTERS['product_type']['reg'])
        info['product_type'] = REGISTERS['product_type'].get('values',{}).get(pt, f"Unknown({pt})") if pt is not None else None
        info['software_version_1'] = read_register(REGISTERS['software_version_1']['reg'])
        info['software_version_2'] = read_register(REGISTERS['software_version_2']['reg'])
        info['hardware_version_1'] = read_register(REGISTERS['hardware_version_1']['reg'])
        info['hardware_version_2'] = read_register(REGISTERS['hardware_version_2']['reg'])
        info['serial_number']      = read_register_ascii(REGISTERS['product_sn']['reg'][0],
                                         REGISTERS['product_sn']['reg'][1] - REGISTERS['product_sn']['reg'][0] + 1)
        info['model_code']         = read_register(REGISTERS['model_code']['reg'])
        info['rs485_address']      = read_register(REGISTERS['rs485_address']['reg'])
        info['rs485_version']      = read_register(REGISTERS['rs485_version']['reg'])
        bt = read_register(REGISTERS['battery_type']['reg'])
        info['battery_type']       = REGISTERS['battery_type'].get('values',{}).get(bt, f"Unknown({bt})") if bt is not None else None
        info['nominal_battery_capacity'] = read_register(REGISTERS['nominal_battery_capacity']['reg'])
        info['system_voltage']     = read_register(REGISTERS['system_voltage']['reg'])
        return jsonify({"ok": True, "info": info})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/fault_status")
def api_fault_status():
    faults = {}
    try:
        for k in ['fault_bits_1','fault_bits_2','fault_bits_3','fault_bits_4',
                  'fault_code_1','fault_code_2','fault_code_3','fault_code_4']:
            faults[k] = read_register(REGISTERS[k]['reg'])
        return jsonify({"ok": True, "faults": faults})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/today_energy")
def api_today_energy():
    result = integrate_today_from_csv()
    # xF03D direkt regiszter a hálózatról fogyasztott kWh-hoz — megbízhatóbb mint az energiamérleg
    with telemetry_lock:
        mains_reg = telemetry.get("mains_load_kwh_today")
    if mains_reg is not None and mains_reg > 0:
        result["grid_kwh"] = round(mains_reg, 2)
    return jsonify(result)

@app.route("/api/statistics")
def api_statistics():
    stats = {}
    try:
        for k in ['battery_charge_ah_today','battery_discharge_ah_today',
                  'pv_power_generation_today','load_power_consumption_today',
                  'total_running_days','total_battery_overdischarge','total_battery_full_charge']:
            stats[k] = read_register(REGISTERS[k]['reg'])
        for i in range(1, 8):
            stats[f'pv_generation_day_minus_{i}']     = read_register(REGISTERS[f'history_pv_power_generation_today_minus_{i}']['reg'])
            stats[f'battery_charge_day_minus_{i}']    = read_register(REGISTERS[f'history_battery_charge_level_today_minus_{i}']['reg'])
            stats[f'battery_discharge_day_minus_{i}'] = read_register(REGISTERS[f'history_battery_discharge_level_today_minus_{i}']['reg'])
            stats[f'load_consumption_day_minus_{i}']  = read_register(REGISTERS[f'history_power_consumption_load_today_minus_{i}']['reg'])
        return jsonify({"ok": True, "statistics": stats})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

def open_browser():
    time.sleep(1)
    webbrowser.open("http://127.0.0.1:5000")


@app.route("/api/history")
def api_history():
    """Return CSV history as JSON for charts. ?hours=24 or ?days=7"""
    try:
        hours = int(request.args.get("hours", 24))
        days  = int(request.args.get("days",  0))
        if days > 0:
            hours = days * 24
        hours = min(hours, 24 * 30)  # max 30 days

        if not os.path.exists(HISTORY_FILE):
            return jsonify({"ok": True, "rows": []})

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = []
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    ts_str = row.get("timestamp","")
                    if not ts_str:
                        continue
                    # Parse ISO timestamp
                    if ts_str.endswith("Z"):
                        ts_str = ts_str[:-1] + "+00:00"
                    ts = datetime.fromisoformat(ts_str)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if ts < cutoff:
                        continue
                    def pf(k):
                        v = row.get(k)
                        try: return float(v) if v and v != "" else None
                        except: return None
                    rows.append({
                        "t":      ts.astimezone(UK_TZ).strftime("%Y-%m-%dT%H:%M:%S"),
                        "pv":     pf("pv1_p"),
                        "load":   pf("load_p"),
                        "bat_p":  pf("bat_p"),
                        "bat_v":  pf("bat_v"),
                        "soc":    pf("soc"),
                        "grid_v": pf("grid_v"),
                        "bat_i":  pf("bat_i"),
                        "price":  pf("price_now"),
                    })
                except Exception:
                    continue
        return jsonify({"ok": True, "rows": rows, "count": len(rows)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/optimizer")
def api_optimizer():
    with geo_lock:
        city = geo_state.get("city", "Unknown")
        lat  = geo_state.get("lat", 53.07)
        lon  = geo_state.get("lon", -0.81)
        src  = geo_state.get("source", "default")
    with weather_lock:
        w = weather_state.copy()
    opt = load_optimizer()
    slots_needed = compute_required_slots()
    hourly = analyze_hourly_patterns()
    return jsonify({
        "location": f"{city} ({lat:.2f}, {lon:.2f}) [{src}]",
        "weather": w,
        "optimizer": opt,
        "slots_tonight": slots_needed,
        "hourly_patterns": {
            "solar_start": hourly.get("typical_solar_start"),
            "solar_end":   hourly.get("typical_solar_end"),
            "peak_hour":   hourly.get("peak_solar_hour"),
            "data_points": hourly.get("data_points", 0),
            "hourly_pv":   hourly.get("hourly_pv_avg", {}),
            "hourly_load": hourly.get("hourly_load_avg", {}),
        },
    })

@app.route("/api/daily_summary")
def api_daily_summary():
    records = load_daily_records()
    return jsonify({"records": records[-30:]})  # last 30 days

@app.route("/api/inverter_history")
def api_inverter_history():
    """
    Returns last 7 days + today directly from inverter history registers.
    Augments with cloud cover from ems_daily.json where available.
    """
    hist = read_inverter_history()
    days = hist.get('days', [])
    # Augment with cloud cover from daily records file
    file_recs = {r.get('date'): r for r in load_daily_records()}
    for day in days:
        rec = file_recs.get(day['date'], {})
        day['cloud_avg'] = rec.get('cloud_avg')
        day['evening_soc'] = rec.get('evening_soc')
    return jsonify({'days': days, 'fetched': hist.get('fetched')})


@app.route("/api/force_fetch", methods=["POST"])
def api_force_fetch():
    global _last_afternoon_fetch
    try:
        _last_afternoon_fetch = None
        update_prices()
        fetch_weather()
        slots = _do_replan()
        return jsonify({"ok": True, "slots": len(slots), "msg": "Fetched OK - "+str(len(slots))+" slots planned"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/refresh_weather", methods=["POST"])
def api_refresh_weather():
    """Manually trigger weather refresh. Only re-detects location if no manual override."""
    try:
        with config_lock:
            has_manual = bool(config.get("manual_lat")) and bool(config.get("manual_lon"))
        def _refresh():
            if not has_manual:
                detect_location()
            fetch_weather()
        threading.Thread(target=_refresh, daemon=True).start()
        return jsonify({"ok": True, "message": "Weather refresh triggered"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/run_plan", methods=["POST"])
def api_run_plan():
    """Manually trigger the nightly planning cycle."""
    global _last_plan_date
    _last_plan_date = None  # force re-run
    try:
        run_nightly_plan()
        with config_lock:
            slots = config.get("max_cheap_slots", 8)
        return jsonify({"ok": True, "message": f"Plan complete: {slots} slots scheduled"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})



# ── SSL Certificate generation ────────────────────────────────

def register_windows_autostart():
    """Add EMS to Windows startup registry so it runs on boot."""
    try:
        import winreg, sys
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        exe_path = sys.executable if getattr(sys, 'frozen', False) else f'"{sys.executable}" "{os.path.abspath(__file__)}"'
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "AttillaEMS", 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
        print(f"[STARTUP] Windows autostart registered: {exe_path}")
        return True
    except ImportError:
        pass  # Not Windows
    except Exception as e:
        print(f"[STARTUP] Autostart registration failed: {e}")
    return False

def remove_windows_autostart():
    """Remove EMS from Windows startup."""
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "AttillaEMS")
        winreg.CloseKey(key)
        print("[STARTUP] Windows autostart removed")
        return True
    except Exception:
        return False

if __name__ == "__main__":
    print(f"{'='*50}")
    print(f"  {APP_NAME} v{APP_VERSION} ({BUILD_DATE})")
    print(f"{'='*50}")
    print(f"[STARTUP] Working directory: {APP_DIR}")

    # TEST MODE: Force trial expiry for testing paywall
    import sys as _sys_argv
    _force_trial_expired = "--force-trial-expired" in _sys_argv.argv
    _force_paywall = "--force-paywall" in _sys_argv.argv

    # Register Windows autostart (silent, only on Windows)
    register_windows_autostart()

    # 0. Load config FIRST (manual_lat/lon needed by detect_location)
    load_config()

    # TEST: Simulate expired trial
    if _force_trial_expired:
        with config_lock:
            config["install_date"] = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
        print("[TEST] Forced trial expiry — 20 days ago")
        save_config()

    # 1. Detect location
    threading.Thread(target=detect_location, daemon=True).start()

    # 2. Find serial port
    find_serial_port()

    # 2b. Read current E20F charge priority from inverter
    try:
        _charge_pri_now = read_register(REG_CHARGE_PRI)
        if _charge_pri_now is not None:
            _mode_names = {0: 'PV-preferred', 1: 'Mains-preferred', 2: 'Hybrid', 3: 'PV-only'}
            with ems_lock:
                ems_state["charge_mode"] = _mode_names.get(_charge_pri_now, str(_charge_pri_now))
            print(f"[STARTUP] E20F charge mode read: {ems_state['charge_mode']}")
    except Exception as _e:
        print(f"[STARTUP] E20F read error: {_e}")

    # 3. Init optimizer file if missing
    load_optimizer()

    # 4. Fetch prices (use cache if fresh)
    try:
        cache_loaded = load_prices_cache()
        if not cache_loaded:
            print("[STARTUP] Fetching Octopus prices...")
            update_prices()
        else:
            print("[STARTUP] Using cached prices")
        cheap_slots = compute_cheap_slots()
        now_utc = datetime.now(timezone.utc)
        with ems_lock:
            ems_state["cheap_slots"] = [
                {"start": c["start"].astimezone(UK_TZ).isoformat(),
                 "end":   c["end"].astimezone(UK_TZ).isoformat(),
                 "price": c["price"]}
                for c in cheap_slots
            ]
            next_slot = next(
                (c for c in cheap_slots if c["start"].astimezone(timezone.utc) > now_utc),
                None
)

            ems_state["next_cheap_slot"] = (
                {"start": next_slot["start"].astimezone(UK_TZ).isoformat(),
                 "end":   next_slot["end"].astimezone(UK_TZ).isoformat(),
                 "price": next_slot["price"]}
                if next_slot else None
            )
            ems_state["next_switch_time"] = next_slot["start"].astimezone(UK_TZ).isoformat() if next_slot else None
    except Exception as e:
        print(f"[STARTUP] Price fetch error: {e}")

    # 5. Fetch weather in background
    threading.Thread(target=fetch_weather, daemon=True).start()

    # 5b. Init trial token (if missing) — must happen before license check
    import uuid
    with config_lock:
        if not config.get("trial_token"):
            config["trial_token"] = str(uuid.uuid4())
    save_config()

    # 6. License check
    _lic_valid, _lic_reason = check_license()
    print(f"[LICENSE] {'OK' if _lic_valid else 'PAYWALL'} — {_lic_reason}")
    if not _lic_valid:
        # Disable automation immediately on invalid license
        with config_lock:
            config["automation_enabled"] = False
        with ems_lock:
            ems_state["last_error"] = f"License {_lic_reason} — subscribe at fluxsignals.com"
        # Machine lock failure is fatal — prevent operation
        if _lic_reason == "machine_changed":
            print("[LICENSE] FATAL: Machine lock violation — this code is locked to a different computer")
            print("[LICENSE] This copy appears to be used on an unauthorized device")
            _sys.exit(1)
        # Other failures show paywall but still start Flask so the UI loads
        print("[LICENSE] Trial expired or invalid — paywall will be shown, automation disabled")
    threading.Thread(target=_heartbeat_loop, daemon=True).start()

    # 7. Start loops
    threading.Thread(target=poll_telemetry_loop, daemon=True).start()
    threading.Thread(target=ems_scheduler_loop,  daemon=True).start()
    threading.Thread(target=open_browser,         daemon=True).start()
    print("[STARTUP] http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)