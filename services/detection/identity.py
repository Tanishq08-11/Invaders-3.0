"""
Network identity
=================
A source IP is not an identity. Network events are attributed to a device ONLY through
an explicit DeviceBinding (static assignment, DHCP lease import, agent report) that is
valid at the event time. MAC addresses, when observed in the frame, are compared with
the binding as supporting evidence; a mismatch is reported, a MAC alone never attributes.

Entity keys used for baselines:
  device:<key>  registered device (binding found)
  addr:<ip>     internal address only — baselines are per address, NOT per person
  user:<id>     authenticated portal user (application events)
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.database import db
from core.models import DeviceBinding, RegisteredDevice
from core.timeutil import naive_utc


def resolve_device(ip: Optional[str], ts: Optional[float], mac: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not ip:
        return None
    at = naive_utc(ts) if ts else datetime.now(timezone.utc).replace(tzinfo=None)
    rows = (
        db.session.query(DeviceBinding, RegisteredDevice)
        .join(RegisteredDevice, RegisteredDevice.device_key == DeviceBinding.device_key)
        .filter(DeviceBinding.ip_address == ip, DeviceBinding.valid_from <= at,
                db.or_(DeviceBinding.valid_to.is_(None), DeviceBinding.valid_to > at),
                RegisteredDevice.active.is_(True))
        .all()
    )
    keys = {b.device_key for b, _ in rows}
    if len(keys) != 1:
        # none, or overlapping bindings of several devices to one address → do not guess
        return {"ambiguous": True, "candidates": sorted(keys)} if len(keys) > 1 else None
    binding, device = rows[0]
    mac = (mac or "").lower() or None
    mac_status = None
    if binding.mac_address and mac:
        mac_status = "match" if binding.mac_address.lower() == mac else "mismatch"
    return {
        "device_key": device.device_key,
        "owner_user_id": device.owner_user_id,
        "method": "ip_binding" + ("+mac" if mac_status == "match" else ""),
        "binding_source": binding.source,
        "mac_status": mac_status,
        "device": device,
    }


def entity_for_network(internal_ip: Optional[str], ts: Optional[float], mac: Optional[str] = None):
    """(entity_key, kind, resolution) for the internal endpoint of a network event."""
    if not internal_ip:
        return None, None, None
    res = resolve_device(internal_ip, ts, mac)
    if res and not res.get("ambiguous"):
        return f"device:{res['device_key']}", "device", res
    return f"addr:{internal_ip}", "addr", res


def mark_seen(device: RegisteredDevice, ts: Optional[float]) -> None:
    when = naive_utc(ts) if ts else datetime.now(timezone.utc).replace(tzinfo=None)
    if device.last_seen_at is None or device.last_seen_at < when:
        device.last_seen_at = when


def devices_of_user(user_id: int):
    return RegisteredDevice.query.filter_by(owner_user_id=user_id, active=True).all()
