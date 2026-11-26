"""InjecAgent tool catalog loader and least-privilege classifier.

InjecAgent test cases name the user tool and attacker tools (e.g.
``AugustSmartLockGrantGuestAccess``), where each name is ``Toolkit + tool``.
``tools.json`` stores toolkits and their tools separately, so this module
builds the full-name index and classifies each tool into one of four classes
consumed by ``policies/injecagent_least_privilege.yog``:

* ``read``            -- ordinary information retrieval
* ``sensitive_read``  -- credentials, addresses, payment methods, health/genetic
                         records, location, or personal history
* ``write``           -- state-changing or outbound communication
* ``destructive``     -- irreversible, financial, access-grant, execution,
                         deepfake, dispatch, or traffic-control actions

Precedence when multiple patterns match is:
``destructive > write > sensitive_read > read``.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, Mapping

CLASS_PRECEDENCE = ("destructive", "write", "sensitive_read", "read")

_DESTRUCTIVE_TOOLKITS = {
    "Terminal",
}

_DESTRUCTIVE_PREFIXES_OR_SUBSTRINGS = (
    "Delete",
    "Grant",
    "Unlock",
    "Transfer",
    "Withdraw",
    "Execute",
    "Disable",
    "EnableTwoFactor",
    "Revoke",
    "ClearHistory",
    "ExportPasswords",
    "ImportPasswords",
    "SharePassword",
    "ShareData",
    "BlockDomain",
    "UnblockDomain",
    "PayBill",
    "SendMoney",
    "PlaceOrder",
    "TradeStock",
    "MakeTransaction",
    "DeploySmartContract",
    "CallSmartContractFunction",
    "SignMessage",
    "Cancel",
    "ControlDevice",
    "ScheduleDeviceAction",
    "ApplyAllowedOperation",
    "HandObjectsToPerson",
    "ManageCollaborator",
    "ManageMembership",
    "ManageNoteSharingLevel",
    "SetDataPrivacy",
    "CreateLink",
    "Deposit",
    "HandleRequest",
    "RequestPrescription",
    "CreateDispatchRequest",
    "RedirectDispatchResources",
    "EditIncident",
    "ManageTrafficLightState",
    "GivePriorityTo",
    "ScheduleRoadMaintenance",
    "GenerateVideoDeepfake",
    "GenerateAudioDeepfake",
    "ManipulateVideoDeepfake",
    "ManipulateAudioDeepfake",
    "CreateEthereumAccount",
    "ImportEthereumAccount",
)

_SENSITIVE_READ_SUBSTRINGS = (
    "Password",
    "PersonalInfo",
    "SavedAddresses",
    "SavedPaymentMethods",
    "Genetic",
    "HealthRecommendations",
    "MedicalHistory",
    "Prescriptions",
    "AccessHistory",
    "SearchHistory",
    "GetCurrentLocation",
    "CriminalHistory",
    "CourtRecords",
    "BackgroundCheck",
    "VerifyIdentity",
    "AccountInformation",
    "AccountStatement",
    "Balance",
    "Holdings",
    "OrderHistory",
    "Transactions",
    "SmsHistory",
    "ReceivedSmsMessages",
    "PatientDetails",
    "SearchPatients",
    "ClinicalDocuments",
    "DiagnosticReports",
    "MonitorDataChanges",
    "GetHistoricalData",
    "ReversePhoneLookup",
    "ReadEmail",
    "SearchEmails",
    "DownloadAttachment",
    "GetMessages",
)

_WRITE_SUBSTRINGS = (
    "Send",
    "Create",
    "Update",
    "Move",
    "Book",
    "Post",
    "Add",
    "Set",
    "Reply",
    "Retweet",
    "Like",
    "Unlike",
    "Follow",
    "Unfollow",
    "Upload",
    "Join",
    "Leave",
    "Organize",
    "Schedule",
    "Draft",
    "PlayMedia",
    "ConsultDoctor",
    "Manage",
    "SetupAlert",
    "GeneratePassword",
    "AutoFill",
    "Store",
    "ClickElement",
    "InputText",
    "NavigateTo",
    "GoToRoom",
    "Download",
    "Share",
    "LeaveReview",
)

_READ_PREFIXES = (
    "Search",
    "Get",
    "List",
    "View",
    "Read",
    "Check",
    "Retrieve",
    "Find",
    "LookAround",
    "Estimate",
    "Verify",
    "Compile",
    "Monitor",
    "Predict",
    "Analyze",
    "Track",
    "Geocoding",
    "ReverseGeocoding",
    "AskQuestion",
)


def load_tools(tools_path: str) -> Dict[str, Dict[str, Any]]:
    """Load InjecAgent ``tools.json`` and index by ``Toolkit + tool`` name."""
    with open(tools_path, encoding="utf-8") as handle:
        raw = json.load(handle)

    catalog: Dict[str, Dict[str, Any]] = {}
    if isinstance(raw, list):
        for entry in raw:
            toolkit = str(entry.get("toolkit", ""))
            for tool in entry.get("tools") or []:
                name = str(tool.get("name", ""))
                full_name = f"{toolkit}{name}"
                catalog[full_name] = {
                    "full_name": full_name,
                    "toolkit": toolkit,
                    "tool": name,
                    "summary": tool.get("summary", ""),
                }
    elif isinstance(raw, Mapping):
        for toolkit, tools in raw.items():
            for tool in tools or []:
                name = str(tool.get("name", "")) if isinstance(tool, Mapping) else str(tool)
                full_name = f"{toolkit}{name}"
                catalog[full_name] = {
                    "full_name": full_name,
                    "toolkit": str(toolkit),
                    "tool": name,
                    "summary": tool.get("summary", "") if isinstance(tool, Mapping) else "",
                }
    return catalog


def _strip_toolkit(full_name: str, toolkit: str) -> str:
    if toolkit and full_name.startswith(toolkit):
        return full_name[len(toolkit):]
    return full_name


def classify_tool(full_name: str, toolkit: str = "") -> str:
    """Classify an InjecAgent tool into ``read|sensitive_read|write|destructive``.

    Precedence: ``destructive > write > sensitive_read > read``.
    """
    short = _strip_toolkit(full_name, toolkit)

    if toolkit in _DESTRUCTIVE_TOOLKITS:
        return "destructive"
    if any(token in short or token in full_name for token in _DESTRUCTIVE_PREFIXES_OR_SUBSTRINGS):
        return "destructive"
    if any(token in short or token in full_name for token in _WRITE_SUBSTRINGS):
        # Sensitive reads like DownloadAttachment or GetMessages shouldn't be
        # overridden unless they actually write; DownloadAttachment has "Download".
        if short in ("DownloadAttachment", "DownloadFiles", "DownloadData", "DownloadPublicRecord", "DownloadFile"):
            if short == "DownloadAttachment":
                return "sensitive_read"
            return "read" if short == "DownloadPublicRecord" else "sensitive_read"
        return "write"
    if any(token in short or token in full_name for token in _SENSITIVE_READ_SUBSTRINGS):
        return "sensitive_read"
    if short.startswith(_READ_PREFIXES):
        return "read"
    words = re.findall(r"[A-Z][a-z0-9]*", short)
    if any(word.startswith(_READ_PREFIXES) for word in words) or "Search" in words:
        return "read"
    # Conservative fallback for anything unrecognized: treat as write (requires approval).
    return "write"


def facts_for_tool(full_name: str, catalog: Mapping[str, Mapping[str, Any]] | None = None) -> list[tuple[str, tuple]]:
    """Return YOG ``tool_class`` fact for ``full_name``."""
    info = (catalog or {}).get(full_name)
    toolkit = str(info["toolkit"]) if info else ""
    tool_class = classify_tool(full_name, toolkit=toolkit)
    return [("tool_class", (full_name, tool_class))]


def default_data_dir() -> str:
    return os.path.join(os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp", "injecagent")


def load_cases(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError(f"expected list of cases in {path}")
    return data


def classify_catalog(catalog: Mapping[str, Mapping[str, Any]]) -> Dict[str, str]:
    """Return ``{full_name: tool_class}`` for every tool in ``catalog``."""
    return {
        name: classify_tool(name, str(info.get("toolkit", "")))
        for name, info in sorted(catalog.items())
    }
