"""Nautobot Jobs for the Device Lifecycle plugin."""
from .cve_tracking import CVEChatGPTJobHookReceiver, GenerateVulnerabilities
from .lifecycle_reporting import DeviceSoftwareValidationFullReport, InventoryItemSoftwareValidationFullReport

jobs = [CVEChatGPTJobHookReceiver, DeviceSoftwareValidationFullReport, InventoryItemSoftwareValidationFullReport, GenerateVulnerabilities]
