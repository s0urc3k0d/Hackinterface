"""
Schémas Pydantic pour la validation des données
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

# ============================================================================
# Enums
# ============================================================================

class TargetType(str, Enum):
    IP = "ip"
    FQDN = "fqdn"
    DOMAIN = "domain"
    CIDR = "cidr"
    URL = "url"

class ActionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"

# ============================================================================
# Cibles
# ============================================================================

class TargetCreate(BaseModel):
    type: TargetType
    value: str
    description: Optional[str] = None

class TargetResponse(BaseModel):
    id: int
    type: TargetType
    value: str
    description: Optional[str] = None

# ============================================================================
# VPN
# ============================================================================

class VPNStatus(BaseModel):
    connected: bool
    config_loaded: bool
    tun_ip: Optional[str] = None

class PingRequest(BaseModel):
    target: str

# ============================================================================
# Actions
# ============================================================================

class ActionRequest(BaseModel):
    target_id: int
    action: str
    options: Optional[Dict[str, Any]] = None

class ActionResult(BaseModel):
    action: str
    target: str
    status: ActionStatus
    command: Optional[str] = None
    output: Optional[str] = None
    error: Optional[str] = None
    duration: Optional[float] = None
    timestamp: Optional[str] = None
    parsed_data: Optional[Dict[str, Any]] = None

# ============================================================================
# Workflows
# ============================================================================

class WorkflowRequest(BaseModel):
    workflow_id: str
    target_id: int
    options: Optional[Dict[str, Any]] = None

class WorkflowStep(BaseModel):
    action: str
    name: str
    description: str
    options: Optional[Dict[str, Any]] = None
    condition: Optional[str] = None  # Condition pour exécuter cette étape

class WorkflowDefinition(BaseModel):
    id: str
    name: str
    description: str
    target_types: List[TargetType]  # Types de cibles compatibles
    steps: List[WorkflowStep]
    auto_chain: bool = True  # Enchaînement automatique basé sur les découvertes

# ============================================================================
# Rapports
# ============================================================================

class ReportRequest(BaseModel):
    type: str = "oscp"  # oscp, client, json
    include_screenshots: bool = True
    title: Optional[str] = None
    author: Optional[str] = None

# ============================================================================
# Résultats parsés
# ============================================================================

class NmapPort(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None

class NmapResult(BaseModel):
    host: str
    state: str
    ports: List[NmapPort]
    os_guess: Optional[str] = None

class SubdomainResult(BaseModel):
    subdomain: str
    ip: Optional[str] = None
    status_code: Optional[int] = None

class VulnerabilityResult(BaseModel):
    name: str
    severity: str  # info, low, medium, high, critical
    description: str
    reference: Optional[str] = None
    evidence: Optional[str] = None
