import json
import os
import uuid
from datetime import datetime, timezone
import streamlit as st
from google.cloud import firestore
from google.oauth2 import service_account


class FirestoreLogger:
    """
    Stores Sentinel-A2A security events in Google Cloud Firestore.
    """

    def __init__(self, project_id=None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
        self.db = None
        self.collection = None

        # 1. Streamlit Secrets Integration
        if hasattr(st, "secrets"):
            secret_key = None
            for key in ["textkey", "firestore", "gcp_service_account"]:
                if key in st.secrets:
                    secret_key = st.secrets[key]
                    break

            if secret_key is not None:
                try:
                    if isinstance(secret_key, str):
                        key_dict = json.loads(secret_key)
                    else:
                        key_dict = dict(secret_key)

                    creds = service_account.Credentials.from_service_account_info(key_dict)
                    self.project_id = self.project_id or key_dict.get("project_id")
                    self.db = firestore.Client(credentials=creds, project=self.project_id)
                except Exception as e:
                    print(f"[FirestoreLogger] Secrets init failed: {e}")

        # 2. GCP Default Credentials Fallback
        if self.db is None:
            try:
                if self.project_id:
                    self.db = firestore.Client(project=self.project_id)
                else:
                    self.db = firestore.Client()
            except Exception as e:
                print(f"[FirestoreLogger] GCP default init failed: {e}")

        if self.db is not None:
            self.collection = self.db.collection("security_events")
            print("[FirestoreLogger] Connected successfully to Firestore.")
        else:
            print("[FirestoreLogger] WARNING: Unconfigured mode. Events will NOT save.")

    def log_event(self, security_event):
        """
        Save one Sentinel-A2A security event to Firestore.
        """
        if self.collection is None:
            print("[FirestoreLogger] Cannot log event: Client not connected.")
            return False

        if not isinstance(security_event, dict):
            raise ValueError("security_event must be a dictionary.")

        try:
            doc_id = security_event.get("event_id") or str(uuid.uuid4())
            
            timestamp = security_event.get("timestamp")
            if not timestamp:
                timestamp = datetime.now(timezone.utc).isoformat()
            else:
                timestamp = str(timestamp)

            event_payload = {
                "event_id": str(doc_id),
                "timestamp": timestamp,
                "source_agent": str(security_event.get("source_agent", "ShoppingAgent")),
                "target_agent": str(security_event.get("target_agent", "PaymentAgent")),
                "tool": str(security_event.get("tool", "")),
                "decision": str(security_event.get("decision", "UNKNOWN")),
                "risk_score": int(security_event.get("risk_score", 0)),
                "risk_level": str(security_event.get("risk_level", "LOW")),
                "authorized": bool(security_event.get("authorized", True)),
                "threats": [str(t) for t in security_event.get("threats", [])],
                "gemini_analysis": str(security_event.get("gemini_analysis", ""))
            }

            self.collection.document(str(doc_id)).set(event_payload)
            print(f"[FirestoreLogger] Logged event successfully: {doc_id}")
            return str(doc_id)

        except Exception as error:
            print(f"[FirestoreLogger] Error writing event: {error}")
            return False

    def get_recent_events(self, limit=50):
        if self.collection is None:
            return []
        try:
            docs = self.collection.limit(limit).stream()
            return [doc.to_dict() for doc in docs]
        except Exception as error:
            print(f"[FirestoreLogger] Error retrieving logs: {error}")
            return [] 
