import os
import json
import uuid
from datetime import datetime, timezone
import streamlit as st
from google.cloud import firestore
from google.oauth2 import service_account

# Global module fallback
LOCAL_EVENT_STORE = []


class FirestoreLogger:
    """
    Logs Sentinel-A2A security events to Google Cloud Firestore or
    falls back to Streamlit session_state / local memory.
    """

    def __init__(self, project_id=None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
        self.db = None
        self.collection = None
        self.connection_error = None

        # Initialize Session State array if available
        if hasattr(st, "session_state") and "session_events" not in st.session_state:
            st.session_state["session_events"] = []

        # 1. Streamlit secrets priority
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
                    self.connection_error = f"Streamlit secrets init failed: {e}"

        # 2. Application Default Credentials
        if self.db is None:
            try:
                if self.project_id:
                    self.db = firestore.Client(project=self.project_id)
                else:
                    self.db = firestore.Client()
                self.connection_error = None
            except Exception as e:
                if self.connection_error is None:
                    self.connection_error = f"ADC initialization failed: {e}"

        if self.db is not None:
            self.collection = self.db.collection("security_events")

    @property
    def is_connected(self):
        return self.collection is not None

    def log_event(self, event_data):
        if not isinstance(event_data, dict):
            return None

        payload = dict(event_data)
        if "timestamp" not in payload:
            payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "event_id" not in payload:
            payload["event_id"] = str(uuid.uuid4())

        # Save to local session stores unconditionally and persist them across reruns.
        event_id = payload.get("event_id")
        if hasattr(st, "session_state"):
            if "local_events" not in st.session_state:
                st.session_state["local_events"] = []
            if "session_events" not in st.session_state:
                st.session_state["session_events"] = []

            if not any(existing.get("event_id") == event_id for existing in st.session_state["local_events"]):
                st.session_state["local_events"].insert(0, payload)
            if not any(existing.get("event_id") == event_id for existing in st.session_state["session_events"]):
                st.session_state["session_events"].insert(0, payload)

        if not any(existing.get("event_id") == event_id for existing in LOCAL_EVENT_STORE):
            LOCAL_EVENT_STORE.insert(0, payload)

        # Attempt Cloud Firestore Write
        if self.collection is not None:
            try:
                doc_ref = self.collection.add(payload)
                return doc_ref[1].id
            except Exception as e:
                print(f"Firestore log write failed: {e}")

        return f"LOCAL_{payload['event_id'][:8]}" 
