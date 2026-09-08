import json
import os
import streamlit as st
from google.cloud import firestore
from google.oauth2 import service_account
from cloud.firestore_logger import LOCAL_EVENT_STORE


class FirestoreReader:
    """
    Reads Sentinel-A2A security events from Cloud Firestore or local session memory.
    """

    def __init__(self, project_id=None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
        self.db = None
        self.collection = None
        self.connection_error = None

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

    def _get_local_events(self):
        events = []
        if hasattr(st, "session_state") and "session_events" in st.session_state:
            events.extend(st.session_state["session_events"])
        
        for e in LOCAL_EVENT_STORE:
            if e not in events:
                events.append(e)
                
        return sorted(events, key=lambda x: str(x.get("timestamp", "")), reverse=True)

    def get_recent_events(self, limit=100):
        if self.collection is not None:
            try:
                documents = (
                    self.collection
                    .order_by("timestamp", direction=firestore.Query.DESCENDING)
                    .limit(limit)
                    .stream()
                )
                events = []
                for document in documents:
                    event = document.to_dict()
                    event["document_id"] = document.id
                    events.append(event)
                if events:
                    return events
            except Exception as e:
                print(f"Firestore fetch failed: {e}")

        return self._get_local_events()[:limit]

    def get_blocked_events(self, limit=100):
        if self.collection is not None:
            try:
                documents = (
                    self.collection
                    .where("decision", "==", "BLOCK")
                    .limit(limit)
                    .stream()
                )
                events = []
                for document in documents:
                    event = document.to_dict()
                    event["document_id"] = document.id
                    events.append(event)
                if events:
                    return events
            except Exception as e:
                print(f"Firestore blocked fetch failed: {e}")

        local_events = self._get_local_events()
        return [e for e in local_events if e.get("decision") == "BLOCK"][:limit]

    def get_event_count(self):
        if self.collection is not None:
            try:
                documents = self.collection.stream()
                count = sum(1 for _ in documents)
                if count > 0:
                    return count
            except Exception as e:
                print(f"Firestore count error: {e}")

        return len(self._get_local_events()) 
