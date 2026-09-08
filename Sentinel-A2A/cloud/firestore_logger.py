import json
import os
import uuid

import streamlit as st
from google.cloud import firestore
from google.oauth2 import service_account

# Shared in-memory event store for local UI testing fallback
LOCAL_EVENT_STORE = []


class FirestoreLogger:
    """
    Writes Sentinel-A2A security events to Google Cloud Firestore, while maintaining
    a local in-memory event list as a fallback when Firestore is disconnected.
    """

    def __init__(self, project_id=None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
        self.db = None
        self.collection = None
        self.connection_error = None

        # 1. First priority: Streamlit secrets
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
            else:
                self.connection_error = (
                    "No matching key found in st.secrets "
                    "(expected 'textkey', 'firestore', or 'gcp_service_account')"
                )

        # 2. Second priority: standard GCP Application Default Credentials / Project ID
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

        # Initialize collection if connection succeeded
        if self.db is not None:
            self.collection = self.db.collection("security_events")

    @property
    def is_connected(self):
        return self.collection is not None

    def log_event(self, event):
        """
        Write a single security event dict to local fallback memory and Firestore (if available).
        """
        if not isinstance(event, dict):
            return None

        event_id = event.get("event_id") or str(uuid.uuid4())
        event["event_id"] = event_id

        # Always append to local in-memory store so UI updates immediately
        if not any(e.get("event_id") == event_id for e in LOCAL_EVENT_STORE):
            LOCAL_EVENT_STORE.append(event)

        # Write to Google Cloud Firestore if connected
        if self.collection is not None:
            try:
                doc_ref = self.collection.document(event_id)
                doc_ref.set(event)
                return doc_ref.id
            except Exception as e:
                print(f"Error logging event to Firestore: {e}")
                return f"LOCAL_{event_id}"

        return f"LOCAL_{event_id}" 
