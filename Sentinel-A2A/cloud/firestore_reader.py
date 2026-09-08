import json
import os
import streamlit as st
from google.cloud import firestore
from google.oauth2 import service_account


class FirestoreReader:
    """
    Reads Sentinel-A2A security events from Google Cloud
    Firestore for the monitoring dashboard.
    """

    def __init__(self, project_id=None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
        self.db = None
        self.collection = None
        self.connection_error = None  # human-readable reason if connection failed

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
                    print(f"Firestore secret initialization failed: {e}")
            else:
                self.connection_error = (
                    "No matching key found in st.secrets "
                    "(expected 'textkey', 'firestore', or 'gcp_service_account')"
                )

        # 2. Second priority: standard GCP Application Default Credentials
        if self.db is None:
            try:
                if self.project_id:
                    self.db = firestore.Client(project=self.project_id)
                else:
                    self.db = firestore.Client()
                self.connection_error = None  # ADC succeeded, clear any earlier note
            except Exception as e:
                if self.connection_error is None:
                    self.connection_error = f"ADC initialization failed: {e}"
                print(f"GCP default initialization failed: {e}")

        # Initialize collection if connection succeeded
        if self.db is not None:
            self.collection = self.db.collection("security_events")
        else:
            print("Firestore is running in unconfigured fallback mode.")

    @property
    def is_connected(self):
        return self.collection is not None

    def get_recent_events(self, limit=20):
        if self.collection is None:
            return []
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
            return events
        except Exception as e:
            print(f"Error fetching recent events: {e}")
            return []

    def get_blocked_events(self, limit=20):
        if self.collection is None:
            return []
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
            return events
        except Exception as e:
            print(f"Error fetching blocked events: {e}")
            return []

    def get_event_count(self):
        if self.collection is None:
            return 0
        try:
            documents = self.collection.stream()
            return sum(1 for _ in documents)
        except Exception as e:
            print(f"Error getting event count: {e}")
            return 0 
