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

        # 1. First priority: Try loading from Streamlit secrets (textkey or dict)
        if hasattr(st, "secrets") and "textkey" in st.secrets:
            try:
                raw_key = st.secrets["textkey"]
                key_dict = json.loads(raw_key) if isinstance(raw_key, str) else dict(raw_key)
                creds = service_account.Credentials.from_service_account_info(key_dict)
                self.project_id = self.project_id or key_dict.get("project_id")
                self.db = firestore.Client(credentials=creds, project=self.project_id)
            except Exception as e:
                print(f"Firestore secret initialization failed: {e}")

        # 2. Second priority: Standard GCP environment credentials
        if self.db is None:
            if not self.project_id:
                raise ValueError("GOOGLE_CLOUD_PROJECT is not configured and no Streamlit secrets found.")
            self.db = firestore.Client(project=self.project_id)

        # Connect to the security events collection.
        self.collection = self.db.collection("security_events")

    def get_recent_events(self, limit=20):
        """
        Retrieve the most recent Sentinel-A2A events.
        """
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
        """
        Retrieve recently blocked security events.
        """
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
        """
        Return the total number of stored security events.
        """
        try:
            documents = self.collection.stream()
            return sum(1 for _ in documents)
        except Exception as e:
            print(f"Error getting event count: {e}")
            return 0 
