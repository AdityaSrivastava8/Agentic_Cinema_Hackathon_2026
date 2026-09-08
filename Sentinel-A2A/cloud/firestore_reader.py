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

        # 1. First priority: Check standard Streamlit secret configurations
        if hasattr(st, "secrets"):
            secret_key = None
            if "textkey" in st.secrets:
                secret_key = st.secrets["textkey"]
            elif "firestore" in st.secrets:
                secret_key = st.secrets["firestore"]
            elif "gcp_service_account" in st.secrets:
                secret_key = st.secrets["gcp_service_account"]

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
                    print(f"Firestore secret initialization failed: {e}")

        # 2. Second priority: Standard GCP environment credentials
        if self.db is None and self.project_id:
            try:
                self.db = firestore.Client(project=self.project_id)
            except Exception as e:
                print(f"GCP default initialization failed: {e}")

        # Initialize collection if database connection is established
        if self.db is not None:
            self.collection = self.db.collection("security_events")
        else:
            print("Firestore is running in unconfigured fallback mode.")

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
