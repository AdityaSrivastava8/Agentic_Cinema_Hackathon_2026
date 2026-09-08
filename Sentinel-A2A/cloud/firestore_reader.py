import json
import os
import streamlit as st
from google.cloud import firestore
from google.oauth2 import service_account


class FirestoreReader:
    """
    Reads Sentinel-A2A security logs from Google Cloud Firestore.
    """

    def __init__(self, project_id=None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
        self.db = None
        self.collection = None

        # 1. Check Streamlit secrets
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
                    print(f"[FirestoreReader] Secrets init failed: {e}")

        # 2. Standard GCP Default Credentials Fallback
        if self.db is None:
            try:
                if self.project_id:
                    self.db = firestore.Client(project=self.project_id)
                else:
                    self.db = firestore.Client()
            except Exception as e:
                print(f"[FirestoreReader] GCP default init failed: {e}")

        if self.db is not None:
            self.collection = self.db.collection("security_events")
            print("[FirestoreReader] Connected successfully to Firestore.")

    def get_recent_events(self, limit=50):
        """Fetch latest security logs."""
        if self.collection is None:
            return []

        try:
            docs = (
                self.collection
                .order_by("timestamp", direction=firestore.Query.DESCENDING)
                .limit(limit)
                .stream()
            )
            return [doc.to_dict() for doc in docs]
        except Exception as error:
            print(f"[FirestoreReader] Error reading logs: {error}")
            return [] 
