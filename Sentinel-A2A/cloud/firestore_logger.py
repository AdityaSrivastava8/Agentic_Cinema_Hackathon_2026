import json
import os

import streamlit as st
from google.cloud import firestore
from google.oauth2 import service_account


class FirestoreLogger:
    """
    Writes Sentinel-A2A security events to Google Cloud Firestore.

    Uses the SAME credential resolution order as FirestoreReader so that
    logging (writes) and the dashboard (reads) always talk to the same
    Firestore project with the same credentials.
    """

    def __init__(self, project_id=None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
        self.db = None
        self.collection = None

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
                    print(f"Firestore secret initialization failed (logger): {e}")

        # 2. Second priority: standard GCP Application Default Credentials
        if self.db is None:
            try:
                if self.project_id:
                    self.db = firestore.Client(project=self.project_id)
                else:
                    self.db = firestore.Client()
            except Exception as e:
                print(f"GCP default initialization failed (logger): {e}")

        # Initialize collection if connection succeeded
        if self.db is not None:
            self.collection = self.db.collection("security_events")
        else:
            print("FirestoreLogger is running in unconfigured fallback mode.")

    def log_event(self, event):
        """
        Write a single security event dict to Firestore.

        Returns the new document ID on success, or None if logging is
        unavailable / fails (the caller decides how to surface that).
        """
        if self.collection is None:
            return None
        try:
            doc_ref = self.collection.document()
            doc_ref.set(event)
            return doc_ref.id
        except Exception as e:
            print(f"Error logging event to Firestore: {e}")
            return None 
