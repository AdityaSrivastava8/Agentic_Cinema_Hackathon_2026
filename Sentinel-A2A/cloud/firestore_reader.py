import os

from google.cloud import firestore


class FirestoreReader:
    """
    Reads Sentinel-A2A security events from Google Cloud
    Firestore for the monitoring dashboard.
    """

    def __init__(self, project_id=None):

        # Use the supplied project ID or read it from
        # the Google Cloud environment.
        self.project_id = project_id or os.getenv(
            "GOOGLE_CLOUD_PROJECT"
        )

        if not self.project_id:
            raise ValueError(
                "GOOGLE_CLOUD_PROJECT is not configured."
            )

        # Create the Firestore client.
        self.db = firestore.Client(
            project=self.project_id
        )

        # Connect to the security events collection.
        self.collection = self.db.collection(
            "security_events"
        )

    def get_recent_events(self, limit=20):
        """
        Retrieve the most recent Sentinel-A2A events.
        """

        documents = (
            self.collection
            .order_by(
                "timestamp",
                direction=firestore.Query.DESCENDING
            )
            .limit(limit)
            .stream()
        )

        events = []

        for document in documents:

            event = document.to_dict()

            # Add the Firestore document ID.
            event["document_id"] = document.id

            events.append(event)

        return events

    def get_blocked_events(self, limit=20):
        """
        Retrieve recently blocked security events.
        """

        documents = (
            self.collection
            .where(
                "decision",
                "==",
                "BLOCK"
            )
            .limit(limit)
            .stream()
        )

        events = []

        for document in documents:

            event = document.to_dict()

            event["document_id"] = document.id

            events.append(event)

        return events

    def get_event_count(self):
        """
        Return the total number of stored security events.
        """

        documents = self.collection.stream()

        return sum(
            1 for _ in documents
        )
