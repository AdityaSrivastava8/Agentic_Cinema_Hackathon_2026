from google.cloud import firestore


class FirestoreLogger:
    """
    Stores Sentinel-A2A security events in Google Cloud Firestore.

    Each inspected agent request can be recorded with:
    - source agent
    - target agent
    - requested tool
    - detected threats
    - risk score
    - risk level
    - authorization result
    - Gemini analysis
    - final decision
    """

    def __init__(self, project_id):
        # Create a Firestore client using the Google Cloud project.
        self.db = firestore.Client(project=project_id)

        # All Sentinel-A2A security events will be stored
        # inside this Firestore collection.
        self.collection = self.db.collection("security_events")

    def log_event(self, security_event):
        """
        Save one Sentinel-A2A security event to Firestore.
        """

        # Add the event as a new Firestore document.
        document = self.collection.document()

        document.set(security_event)

        # Return the generated document ID.
        return document.id 
