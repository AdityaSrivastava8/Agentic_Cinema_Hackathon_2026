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
        Uses event_id as the document ID if present, otherwise auto-generates one.
        """
        if not isinstance(security_event, dict):
            raise ValueError("security_event must be a dictionary.")

        # Re-use the existing UUID if Sentinel already assigned an event_id
        doc_id = security_event.get("event_id")

        if doc_id:
            document = self.collection.document(str(doc_id))
        else:
            document = self.collection.document()

        # Save event payload to Firestore
        document.set(security_event)

        # Return the document ID
        return document.id

    def get_recent_events(self, limit=50):
        """
        Retrieve the latest security logs from Firestore for audit dashboards.
        """
        try:
            docs = (
                self.collection
                .order_by("timestamp", direction=firestore.Query.DESCENDING)
                .limit(limit)
                .stream()
            )
            return [doc.to_dict() for doc in docs]
        except Exception as error:
            print(f"[FirestoreLogger] Error retrieving logs: {error}")
            return [] 
