"""
Central Google Cloud configuration for Sentinel-A2A.

Keeps Google Cloud settings in one place so the rest
of the application does not contain hard-coded
project configuration.
"""

import os


class CloudConfig:
    """
    Reads Sentinel-A2A Google Cloud configuration
    from environment variables.
    """

    def __init__(self):

        # Google Cloud project.
        self.project_id = os.getenv(
            "GOOGLE_CLOUD_PROJECT"
        )

        # Google Cloud region.
        self.region = os.getenv(
            "GOOGLE_CLOUD_REGION",
            "us-central1"
        )

        # Firestore database.
        self.firestore_database = os.getenv(
            "FIRESTORE_DATABASE",
            "(default)"
        )

        # Gemini model used by Sentinel-A2A.
        self.gemini_model = os.getenv(
            "GEMINI_MODEL",
            "gemini-2.5-flash"
        )

        # Cloud Run service name.
        self.cloud_run_service = os.getenv(
            "CLOUD_RUN_SERVICE",
            "sentinel-a2a"
        )

    def is_configured(self):
        """
        Check whether the minimum Google Cloud
        configuration is available.
        """

        return bool(
            self.project_id
        )

    def get_summary(self):
        """
        Return configuration information safe
        for displaying in the dashboard.

        No credentials or secrets are returned.
        """

        return {
            "project_id": self.project_id or "Not configured",
            "region": self.region,
            "firestore_database": self.firestore_database,
            "gemini_model": self.gemini_model,
            "cloud_run_service": self.cloud_run_service
        }
