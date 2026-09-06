import os


class GeminiConfig:
    """
    Configuration for Sentinel-A2A's Gemini security engine
    running through Google Cloud Vertex AI.
    """

    # Google Cloud project ID.
    PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT")

    # Vertex AI location.
    LOCATION = os.getenv(
        "GOOGLE_CLOUD_LOCATION",
        "global"
    )

    # Gemini model used for semantic threat analysis.
    MODEL = "gemini-2.5-flash"

    # Keep security analysis deterministic.
    TEMPERATURE = 0.0

    @classmethod
    def validate(cls):
        """
        Make sure the required Google Cloud configuration
        is available.
        """

        if not cls.PROJECT_ID:
            raise ValueError(
                "GOOGLE_CLOUD_PROJECT is not configured."
            )

        return True 
