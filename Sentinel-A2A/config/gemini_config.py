import os


class GeminiConfig:
    """
    Central configuration for Sentinel-A2A's Gemini
    security intelligence layer.

    Keeps model and API configuration in one place.
    """

    # Gemini API key is read from the environment.
    # Never hard-code the actual key here.
    API_KEY = os.getenv("GEMINI_API_KEY")

    # Gemini model used for semantic threat analysis.
    MODEL = "gemini-2.5-flash"

    # Temperature controls how deterministic Gemini's
    # security analysis should be.
    TEMPERATURE = 0.0

    # Maximum output size for the security analysis.
    MAX_OUTPUT_TOKENS = 500

    @classmethod
    def validate(cls):
        """
        Verify that the Gemini API key is available.
        """

        if not cls.API_KEY:
            raise ValueError(
                "GEMINI_API_KEY is not configured."
            )

        return True
