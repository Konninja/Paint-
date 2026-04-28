import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(64).hex())
    DEBUG = os.environ.get('FLASK_DEBUG', 'False') == 'True'

    # API Keys
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
    HUNTER_API_KEY = os.environ.get('HUNTER_API_KEY', '')
    DEHASHED_EMAIL = os.environ.get('DEHASHED_EMAIL', '')
    DEHASHED_API_KEY = os.environ.get('DEHASHED_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    WHATCMS_API_KEY = os.environ.get('WHATCMS_API_KEY', '')

    # Rate limiting
    RATE_LIMIT_REQUESTS = 10
    RATE_LIMIT_WINDOW = 60  # seconds

    @classmethod
    def apis_configured(cls):
        return {
            'shodan': bool(cls.SHODAN_API_KEY),
            'hunter': bool(cls.HUNTER_API_KEY),
            'dehashed': bool(cls.DEHASHED_EMAIL and cls.DEHASHED_API_KEY),
            'virustotal': bool(cls.VIRUSTOTAL_API_KEY),
            'whatcms': bool(cls.WHATCMS_API_KEY),
        }
