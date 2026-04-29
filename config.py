import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(64).hex())
    DEBUG = os.environ.get('FLASK_DEBUG', 'False') == 'True'

    # Original API Keys
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
    HUNTER_API_KEY = os.environ.get('HUNTER_API_KEY', '')
    DEHASHED_EMAIL = os.environ.get('DEHASHED_EMAIL', '')
    DEHASHED_API_KEY = os.environ.get('DEHASHED_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    WHATCMS_API_KEY = os.environ.get('WHATCMS_API_KEY', '')

    # Breach Databases
    SNUSBASE_API_KEY = os.environ.get('SNUSBASE_API_KEY', '')
    BETA_SNUSBASE_KEY = os.environ.get('BETA_SNUSBASE_KEY', '')
    LEAKCHECK_API_KEY = os.environ.get('LEAKCHECK_API_KEY', '')
    INTELVAULT_KEY = os.environ.get('INTELVAULT_KEY', '')
    INTELX_KEY = os.environ.get('INTELX_KEY', '')

    # OSINT Platforms
    CSINT_TOOLS_KEY1 = os.environ.get('CSINT_TOOLS_KEY1', '')
    CSINT_TOOLS_KEY2 = os.environ.get('CSINT_TOOLS_KEY2', '')
    TRACKED_SH_KEY1 = os.environ.get('TRACKED_SH_KEY1', '')
    TRACKED_SH_KEY2 = os.environ.get('TRACKED_SH_KEY2', '')
    OSINTCAT_KEY1 = os.environ.get('OSINTCAT_KEY1', '')
    OSINTCAT_KEY2 = os.environ.get('OSINTCAT_KEY2', '')
    SOURCE_RED_KEY = os.environ.get('SOURCE_RED_KEY', '')
    SEON_API_KEY = os.environ.get('SEON_API_KEY', '')
    OSINTWAVE_KEY = os.environ.get('OSINTWAVE_KEY', '')

    # Paid Service Credentials
    GOLOOKUP_EMAIL = os.environ.get('GOLOOKUP_EMAIL', '')
    GOLOOKUP_PASS = os.environ.get('GOLOOKUP_PASS', '')

    # Rate limiting
    RATE_LIMIT_REQUESTS = 10
    RATE_LIMIT_WINDOW = 60

    @classmethod
    def apis_configured(cls):
        return {
            'shodan': bool(cls.SHODAN_API_KEY),
            'hunter': bool(cls.HUNTER_API_KEY),
            'dehashed': bool(cls.DEHASHED_EMAIL and cls.DEHASHED_API_KEY),
            'virustotal': bool(cls.VIRUSTOTAL_API_KEY),
            'whatcms': bool(cls.WHATCMS_API_KEY),
            'snusbase': bool(cls.SNUSBASE_API_KEY),
            'leakcheck': bool(cls.LEAKCHECK_API_KEY),
            'intelvault': bool(cls.INTELVAULT_KEY),
            'intelx': bool(cls.INTELX_KEY),
            'seon': bool(cls.SEON_API_KEY),
            'osintwave': bool(cls.OSINTWAVE_KEY),
            'csint_tools': bool(cls.CSINT_TOOLS_KEY1),
            'tracked_sh': bool(cls.TRACKED_SH_KEY1),
            'osintcat': bool(cls.OSINTCAT_KEY1),
            'source_red': bool(cls.SOURCE_RED_KEY),
            'golookup': bool(cls.GOLOOKUP_EMAIL and cls.GOLOOKUP_PASS),
        }
