from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    APP_NAME: str = "netinspect"
    VERSION: str = "1.0.0"
    RATE_LIMIT: str = "60/minute"
    CACHE_TTL_DNS: int = 300
    CACHE_TTL_WHOIS: int = 3600
    CACHE_TTL_SSL: int = 3600
    CACHE_TTL_IP: int = 86400
    CACHE_TTL_HEADERS: int = 300
    CACHE_TTL_REDIRECTS: int = 300
    PORT_SCAN_LIST: str = Field(default="21,22,25,53,80,443,3306,5432,6379,8080,8443,27017")
    API_VERSION: str = "v1"
    SQLITE_DB: str = "netinspect.db"
    IP_API_URL: str = "http://ip-api.com/json/{ip}?fields=66846719"
    # timeouts
    HTTP_TIMEOUT: int = 10

    class Config:
        env_file = ".env"


settings = Settings()
