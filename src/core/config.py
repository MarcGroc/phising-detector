from pydantic_settings import BaseSettings, SettingsConfigDict
#from pydantic import SecretStr


class DBSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DB_")


class SecuritySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SEC_")
    # SECRET: SecretStr = 'secret'


class Settings(BaseSettings):
    """Loads variables from .env file"""

    PROJECT_NAME: str = "Phising Detector"
    DEBUG: bool = True
    DB: DBSettings = DBSettings()
    SECURITY: SecuritySettings = SecuritySettings()

    model_config = SettingsConfigDict(env_file='./.env', env_file_encoding="utf-8")

settings = Settings()
