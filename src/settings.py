from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings (BaseSettings):
    DB_HOST: str
    DB_PORT: str
    DB_DATABASE: str
    DB_USER: str
    DB_PASSWORD: str
    SECRET_KEY: str
    ALGORITHM: str
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_PORT: str
    MAIL_SERVER: str
    mailtrap_token: str
    
    model_config = SettingsConfigDict (env_file= ".env")

settings = Settings ()