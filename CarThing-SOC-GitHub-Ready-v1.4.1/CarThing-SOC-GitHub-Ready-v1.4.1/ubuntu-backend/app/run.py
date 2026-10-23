"""Run server with validated host and port from .env."""
import uvicorn
from .config import Settings

if __name__ == "__main__":
    s = Settings()
    s.validate()
    uvicorn.run("app.main:app", host=s.host, port=s.port, workers=1)
