from fastapi import FastAPI

app = FastAPI(title="PMA Auth Service", version="1.0.0")


@app.get("/health")
def health_check():
    return {"status": "ok"}