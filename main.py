from fastapi import FastAPI
from src.auth_router import auth_router
from src.database import init_db
from src.loggings import logging


app = FastAPI ()

app.include_router (auth_router)

@app.on_event ('startup')
async def on_startup ():
    try:
        await init_db ()
    except Exception as e:
        logging.exception ("Error Occured during StartUp")
