from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import socketio
from .api import analysis
from .core.database import engine, Base
import asyncio

app = FastAPI(title="ForTAI API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Socket.IO setup
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=["http://localhost:3000"]
)
socket_app = socketio.ASGIApp(sio)

# Include API routers
app.include_router(analysis.router, prefix="/api", tags=["analysis"])

# Mount Socket.IO
app.mount("/socket.io", socket_app)


@app.on_event("startup")
async def startup_event():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@sio.event
async def connect(sid, environ):
    print(f"Client {sid} connected")


@sio.event
async def disconnect(sid):
    print(f"Client {sid} disconnected")


@app.get("/")
async def root():
    return {"message": "ForTAI API is running"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}