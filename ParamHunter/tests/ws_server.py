#!/usr/bin/env python3
"""Mock WebSocket vulnerável (só p/ testar --websocket). ws://127.0.0.1:8001/"""
import asyncio
from aiohttp import web, WSMsgType


async def handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    async for msg in ws:
        if msg.type == WSMsgType.TEXT:
            data = msg.data
            if "'" in data or '"' in data:
                await ws.send_str("You have an error in your SQL syntax (MySQL) near ''")
            else:
                await ws.send_str("echo:" + data[:120])
        elif msg.type == WSMsgType.ERROR:
            break
    return ws


app = web.Application()
app.router.add_route("GET", "/", handler)

if __name__ == "__main__":
    print("[ws-lab] ws://127.0.0.1:8001/")
    web.run_app(app, host="127.0.0.1", port=8001, print=None)
