from collections.abc import Awaitable, Callable

from starlette.types import Message, Send


def warm_before_startup_complete(
    send: Send, warm: Callable[[], Awaitable[None]]
) -> Send:
    async def warming_send(message: Message) -> None:
        if message["type"] == "lifespan.startup.complete":
            await warm()
        await send(message)

    return warming_send
