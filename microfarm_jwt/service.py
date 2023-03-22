import jwt
import asyncio
import logging
from pathlib import Path
from aiozmq import rpc
from minicli import run, cli
from datetime import datetime, timedelta, timezone


logger = logging.getLogger('microfarm_jwt')


class JWTService(rpc.AttrHandler):

    def __init__(self, private_key: bytes, public_key: bytes):
        self.private_key = private_key
        self.public_key = public_key

    @rpc.method
    def get_token(self, data: dict) -> str:
        logger.info('Got jwt request.')
        data = {
            **data,
            "exp": datetime.now(tz=timezone.utc) + timedelta(hours=1)
        }
        return jwt.encode(data, self.private_key, algorithm="RS256")

    @rpc.method
    def verify_token(self, token: str) -> dict:
        try:
            return jwt.decode(token, self.public_key, algorithms=["RS256"])
        except jwt.exceptions.InvalidSignatureError:
            return {"error": "Invalid token"}
        except jwt.ExpiredSignatureError:
            return {"error": "Token expired"}


@cli
async def serve(config: Path, private_key: Path, public_key: Path) -> None:
    import tomli
    import logging.config

    assert config.is_file()
    assert private_key.is_file()
    assert public_key.is_file()

    with config.open("rb") as f:
        settings = tomli.load(f)

    with private_key.open("rb") as f:
        private_key_pem = f.read()

    with public_key.open("rb") as f:
        public_key_pem = f.read()

    if logconf := settings.get('logging'):
        print('Applying logging configuration.')
        logging.config.dictConfigClass(logconf).configure()

    service = JWTService(private_key_pem, public_key_pem)
    server = await rpc.serve_rpc(service, bind=settings['rpc']['bind'])
    print(f" [x] JWT Service ({settings['rpc']['bind']})")
    await server.wait_closed()


if __name__ == '__main__':
    run()
