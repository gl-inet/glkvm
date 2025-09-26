





















from . import BaseAuthService



class Plugin(BaseAuthService):
    async def authorize(self, user: str, passwd: str) -> bool:
        _ = user
        _ = passwd
        return False
