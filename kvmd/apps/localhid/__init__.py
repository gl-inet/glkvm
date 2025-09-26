





















from ...clients.kvmd import KvmdClient

from ... import htclient

from .. import init

from .server import LocalHidServer



def main(argv: (list[str] | None)=None) -> None:
    config = init(
        prog="kvmd-localhid",
        description=" Local HID to KVMD proxy",
        check_run=True,
        argv=argv,
    )[2].localhid

    user_agent = htclient.make_user_agent("KVMD-LocalHID")

    LocalHidServer(
        kvmd=KvmdClient(user_agent=user_agent, **config.kvmd._unpack()),
    ).run()
