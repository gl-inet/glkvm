





















from ...clients.streamer import StreamerFormats
from ...clients.streamer import MemsinkStreamerClient

from .. import init

from .server import MediaServer



def main(argv: (list[str] | None)=None) -> None:
    config = init(
        prog="kvmd-media",
        description="The media proxy",
        check_run=True,
        argv=argv,
    )[2].media

    def make_streamer(name: str, fmt: int) -> (MemsinkStreamerClient | None):
        if getattr(config.memsink, name).sink:
            return MemsinkStreamerClient(name.upper(), fmt, **getattr(config.memsink, name)._unpack())
        return None

    MediaServer(
        h264_streamer=make_streamer("h264", StreamerFormats.H264),
        jpeg_streamer=make_streamer("jpeg", StreamerFormats.JPEG),
    ).run(**config.server._unpack())
