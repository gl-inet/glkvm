# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    Copyright (C) 2018-2024  Maxim Devaev <mdevaev@gmail.com>               #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
#    This program is distributed in the hope that it will be useful,         #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#    GNU General Public License for more details.                            #
#                                                                            #
#    You should have received a copy of the GNU General Public License       #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                            #
# ========================================================================== #


import re
import asyncio
import time
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import AsyncGenerator

# =====
class LogReader:
    def __init__(self):
        self.logger = logging.getLogger('kvmd')
        self.logger.setLevel(logging.DEBUG)
        handler = RotatingFileHandler(
            filename='/var/log/kvmd.log',
            maxBytes=512 * 1024,
            backupCount=2,
        )
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    async def poll_log(self, seek: int, follow: bool) -> AsyncGenerator[dict, None]:
        with open('/var/log/kvmd.log', 'r') as log_file:
            if seek > 0:
                log_file.seek(0, 2)
                file_size = log_file.tell()
                log_file.seek(max(0, file_size - seek), 0)

            while True:
                line = log_file.readline()
                if line:
                    yield self.__line_to_record(line)
                elif follow:
                    await asyncio.sleep(1)
                else:
                    break

    def __line_to_record(self, line: str) -> dict:
        parts = line.split(' - ', 3)
        if len(parts) == 4:
            dt = datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S,%f')
            return {
                "dt": dt,
                "service": "kvmd",
                "msg": parts[3].rstrip(),
            }
        return {}
