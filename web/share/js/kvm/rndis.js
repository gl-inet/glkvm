/*****************************************************************************
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
*****************************************************************************/


"use strict";

import {tools, $} from "../tools.js";
import {wm} from "../wm.js";

export function Rndis() {
    var self = this;
    var __running = false;

    var __init__ = function() {
        tools.el.setOnClick($("rndis-toggle-button"), __toggleRndis);
        __updateState();
    };

    var __updateState = function() {
        tools.httpGet("/api/rndis/status", function(http) {
            if (http.status === 200) {
                let data = JSON.parse(http.responseText);
                if (data.result && data.result.hasOwnProperty("running")) {
                    __running = data.result.running;
                    $("rndis-toggle-button").innerHTML = (__running ? "&bull; Stop RNDIS" : "&bull; Start RNDIS");
                } else {
                    console.error("Invalid RNDIS status response format");
                }
            }
        });
    };

    var __toggleRndis = function() {
        const action = __running ? "stop" : "start";
        tools.httpPost(`/api/rndis/${action}`, function(http) {
            if (http.status === 200) {
                tools.info(`RNDIS ${action}ed`);
                __updateState();
            } else {
                wm.error(`Can't ${action} RNDIS:<br>`, http.responseText);
            }
        });
    };

    self.setSocket = function(ws) {
        tools.el.setEnabled($("rndis-toggle-button"), ws);
    };

    __init__();
} 