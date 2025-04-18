/*****************************************************************************


















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