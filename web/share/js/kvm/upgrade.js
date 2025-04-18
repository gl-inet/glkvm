import {tools} from "../tools.js";

export function Upgrade() {
    var self = this;

    self.init = function() {
        // 获取版本信息(最优先执行)
        self.compareVersions();

        // 使用 document.getElementById 替代 tools.$
        self.selectButton = document.getElementById("upgrade-select-button");
        self.downloadButton = document.getElementById("upgrade-download-button");
        self.startButton = document.getElementById("upgrade-start-button");
        self.fileInput = document.getElementById("upgrade-file");
        self.messageUploading = document.getElementById("upgrade-message-uploading");
        self.messageDownloading = document.getElementById("upgrade-message-downloading");
        self.messageVersion = document.getElementById("upgrade-message-version");
        self.localModel = document.getElementById("upgrade-local-model");
        self.localVersion = document.getElementById("upgrade-local-version");
        self.serverModel = document.getElementById("upgrade-server-model");
        self.serverVersion = document.getElementById("upgrade-server-version");

        // 绑定事件
        if (self.selectButton) {
            self.selectButton.onclick = () => {
                if (self.fileInput) {
                    self.fileInput.click();
                }
            };
        }

        if (self.downloadButton) {
            self.downloadButton.onclick = () => self.downloadFirmware();
        }

        if (self.startButton) {
            self.startButton.onclick = () => self.startUpgrade();
        }

        if (self.fileInput) {
            self.fileInput.onchange = (event) => self.handleFileSelect(event);
        }
    };

    self.compareVersions = function() {
        tools.httpGet("/api/upgrade/compare",
            function(response) {  // callback
                try {
                    // 解析响应JSON
                    const result = JSON.parse(response.responseText);
                    const compare_result = result.result;

                    if (result.error) {
                        tools.error("Failed to compare versions: " + result.error);
                        return;
                    }

                    // 获取元素(因为此时可能还没有执行init的其他部分)
                    const localModel = document.getElementById("upgrade-local-model");
                    const localVersion = document.getElementById("upgrade-local-version");
                    const serverModel = document.getElementById("upgrade-server-model");
                    const serverVersion = document.getElementById("upgrade-server-version");
                    const messageVersion = document.getElementById("upgrade-message-version");

                    if (localModel) localModel.innerHTML = compare_result.local_model || "Unknown";
                    if (localVersion) localVersion.innerHTML = compare_result.local_version || "Unknown";
                    if (serverModel) serverModel.innerHTML = compare_result.server_model || "Unknown";
                    if (serverVersion) serverVersion.innerHTML = compare_result.server_version || "Unknown";

                    // 显示版本信息区域
                    if (messageVersion) {
                        messageVersion.classList.remove("hidden");
                    }

                    // 如果有新版本可用,显示提示
                    if (compare_result.local_version && compare_result.server_version &&
                        compare_result.local_version !== compare_result.server_version) {
                        tools.info("New firmware version available: " + compare_result.server_version);
                    }
                } catch (error) {
                    tools.error("Failed to parse version info: " + error.message);
                    console.error("Raw response:", response.responseText);
                }
            }
        );
    };

    self.handleFileSelect = function(event) {
        const file = event.target.files[0];
        if (!file) return;

        self.messageUploading.classList.remove("hidden");
        self.selectButton.disabled = true;

        // 创建并显示进度条
        const progressBar = document.createElement("div");
        progressBar.className = "progress-bar";
        progressBar.innerHTML = `
            <div class="progress-value"></div>
        `;
        self.messageUploading.appendChild(progressBar);

        const formData = new FormData();
        formData.append("file", file);

        // 创建 XHR 请求以支持进度监控
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/upgrade/upload", true);

        // 监听上传进度
        xhr.upload.onprogress = function(e) {
            if (e.lengthComputable) {
                const percent = (e.loaded / e.total) * 100;
                tools.progress.setValue(progressBar, `Uploading: ${file.name}`, percent);
            }
        };

        // 处理请求完成
        xhr.onload = function() {
            self.messageUploading.classList.add("hidden");
            self.selectButton.disabled = false;

            try {
                const response = JSON.parse(xhr.responseText);
                if (response.error) {
                    tools.error("Firmware upload failed: " + response.error);
                    return;
                }

                // 显示上传成功信息
                tools.info(`Firmware ${file.name} (${tools.formatSize(response.size)}) uploaded successfully`);
                self.startButton.disabled = false;

            } catch (error) {
                tools.error("Failed to parse response: " + error);
            }

            // 清理进度条
            progressBar.remove();
        };

        // 处理上传错误
        xhr.onerror = function() {
            self.messageUploading.classList.add("hidden");
            self.selectButton.disabled = false;
            tools.error("Network error occurred during firmware upload");
            progressBar.remove();
        };

        // 开始上传
        xhr.send(formData);
    };

    self.startUpgrade = function() {
        if (!confirm("Are you sure you want to upgrade the system? The device will reboot after upgrade.")) {
            return;
        }

        self.selectButton.disabled = true;
        self.startButton.disabled = true;

        // 创建状态消息元素
        const statusMessage = document.createElement("div");
        statusMessage.className = "upgrade-status-message";
        self.messageVersion.parentNode.insertBefore(statusMessage, self.messageVersion.nextSibling);

        // 显示等待消息
        statusMessage.innerHTML = `
            <div class="message-content waiting">
                <span class="spinner"></span>
                Starting upgrade...
            </div>
        `;

        tools.httpPost("/api/upgrade/start",
            function(response) {  // callback
                try {
                    const result = JSON.parse(response.responseText);

                    if (result.ok && result.result.status === "Upgrade started") {
                        // Upgrade success
                        statusMessage.innerHTML = `
                            <div class="message-content success">
                                <i class="fas fa-check-circle"></i>
                                Upgrade started, device will reboot soon...
                                <pre class="upgrade-log">${result.result.stdout}</pre>
                            </div>
                        `;
                        tools.info("Upgrade started, device will reboot soon...");

                        // 3秒后自动刷新页面
                        setTimeout(() => {
                            window.location.reload();
                        }, 3000);

                    } else {
                        // 升级失败
                        statusMessage.innerHTML = `
                            <div class="message-content error">
                                <i class="fas fa-exclamation-circle"></i>
                                Upgrade failed: ${result.result.stderr || "Unknown error"}
                                <pre class="upgrade-log">${result.result.stdout || ""}</pre>
                            </div>
                        `;
                        tools.error("Upgrade failed: " + (result.result.stderr || "Unknown error"));
                        self.selectButton.disabled = false;
                        self.startButton.disabled = false;
                    }
                } catch (error) {
                    // JSON 解析错误
                    statusMessage.innerHTML = `
                        <div class="message-content error">
                            <i class="fas fa-exclamation-circle"></i>
                            Failed to parse response: ${error.message}
                        </div>
                    `;
                    tools.error("Failed to parse response: " + error.message);
                    self.selectButton.disabled = false;
                    self.startButton.disabled = false;
                }
            },
            {}  // body
        );
    };

    self.downloadFirmware = function() {
        self.messageDownloading.classList.remove("hidden");
        self.downloadButton.disabled = true;
        self.selectButton.disabled = true;

        // 创建并显示进度条
        const progressBar = document.createElement("div");
        progressBar.className = "progress-bar";
        progressBar.innerHTML = `
            <div class="progress-value"></div>
        `;
        self.messageDownloading.appendChild(progressBar);

        fetch("/api/upgrade/download", {
            method: "GET",
        }).then(response => {
            const reader = response.body.getReader();
            let receivedLength = 0;

            // 读取流数据
            function readStream() {
                reader.read().then(({done, value}) => {
                    if (done) {
                        self.messageDownloading.classList.add("hidden");
                        self.downloadButton.disabled = false;
                        self.selectButton.disabled = false;
                        progressBar.remove();
                        tools.info("固件下载完成");
                        self.startButton.disabled = false;
                        return;
                    }

                    const text = new TextDecoder().decode(value);
                    const lines = text.trim().split('\n');
                    console.log("lines=",lines);

                    lines.forEach(line => {
                        if (!line) return;

                        try {
                            const data = JSON.parse(line);
                            if (data.firmware) {
                                const percent = Math.floor((data.firmware.written / data.firmware.size) * 100);
                                if (percent >= 0 && percent <= 100) {
                                    tools.progress.setValue(progressBar, `正在下载固件: ${percent}%`, percent);
                                }
                            }
                        } catch (error) {
                            console.warn("解析进度数据失败:", error, "原始数据:", line);
                        }
                    });

                    // 继续读取下一块数据
                    readStream();
                }).catch(error => {
                    self.messageDownloading.classList.add("hidden");
                    self.downloadButton.disabled = false;
                    self.selectButton.disabled = false;
                    tools.error("下载固件时发生错误: " + error);
                    progressBar.remove();
                });
            }

            readStream();
        }).catch(error => {
            self.messageDownloading.classList.add("hidden");
            self.downloadButton.disabled = false;
            self.selectButton.disabled = false;
            tools.error("下载固件时发生网络错误");
            progressBar.remove();
        });
    };
}