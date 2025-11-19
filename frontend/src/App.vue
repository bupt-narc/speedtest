<template>
    <div class="app">
        <h1>Proactive DDos Defender Speed Test</h1>

        <div class="info-container">
            <p>{{ now.IpAddress }}</p>
            <button @click="saveCSV">save csv</button>
            <div style="height: 100%;width: 100%">
                <p>Ping: {{ now.Ping.toFixed(2) }} ms</p>
                <div class="echarts-container"
                     style="width: 800px;height: 250px">
                    <echarts-component name="Ping"
                                       container-id="echarts-component-ping"
                                       ref="chartPingRef"/>
                </div>
            </div>

            <div style="height: 100%;width: 100%">
                <p>Jitter: {{ now.Jitter.toFixed(2) }} ms</p>
                <div class="echarts-container"
                     style="width: 800px;height: 250px">
                    <echarts-component name="Jitter"
                                       container-id="echarts-component-jitter"
                                       ref="chartJitterRef"/>
                </div>
            </div>

            <div style="height: 100%;width: 100%">
                <p>Download Speed: {{ downloadSpeed.toFixed(2) }} KB/s</p>
                <div class="echarts-container"
                     style="width: 800px;height: 250px">
                    <echarts-component name="Download Speed(KB/s)"
                                       container-id="echarts-component-download-speed"
                                       ref="chartDownloadSpeedRef"/>
                </div>
            </div>

            <div style="height: 100%;width: 100%">
                <p>Upload Speed: {{ uploadSpeed.toFixed(2) }} KB/s</p>
                <div class="echarts-container"
                     style="width: 800px;height: 250px">
                    <echarts-component name="Upload Speed(KB/s)"
                                       container-id="echarts-component-upload-speed"
                                       ref="chartUploadSpeedRef"/>
                </div>
            </div>
        </div>
    </div>
</template>

<script setup lang="ts">
import {onMounted, onUnmounted, ref} from "vue";
import {exportCsv} from "@/utils/csv";
import type {csvHeaderINTF} from "@/interfaces/csvHeaderINTF";
import EchartsComponent from "@/models/echartsComponent.vue";

const now = ref({
    IpAddress: "",
    Ping: 0,
    Jitter: 0
})
const downloadSpeed = ref(0);
const uploadSpeed = ref(0);
const networkData = ref<Map<string, string>[]>([])
let timer: number

const chartPingRef = ref<{ chartData: [] }>()
const chartJitterRef = ref<{ chartData: [] }>()
const chartDownloadSpeedRef = ref<{ chartData: [] }>()
const chartUploadSpeedRef = ref<{ chartData: [] }>()

// Track ongoing tests to prevent overlaps
let downloadTestInProgress = false;
let uploadTestInProgress = false;

onMounted(() => {
    // Warm up connection first
    warmupConnection().then(() => {
        // Run tests every 2 seconds to avoid overlap
        timer = setInterval(() => {
            testNetworkStatus();
            if (!downloadTestInProgress) {
                testDownloadSpeed();
            }
            if (!uploadTestInProgress) {
                testUploadSpeed();
            }
            addNetworkData();
            updateCharts();
        }, 2000)
    })
})

// Warm up the connection to the server
async function warmupConnection() {
    try {
        // Make a few small requests to establish the connection
        for (let i = 0; i < 3; i++) {
            await fetch("backend/getIP");
            await new Promise(resolve => setTimeout(resolve, 100));
        }
    } catch (error) {
        console.error("Warmup failed:", error);
    }
}

function testNetworkStatus() {
    const startTime = Date.now()
    fetch("backend/getIP")
        .then(response => {
            if (!response.ok) {
                now.value.Ping = 0
                now.value.Jitter = 0
                throw new Error("Failed to fetch from server!");
            }

            return response.json() as Promise<IIPInformation>
        })
        .then(info => {
            const duration = Math.abs(Date.now() - startTime)
            const jitter = Math.abs(now.value.Ping - duration);
            now.value = {
                IpAddress: info.processedString,
                Ping: duration,
                Jitter: jitter < now.value.Jitter ? jitter * 0.8 + now.value.Jitter * 0.2 :
                    jitter * 0.3 + now.value.Jitter * 0.7
            }
        })
}

async function testDownloadSpeed() {
    if (downloadTestInProgress) {
        return; // Skip if test is already running
    }
    
    downloadTestInProgress = true;
    
    try {
        const response = await fetch("backend/garbage?ckSize=8");
        
        if(!response.ok) {
            downloadSpeed.value = 0;
            downloadTestInProgress = false;
            return;
        }
        
        if (!response.body) {
            downloadSpeed.value = 0;
            downloadTestInProgress = false;
            return;
        }
        
        const reader = response.body.getReader();
        let totalSize = 0;
        let startTime = 0;
        let endTime = 0;
        let firstChunkReceived = false;

        const processData = (result: ReadableStreamReadResult<Uint8Array>): void => {
            if (result.done) {
                endTime = Date.now();
                // Calculate speed: totalSize in bytes, time in milliseconds
                // Convert to KB/s: (bytes / 1024) / (ms / 1000) = bytes * 1000 / 1024 / ms
                if (firstChunkReceived && endTime > startTime) {
                    const newSpeed = totalSize / 1024 / (endTime - startTime) * 1000;
                    // Apply smoothing to reduce fluctuations
                    downloadSpeed.value = downloadSpeed.value === 0 ? newSpeed : 
                        newSpeed * 0.3 + downloadSpeed.value * 0.7;
                }
                downloadTestInProgress = false;
                return;
            }
            
            // Start timing after first chunk to exclude connection overhead
            if (!firstChunkReceived) {
                startTime = Date.now();
                firstChunkReceived = true;
            }
            
            // Read next chunk
            const value = result.value;
            const length = value.length;
            totalSize += length;
            reader.read().then(processData);
        };
        
        reader.read().then(processData);
    } catch (error) {
        console.error("Download test failed:", error);
        downloadTestInProgress = false;
    }
}

async function testUploadSpeed() {
    if (uploadTestInProgress) {
        return; // Skip if test is already running
    }
    
    uploadTestInProgress = true;
    
    try {
        // Create 2MB of data for a more accurate test
        const fileSizeInBytes = 2 * 1024 * 1024; // 2MB
        const buffer = new ArrayBuffer(fileSizeInBytes);
        const dataView = new DataView(buffer);

        // Fill with random-ish data
        for (let i = 0; i < fileSizeInBytes; i++) {
            dataView.setUint8(i, i % 256);
        }
        
        // Start timing just before the fetch
        const startTime = Date.now();
        
        const response = await fetch("backend/empty", {
            method: "POST",
            body: dataView
        });
        
        if (!response.ok) {
            uploadSpeed.value = 0;
            uploadTestInProgress = false;
            return;
        }
        
        // Calculate upload speed
        // Time includes upload + minimal server processing
        // This is more accurate than trying to separate them
        const endTime = Date.now();
        const durationMs = endTime - startTime;
        
        if (durationMs > 0) {
            const newSpeed = fileSizeInBytes / 1024 / durationMs * 1000;
            // Apply smoothing to reduce fluctuations
            uploadSpeed.value = uploadSpeed.value === 0 ? newSpeed :
                newSpeed * 0.3 + uploadSpeed.value * 0.7;
        }
        
        uploadTestInProgress = false;
    } catch (error) {
        console.error("Upload test failed:", error);
        uploadTestInProgress = false;
    }
}

function saveCSV() {
    const columns: csvHeaderINTF[] = [
        {
            title: "time",
            key: "time"
        },
        {
            title: "ping",
            key: "ping"
        },
        {
            title: "jitter",
            key: "jitter"
        },
        {
            title: "download speed(KB/s)",
            key: "download speed"
        },
        {
            title: "upload speed(KB/s)",
            key: "upload speed"
        },
    ]

    exportCsv(columns, networkData.value, "network" + Date.now() + ".csv");
}

function addNetworkData() {
    const data = new Map<string, string>();
    data.set("time", new Date().getTime().toString());
    data.set("ping", now.value.Ping.toString());
    data.set("jitter", now.value.Jitter.toString());
    data.set("download speed", downloadSpeed.value.toString());
    data.set("upload speed", uploadSpeed.value.toString());
    networkData.value.push(data);
}

function updateCharts() {
    updateSingleChart(chartPingRef.value?.chartData, "ping");
    updateSingleChart(chartJitterRef.value?.chartData, "jitter");
    updateSingleChart(chartDownloadSpeedRef.value?.chartData, "download speed");
    updateSingleChart(chartUploadSpeedRef.value?.chartData, "upload speed");
}

function updateSingleChart(chartData: (number | string)[][] | undefined, attr: string) {
    if (chartData != undefined) {
        if (chartData.length > 30) {
            chartData.shift();
        }
        const mapItem = networkData.value[networkData.value.length - 1]
        const timeStr = mapItem.get('time');
        let time = 0;
        if(timeStr != undefined) {
            time = ~~timeStr;
        }
        const value = mapItem.get(attr);
        const newData = [time, value];
        // @ts-ignore
        chartData.push(newData);
    }
}

onUnmounted(() => {
    clearInterval(timer);
})
</script>

<style>
.app {
    width: 100%;
    height: 100%;
}

.info-container {
    width: 100%;
    height: auto;
}
</style>
