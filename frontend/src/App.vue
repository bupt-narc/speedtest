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

onMounted(() => {
    timer = setInterval(() => {
        testNetworkStatus();
        testDownloadSpeed();
        testUploadSpeed();
        addNetworkData();
        updateCharts();
    }, 1000)
})

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
    /*const startTime = Date.now()
    fetch("backend/garbage?ckSize=6")
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to fetch from server!");
            }
            return response.blob()
        })
        .then((blob => {
            console.log("startTime:" + startTime)
            console.log("endTime:" + Date.now())
            downloadSpeed.value = blob.size / 1024 / (Date.now() - startTime) * 1000
            console.log(downloadSpeed.value)
        }))*/
    const response = await fetch("backend/garbage?ckSize=4");
    
    if(!response.ok) {
        downloadSpeed.value = 0;
        return;
    }
    
    if (!response.body) {
        downloadSpeed.value = 0;
        return;
    }
    
    const reader = response.body.getReader();
    let totalSize = 0;
    const startTime = Date.now()
    let endTime = 0;

    const processData = (result: ReadableStreamReadResult<Uint8Array>): void => {
        if (result.done) {
            endTime = Date.now();
            downloadSpeed.value = totalSize / 1024 / (endTime - startTime) * 1000;
            return;
        }
        // 读取下一个文件片段，重复处理步骤
        const value = result.value; // Uint8Array
        const length = value.length;
        totalSize += length
        reader.read().then(processData);
    };
    reader.read().then(processData);
}

async function testUploadSpeed() {

    const fileSizeInBytes = 1024 * 1024; // 1MB
    const buffer = new ArrayBuffer(fileSizeInBytes);
    const dataView = new DataView(buffer);

    for (let i = 0; i < fileSizeInBytes; i++) {
        dataView.setUint8(i, i % 256);
    }
    const startTime = Date.now();
    fetch("backend/empty", {
        method: "POST",
        body: dataView
    })
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to fetch from server!");
            }
        })
        .then(() => {
            uploadSpeed.value = fileSizeInBytes / 1024 / (Date.now() - startTime) * 1000
        })

    /*const response = await fetch("backend/empty", {
        method: "POST",
        body: dataView
    })
    const writer = response.body.getWriter();
    let totalSize = 0;
    const startTime = Date.now()
    let endTime = 0;
    if(!response.ok) {
        uploadSpeed.value = 0;
        return;
    }*/

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
