<script setup lang="ts">
import { ref } from "vue";
import { ElMessage } from "element-plus";
import { calculateCidr, type CidrInfo } from "../../utils/networkSecurity";
import { toErrorMessage } from "../../utils/errorMessage";

const input = ref("192.168.1.10/24");
const result = ref<CidrInfo>();

const fields: Array<[keyof CidrInfo, string]> = [
  ["address", "输入地址"],
  ["scope", "地址类型"],
  ["network", "网络地址"],
  ["broadcast", "广播地址"],
  ["netmask", "子网掩码"],
  ["wildcard", "通配符掩码"],
  ["firstHost", "首个可用地址"],
  ["lastHost", "最后可用地址"],
  ["addressCount", "地址总数"],
  ["usableHostCount", "可用主机数"],
  ["integer", "整数表示"],
  ["hexadecimal", "十六进制"],
  ["binary", "二进制"],
];

function calculate() {
  try {
    result.value = calculateCidr(input.value);
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "计算失败，请检查地址格式"));
  }
}

calculate();
</script>

<template>
  <div class="offline-tool-body network-calculator">
    <div class="offline-notice">
      仅做 IPv4/CIDR 数学计算，不发送探测包，也不会检查地址是否在线。
    </div>
    <div class="network-cidr-input">
      <label
        >IPv4 或 CIDR<el-input
          v-model="input"
          placeholder="例如 10.20.30.40/20"
          @keyup.enter="calculate"
      /></label>
      <el-button type="primary" @click="calculate">计算网段</el-button>
    </div>
    <div v-if="result" class="network-result-grid">
      <article
        v-for="[key, label] in fields"
        :key="key"
        :class="{ wide: key === 'binary' }"
      >
        <span>{{ label }}</span>
        <code>{{ result[key] }}</code>
      </article>
    </div>
    <div class="offline-notice network-prefix-note">
      /31 按点到点链路保留两个地址，/32
      表示单个主机；其他网段会扣除网络地址和广播地址。
    </div>
  </div>
</template>
