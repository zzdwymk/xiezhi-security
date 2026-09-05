const { parentPort, workerData } = require("worker_threads");
const AdmZip = require("adm-zip");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  UserFacingError,
  diagnosticError,
  publicErrorMessage,
} = require("./public-error.cjs");

const WORKER_FAILURE_MESSAGE = "后台安装任务失败，请稍后重试";

function report(stage, progress, extra = {}) {
  parentPort.postMessage({ type: "progress", stage, progress, ...extra });
}

function assertRegularFile(filePath, maxBytes) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink())
    throw new UserFacingError("待处理的下载文件类型异常");
  if (stat.size < 1 || stat.size > maxBytes)
    throw new UserFacingError("下载文件超过安全大小限制");
  return stat.size;
}

async function verifySha256(
  filePath,
  expectedSha256,
  maxBytes,
  stage,
  progressStart,
  progressEnd,
) {
  const totalBytes = assertRegularFile(filePath, maxBytes);
  const hash = crypto.createHash("sha256");
  let processedBytes = 0;
  await new Promise((resolve, reject) => {
    const input = fs.createReadStream(filePath, { highWaterMark: 1024 * 1024 });
    input.on("data", (chunk) => {
      hash.update(chunk);
      processedBytes += chunk.length;
      const fraction = totalBytes > 0 ? processedBytes / totalBytes : 0;
      report(stage, progressStart + (progressEnd - progressStart) * fraction, {
        processedBytes,
        totalBytes,
      });
    });
    input.on("end", resolve);
    input.on("error", reject);
  });
  const digest = hash.digest("hex");
  if (expectedSha256 && digest !== expectedSha256) {
    throw new UserFacingError("安装包 SHA-256 校验失败，已拒绝安装");
  }
  return { totalBytes, digest };
}

function safeArchiveEntryName(entryName) {
  const normalized = String(entryName || "").replace(/\\/g, "/");
  if (!normalized || normalized.includes("\0") || normalized.startsWith("/"))
    return undefined;
  const parts = normalized.split("/");
  if (parts.includes("..") || parts.some((part) => !part)) return undefined;
  return { normalized, parts };
}

async function stageExecutableBinary(payload) {
  const {
    binaryPath,
    expectedSha256,
    expectedSize,
    maxBinaryBytes,
    targetPath,
    maxExecutableBytes,
  } = payload;
  const binaryHash = await verifySha256(
    binaryPath,
    expectedSha256,
    maxBinaryBytes,
    expectedSha256 ? "正在校验安装包 SHA-256" : "正在计算安装包 SHA-256",
    0,
    0.7,
  );
  if (expectedSize > 0 && binaryHash.totalBytes !== expectedSize) {
    throw new UserFacingError("安装包长度与官方发布记录不一致");
  }
  report("正在校验工具程序", 0.8);
  const data = fs.readFileSync(binaryPath);
  if (data.length < 1 || data.length > maxExecutableBytes) {
    throw new UserFacingError("下载的安装包大小异常");
  }
  if (data[0] !== 0x4d || data[1] !== 0x5a) {
    throw new UserFacingError("下载的安装包不是有效的可执行文件");
  }
  fs.writeFileSync(targetPath, data, { flag: "wx" });
  report("工具程序安装完成", 1, { processedFiles: 1, totalFiles: 1 });
  return {
    binaryBytes: data.length,
    binarySha256: binaryHash.digest,
    executableBytes: data.length,
    archiveSha256: binaryHash.digest,
  };
}

async function extractExecutable(payload) {
  const {
    archivePath,
    expectedSha256,
    expectedSize,
    maxArchiveBytes,
    executableName,
    targetPath,
    maxExecutableBytes,
  } = payload;
  const archiveHash = await verifySha256(
    archivePath,
    expectedSha256,
    maxArchiveBytes,
    expectedSha256 ? "正在校验安装包 SHA-256" : "正在计算安装包 SHA-256",
    0,
    0.7,
  );
  if (expectedSize > 0 && archiveHash.totalBytes !== expectedSize) {
    throw new UserFacingError("安装包长度与官方发布记录不一致");
  }

  report("正在读取安装包目录", 0.74);
  const zip = new AdmZip(archivePath);
  const matches = zip.getEntries().filter((entry) => {
    if (entry.isDirectory) return false;
    const safeName = safeArchiveEntryName(entry.entryName);
    return (
      safeName &&
      path.posix.basename(safeName.normalized).toLowerCase() ===
        executableName.toLowerCase()
    );
  });
  if (matches.length !== 1)
    throw new UserFacingError("安装包中未找到唯一的受控可执行文件");

  const entry = matches[0];
  const uncompressedSize = Number(entry.header.size);
  const compressedSize = Number(entry.header.compressedSize);
  if (
    !Number.isSafeInteger(uncompressedSize) ||
    uncompressedSize < 1 ||
    uncompressedSize > maxExecutableBytes ||
    !Number.isSafeInteger(compressedSize) ||
    compressedSize < 1 ||
    uncompressedSize / compressedSize > 20
  ) {
    throw new UserFacingError("解压后的文件大小或压缩比异常");
  }
  report("正在解压工具程序", 0.8);
  const executableData = entry.getData();
  if (
    executableData.length !== uncompressedSize ||
    executableData.length > maxExecutableBytes ||
    executableData[0] !== 0x4d ||
    executableData[1] !== 0x5a
  ) {
    throw new UserFacingError("解压后的可执行文件校验失败");
  }
  fs.writeFileSync(targetPath, executableData, { flag: "wx" });
  report("工具程序解压完成", 1, { processedFiles: 1, totalFiles: 1 });
  return {
    archiveBytes: archiveHash.totalBytes,
    archiveSha256: archiveHash.digest,
    executableBytes: executableData.length,
  };
}

async function extractTemplates(payload) {
  const {
    archivePath,
    expectedSha256,
    maxArchiveBytes,
    stagingDir,
    maxFiles,
    maxExtractedBytes,
    sourceMetadata,
  } = payload;
  await verifySha256(
    archivePath,
    expectedSha256,
    maxArchiveBytes,
    "正在校验 Nuclei 模板 SHA-256",
    0,
    0.18,
  );

  report("正在读取 Nuclei 模板目录", 0.2);
  const zip = new AdmZip(archivePath);
  const extraFiles = new Set([
    ".nuclei-ignore",
    "cves.json",
    "TEMPLATES-STATS.json",
    "LICENSE.md",
    "README.md",
  ]);
  const entries = zip.getEntries().filter((entry) => {
    if (entry.isDirectory) return false;
    const safeName = safeArchiveEntryName(entry.entryName);
    if (!safeName || safeName.parts.length < 2) return false;
    const relativeParts = safeName.parts.slice(1);
    const relative = relativeParts.join("/");
    return /\.ya?ml$/i.test(relative) || extraFiles.has(relative);
  });
  if (!entries.length || entries.length > maxFiles)
    throw new UserFacingError("Nuclei 模板文件数量异常");

  let extractedFiles = 0;
  let extractedBytes = 0;
  let yamlFiles = 0;
  for (const entry of entries) {
    const safeName = safeArchiveEntryName(entry.entryName);
    const relativeParts = safeName.parts.slice(1);
    const relative = relativeParts.join("/");
    const size = Number(entry.header.size);
    if (!Number.isSafeInteger(size) || size < 0)
      throw new UserFacingError("Nuclei 模板文件大小异常");
    extractedFiles += 1;
    extractedBytes += size;
    if (extractedFiles > maxFiles || extractedBytes > maxExtractedBytes) {
      throw new UserFacingError("Nuclei 模板解压数量或大小超过安全限制");
    }
    const target = path.join(stagingDir, ...relativeParts);
    const relativeTarget = path.relative(
      path.resolve(stagingDir),
      path.resolve(target),
    );
    if (relativeTarget.startsWith("..") || path.isAbsolute(relativeTarget)) {
      throw new UserFacingError("Nuclei 模板路径超出安装目录");
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, entry.getData(), { flag: "wx" });
    if (/\.ya?ml$/i.test(relative)) yamlFiles += 1;

    if (extractedFiles === entries.length || extractedFiles % 100 === 0) {
      report(
        `正在解压 Nuclei 模板（${extractedFiles}/${entries.length}）`,
        0.22 + 0.76 * (extractedFiles / entries.length),
        {
          processedFiles: extractedFiles,
          totalFiles: entries.length,
          processedBytes: extractedBytes,
        },
      );
    }
  }
  if (!yamlFiles) throw new UserFacingError("官方模板压缩包中未找到 YAML 模板");
  fs.writeFileSync(
    path.join(stagingDir, ".toolbox-source.json"),
    JSON.stringify(sourceMetadata, null, 2),
    { flag: "wx" },
  );
  report("Nuclei 模板解压完成", 1, {
    processedFiles: extractedFiles,
    totalFiles: entries.length,
    processedBytes: extractedBytes,
  });
  return { extractedFiles, extractedBytes, yamlFiles };
}

async function extractScannerPocs(payload) {
  const {
    archivePath,
    maxArchiveBytes,
    stagingDir,
    maxFiles,
    maxExtractedBytes,
    sourceMetadata,
    sourceSubdirectory = "pocs",
    scannerLabel = "扫描器",
  } = payload;
  const archiveHash = await verifySha256(
    archivePath,
    "",
    maxArchiveBytes,
    `正在计算 ${scannerLabel} PoC 快照 SHA-256`,
    0,
    0.18,
  );
  report(`正在读取 ${scannerLabel} PoC 目录`, 0.2);
  const zip = new AdmZip(archivePath);
  const prefix = String(sourceSubdirectory || "pocs")
    .replace(/\\/g, "/")
    .replace(/^\/+|\/+$/g, "");
  const prefixParts = prefix.split("/");
  const entries = zip.getEntries().filter((entry) => {
    if (entry.isDirectory) return false;
    const safeName = safeArchiveEntryName(entry.entryName);
    if (!safeName || safeName.parts.length < prefixParts.length + 2)
      return false;
    const repositoryRelative = safeName.parts.slice(1).join("/");
    return (
      repositoryRelative.startsWith(prefix + "/") &&
      /\.ya?ml$/i.test(repositoryRelative)
    );
  });
  if (!entries.length || entries.length > maxFiles)
    throw new UserFacingError(`${scannerLabel} PoC 文件数量异常`);

  let extractedFiles = 0;
  let extractedBytes = 0;
  for (const entry of entries) {
    const safeName = safeArchiveEntryName(entry.entryName);
    const relativeParts = safeName.parts.slice(1 + prefixParts.length);
    const size = Number(entry.header.size);
    if (!relativeParts.length || !Number.isSafeInteger(size) || size < 1)
      throw new UserFacingError(`${scannerLabel} PoC 文件路径或大小异常`);
    extractedFiles += 1;
    extractedBytes += size;
    if (extractedFiles > maxFiles || extractedBytes > maxExtractedBytes)
      throw new UserFacingError(`${scannerLabel} PoC 解压数量或大小超过安全限制`);
    const target = path.join(stagingDir, ...relativeParts);
    const relativeTarget = path.relative(
      path.resolve(stagingDir),
      path.resolve(target),
    );
    if (relativeTarget.startsWith("..") || path.isAbsolute(relativeTarget))
      throw new UserFacingError(`${scannerLabel} PoC 路径超出安装目录`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, entry.getData(), { flag: "wx" });
    if (extractedFiles === entries.length || extractedFiles % 100 === 0) {
      report(
        `正在解压 ${scannerLabel} PoC（${extractedFiles}/${entries.length}）`,
        0.22 + 0.76 * (extractedFiles / entries.length),
        {
          processedFiles: extractedFiles,
          totalFiles: entries.length,
          processedBytes: extractedBytes,
        },
      );
    }
  }
  fs.writeFileSync(
    path.join(stagingDir, ".toolbox-source.json"),
    JSON.stringify(
      {
        ...sourceMetadata,
        archiveSha256: archiveHash.digest,
        sourceSubdirectory: prefix,
      },
      null,
      2,
    ),
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
  report(`${scannerLabel} PoC 解压完成`, 1, {
    processedFiles: extractedFiles,
    totalFiles: entries.length,
    processedBytes: extractedBytes,
  });
  return {
    extractedFiles,
    extractedBytes,
    yamlFiles: extractedFiles,
    archiveSha256: archiveHash.digest,
  };
}

async function extractPortableTree(payload) {
  const {
    archivePath,
    expectedSha256,
    maxArchiveBytes,
    stagingDir,
    maxFiles,
    maxExtractedBytes,
    sourceMetadata,
    label = "便携工具",
  } = payload;
  const archiveHash = await verifySha256(
    archivePath,
    expectedSha256 || "",
    maxArchiveBytes,
    `正在校验 ${label} 安装包 SHA-256`,
    0,
    0.18,
  );
  report(`正在读取 ${label} 安装包目录`, 0.2);
  const zip = new AdmZip(archivePath);
  const entries = zip.getEntries().filter((entry) => {
    if (entry.isDirectory) return false;
    return Boolean(safeArchiveEntryName(entry.entryName));
  });
  if (!entries.length || entries.length > maxFiles) {
    throw new UserFacingError(`${label} 安装包文件数量异常`);
  }

  let extractedFiles = 0;
  let extractedBytes = 0;
  for (const entry of entries) {
    const safeName = safeArchiveEntryName(entry.entryName);
    if (!safeName) throw new UserFacingError(`${label} 安装包包含不安全路径`);
    const size = Number(entry.header.size);
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new UserFacingError(`${label} 安装包文件大小异常`);
    }
    extractedFiles += 1;
    extractedBytes += size;
    if (extractedFiles > maxFiles || extractedBytes > maxExtractedBytes) {
      throw new UserFacingError(`${label} 解压数量或大小超过安全限制`);
    }
    const target = path.join(stagingDir, ...safeName.parts);
    const relativeTarget = path.relative(
      path.resolve(stagingDir),
      path.resolve(target),
    );
    if (relativeTarget.startsWith("..") || path.isAbsolute(relativeTarget)) {
      throw new UserFacingError(`${label} 解压路径超出安装目录`);
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, entry.getData(), { flag: "wx" });
    if (extractedFiles === entries.length || extractedFiles % 200 === 0) {
      report(
        `正在解压 ${label}（${extractedFiles}/${entries.length}）`,
        0.22 + 0.76 * (extractedFiles / entries.length),
        {
          processedFiles: extractedFiles,
          totalFiles: entries.length,
          processedBytes: extractedBytes,
        },
      );
    }
  }
  fs.writeFileSync(
    path.join(stagingDir, ".toolbox-source.json"),
    JSON.stringify(
      { ...sourceMetadata, archiveSha256: archiveHash.digest },
      null,
      2,
    ),
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
  report(`${label} 解压完成`, 1, {
    processedFiles: extractedFiles,
    totalFiles: entries.length,
    processedBytes: extractedBytes,
  });
  return {
    extractedFiles,
    extractedBytes,
    archiveSha256: archiveHash.digest,
  };
}

async function run() {
  if (!parentPort || !workerData || typeof workerData !== "object") {
    throw new UserFacingError("后台安装任务参数无效");
  }
  if (workerData.task === "extract-executable")
    return extractExecutable(workerData.payload);
  if (workerData.task === "stage-executable-binary")
    return stageExecutableBinary(workerData.payload);
  if (workerData.task === "extract-templates")
    return extractTemplates(workerData.payload);
  if (workerData.task === "extract-scanner-pocs")
    return extractScannerPocs(workerData.payload);
  if (workerData.task === "extract-portable-tree")
    return extractPortableTree(workerData.payload);
  throw new UserFacingError("不支持的后台安装任务");
}

run().then(
  (result) => parentPort.postMessage({ type: "result", result }),
  (error) =>
    parentPort.postMessage({
      type: "error",
      message: publicErrorMessage(error, WORKER_FAILURE_MESSAGE),
      diagnostic: diagnosticError(error).slice(0, 4000),
    }),
);
