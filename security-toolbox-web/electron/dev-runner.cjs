const { spawn, spawnSync } = require("child_process");
const net = require("net");
const path = require("path");

const projectDir = path.resolve(__dirname, "..");
const electron = require("electron");
let vite;
let desktop;
let stopping = false;

function waitForPort(port, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const check = () => {
      const socket = net.connect(port, "127.0.0.1");
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() >= deadline)
          reject(new Error(`端口 ${port} 未在规定时间内就绪`));
        else setTimeout(check, 300);
      });
    };
    check();
  });
}

function killTree(child) {
  if (!child || !child.pid) return;
  if (process.platform === "win32")
    spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
      windowsHide: true,
    });
  else child.kill("SIGTERM");
}

async function run() {
  const npmCli = process.env.npm_execpath;
  if (!npmCli) throw new Error("桌面开发模式必须通过 npm run desktop:dev 启动");
  vite = spawn(
    process.execPath,
    [npmCli, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"],
    {
      cwd: projectDir,
      stdio: "inherit",
      windowsHide: true,
    },
  );
  await waitForPort(5173);
  desktop = spawn(electron, ["."], {
    cwd: projectDir,
    stdio: "inherit",
    env: { ...process.env, TOOLBOX_DEV_URL: "http://127.0.0.1:5173" },
    windowsHide: false,
  });
  desktop.once("exit", (code) => {
    stopping = true;
    killTree(vite);
    process.exit(code || 0);
  });
}

process.on("SIGINT", () => {
  if (!stopping) {
    killTree(desktop);
    killTree(vite);
  }
});
process.on("exit", () => {
  if (!stopping) {
    killTree(desktop);
    killTree(vite);
  }
});
run().catch((error) => {
  console.error(error);
  killTree(vite);
  process.exit(1);
});
