const { spawn, spawnSync } = require("child_process");
const path = require("path");

const projectDir = path.resolve(__dirname, "..");

function createDesktopDevRunner({
  createViteServer = async (options) => (await import("vite")).createServer(options),
  spawnProcess = spawn,
  spawnSyncProcess = spawnSync,
  electronPath,
  runtime = process,
  logger = console,
} = {}) {
  let vite;
  let desktop;
  let desktopStopRequested = false;
  let stopping = false;
  let completion;

  function killDesktop() {
    if (desktopStopRequested || !desktop?.pid || desktop.exitCode != null || desktop.signalCode != null) return;
    desktopStopRequested = true;
    if (runtime.platform === "win32") {
      spawnSyncProcess("taskkill.exe", ["/PID", String(desktop.pid), "/T", "/F"], {
        windowsHide: true,
      });
    } else {
      desktop.kill("SIGTERM");
    }
  }

  function finish(code, error) {
    if (stopping) return completion;
    stopping = true;
    completion = (async () => {
      if (error) logger.error(error);
      killDesktop();
      try {
        await vite?.close();
      } catch (closeError) {
        logger.error(closeError);
        code = 1;
      }
      runtime.exit(code);
    })();
    return completion;
  }

  async function run() {
    runtime.once("SIGINT", () => void finish(130));
    runtime.once("SIGTERM", () => void finish(143));
    runtime.once("exit", killDesktop);
    try {
      if (!runtime.env.npm_execpath)
        throw new Error("桌面开发模式必须通过 npm run desktop:dev 启动");

      // Vite binds its own available port (incrementing if 5173 is occupied).
      // Never probe 5173: its listener may belong to an older checkout.
      vite = await createViteServer({
        root: projectDir,
        server: { host: "127.0.0.1", port: 5173, strictPort: false },
      });
      if (stopping) {
        await vite.close();
        return;
      }
      await vite.listen();
      if (stopping) return;
      const address = vite.httpServer?.address();
      if (!address || typeof address === "string" || !address.port)
        throw new Error("桌面开发服务未取得有效监听端口");
      vite.httpServer.once("error", (error) => void finish(1, error));

      desktop = spawnProcess(electronPath || require("electron"), ["."], {
        cwd: projectDir,
        stdio: "inherit",
        env: {
          ...runtime.env,
          TOOLBOX_DEV_URL: `http://127.0.0.1:${address.port}`,
          TOOLBOX_PROJECT_ROOT: projectDir,
        },
        windowsHide: false,
      });
      desktop.once("error", (error) => void finish(1, error));
      desktop.once("exit", (code) => void finish(code ?? 1));
    } catch (error) {
      await finish(1, error);
    }
  }

  return { run, stop: () => finish(0) };
}

module.exports = { createDesktopDevRunner };

if (require.main === module) void createDesktopDevRunner().run();
