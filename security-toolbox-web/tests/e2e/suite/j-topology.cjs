/*
 * 阶段 J：资产拓扑（全部项目、多中心与项目隔离）
 *
 * 本阶段只通过页面 UI 选择项目并读取可见节点，不直接请求 API，也不写入
 * 业务数据。纯函数边界（IPv6 URL、同 URL 合并优先级）由同目录的
 * verify-topology-contract.cjs 覆盖。
 */
const assert = require("node:assert/strict");
const { runContractChecks } = require("../verify-topology-contract.cjs");
const {
  sleep,
  settle,
  navigate,
  dismissStrayModal,
} = require("../lib/ui.cjs");

function compact(text) {
  return String(text || "").replace(/\s+/g, " ").trim();
}

async function pickerOptions(page) {
  const picker = page.locator(".project-picker").first();
  await picker.waitFor({ state: "visible", timeout: 15000 });
  const trigger = picker.locator(".el-select__wrapper").first();
  if (await trigger.count()) await trigger.click();
  else await picker.click();
  await sleep(350);
  const dropdown = page.locator(".el-select-dropdown:visible").last();
  await dropdown.waitFor({ state: "visible", timeout: 8000 });
  const items = dropdown.locator("li.el-select-dropdown__item");
  await items.first().waitFor({ state: "visible", timeout: 8000 });
  const texts = (await items.allTextContents()).map(compact);
  return { picker, dropdown, items, texts };
}

async function closePicker(page) {
  await page.keyboard.press("Escape").catch(() => {});
  await sleep(250);
}

async function chooseProject(page, itemIndex) {
  const { dropdown, items, texts } = await pickerOptions(page);
  const indexes = texts
    .map((text, index) => ({ text, index }))
    .filter(({ text }) => text && !/^全部项目(?:总览)?$/.test(text));
  const selected = indexes[itemIndex];
  if (!selected) {
    await closePicker(page);
    throw new Error(`项目下拉项索引越界: ${itemIndex}，实际项目数=${indexes.length}`);
  }
  await items.nth(selected.index).click();
  await waitTopologyLoaded(page);
  return selected.text;
}

async function chooseAllProjects(page) {
  const { items, texts } = await pickerOptions(page);
  const index = texts.findIndex((text) => /^全部项目(?:总览)?$/.test(text));
  if (index < 0) {
    await closePicker(page);
    throw new Error(`项目下拉中缺少「全部项目」：${texts.join(" / ")}`);
  }
  await items.nth(index).click();
  await waitTopologyLoaded(page);
}

async function waitTopologyLoaded(page, timeout = 30000) {
  const deadline = Date.now() + timeout;
  const loadingOverlay = page.locator(".topology-state-overlay", { hasText: /正在加载资产/ }).first();
  while (Date.now() < deadline) {
    if (!(await loadingOverlay.isVisible().catch(() => false))) {
      await sleep(450);
      return;
    }
    await sleep(250);
  }
  throw new Error("资产拓扑加载遮罩在限定时间内未消失");
}

/**
 * 等待拓扑页最终呈现出项目选择器或无项目空状态。
 * 项目列表为空时，AssetsTopology.vue 不挂载 AssetTopology 子组件，
 * 因而不会出现加载遮罩/项目下拉；只等待遮罩会把真实空状态误判为
 * 页面未加载完成。
 */
async function waitTopologySurface(page, timeout = 15000) {
  const deadline = Date.now() + timeout;
  const picker = page.locator(".project-picker").first();
  const emptyPrompt = page.locator(".empty-project-prompt").first();
  while (Date.now() < deadline) {
    if (await emptyPrompt.isVisible().catch(() => false)) return "empty";
    if (await picker.isVisible().catch(() => false)) return "picker";
    await sleep(200);
  }
  throw new Error("资产拓扑页未呈现项目选择器或无项目空状态");
}

async function selectedProjectText(page) {
  const selected = page.locator(
    ".project-picker .el-select__selected-item, .project-picker .el-select__placeholder",
  ).first();
  const text = compact(await selected.textContent().catch(() => ""));
  if (text) return text;
  return compact(await page.locator(".project-picker").first().textContent().catch(() => ""));
}

async function visibleCardLabels(page) {
  const cards = page.locator(".node-card-group");
  const labels = [];
  for (let i = 0; i < await cards.count(); i++) {
    const label = compact(await cards.nth(i).getAttribute("aria-label"));
    if (label) labels.push(label);
  }
  return labels;
}

async function visibleHubTitles(page) {
  const titles = page.locator(".topology-hub-node title");
  return (await titles.allTextContents()).map(compact).filter(Boolean);
}

function countBy(values) {
  const counts = new Map();
  for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
  return counts;
}

function mapDiff(expected, actual) {
  const left = countBy(expected);
  const right = countBy(actual);
  const keys = new Set([...left.keys(), ...right.keys()]);
  const diff = [];
  for (const key of keys) {
    if ((left.get(key) || 0) !== (right.get(key) || 0)) {
      diff.push(`${key}: ${left.get(key) || 0} != ${right.get(key) || 0}`);
    }
  }
  return diff;
}

async function run(page, H, ctx) {
  H.phase("阶段 J — 资产拓扑全部项目与隔离回归");

  await H.run("J-00", "拓扑纯函数契约检查通过", async () => {
    const cases = runContractChecks();
    return `纯函数契约 ${cases.length} 项通过`;
  }, { page });

  await H.run("J-01", "资产拓扑默认选择「全部项目」并提供该选项", async () => {
    await navigate(page, "资产拓扑");
    await page.locator(".assets-topology-page").waitFor({ state: "visible", timeout: 15000 });
    await waitTopologyLoaded(page);
    const surface = await waitTopologySurface(page);
    if (surface === "empty") {
      const emptyText = compact(await page.locator(".empty-project-prompt").first().textContent().catch(() => ""));
      if (!/(暂无评估项目|项目列表暂时不可用)/.test(emptyText)) {
        throw new Error(`无项目空状态文案异常：${emptyText || "空"}`);
      }
      ctx.topologyProjectOptions = [];
      ctx.topologyNoProjects = true;
      return `无项目空状态：${emptyText}`;
    }
    ctx.topologyNoProjects = false;
    const selected = await selectedProjectText(page);
    if (!/^全部项目(?:总览)?$/.test(selected)) {
      throw new Error(`默认项目不是全部项目，实际选择=${selected || "空"}`);
    }
    const { texts } = await pickerOptions(page);
    await closePicker(page);
    if (!texts.some((text) => /^全部项目(?:总览)?$/.test(text))) {
      throw new Error(`项目下拉缺少全部项目选项，实际=${texts.join(" / ")}`);
    }
    ctx.topologyProjectOptions = texts
      .filter((text) => text && !/^全部项目(?:总览)?$/.test(text));
    return `默认=${selected}，项目选项 ${ctx.topologyProjectOptions.length} 个`;
  }, { page });

  await H.run("J-02", "全部项目模式按项目渲染独立中心节点", async () => {
    const projectNames = ctx.topologyProjectOptions || [];
    if (ctx.topologyNoProjects) {
      const emptyText = compact(await page.locator(".empty-project-prompt").first().textContent().catch(() => ""));
      if (!(await page.locator(".empty-project-prompt").first().isVisible().catch(() => false))) {
        throw new Error("无项目时应显示项目空状态，但当前空状态不可见");
      }
      return `无项目时显示项目空状态：${emptyText}`;
    }
    const labels = await visibleCardLabels(page);
    if (!labels.length) {
      const emptyAssetOverlay = page.locator(".topology-state-overlay", { hasText: /暂无资产节点/ }).first();
      if (!(await emptyAssetOverlay.isVisible().catch(() => false))) {
        throw new Error("项目存在但无资产时应显示「暂无资产节点」空状态");
      }
      return "项目存在但当前无资产节点，已显示空状态";
    }
    const hubs = await visibleHubTitles(page);
    const meta = compact(await page.locator(".toolbar-meta-group").textContent().catch(() => ""));
    if (hubs.length !== projectNames.length) {
      throw new Error(`中心节点数与项目数不一致：项目=${projectNames.length}，中心=${hubs.length}（${hubs.join(" / ")}）`);
    }
    const missing = projectNames.filter((name) => !hubs.some((title) => title === name));
    if (missing.length) throw new Error(`中心节点缺少项目：${missing.join("、")}`);
    if (!meta.includes(`${projectNames.length} 个项目`)) {
      throw new Error(`顶部项目统计异常：期望包含「${projectNames.length} 个项目」，实际=${meta}`);
    }
    return `项目中心 ${hubs.length} 个：${hubs.join(" / ")}`;
  }, { page, shotOnPass: true });

  await H.run("J-03", "全部项目与逐项目视图保持资产及同 URL 隔离", async () => {
    const projectNames = ctx.topologyProjectOptions || [];
    if (ctx.topologyNoProjects || projectNames.length === 0) return "无项目数据，已验证项目空状态";

    await chooseAllProjects(page);
    const allLabels = await visibleCardLabels(page);
    const perProject = [];
    for (let index = 0; index < projectNames.length; index++) {
      const selected = await chooseProject(page, index);
      const selectedText = await selectedProjectText(page);
      if (selectedText !== selected) {
        throw new Error(`切换项目后选择器文本异常：期望=${selected}，实际=${selectedText}`);
      }
      const labels = await visibleCardLabels(page);
      if (!labels.length) {
        const emptyAssetOverlay = page.locator(".topology-state-overlay", { hasText: /暂无资产节点/ }).first();
        if (!(await emptyAssetOverlay.isVisible().catch(() => false))) {
          throw new Error(`项目 ${selected} 无资产时未显示「暂无资产节点」空状态`);
        }
        perProject.push({ name: selected, labels });
        continue;
      }
      const hubs = await visibleHubTitles(page);
      if (hubs.length !== 1) {
        throw new Error(`单项目模式应只有 1 个中心，项目=${selected}，实际=${hubs.length}`);
      }
      perProject.push({ name: selected, labels });
    }

    const flattened = perProject.flatMap((item) => item.labels);
    const diff = mapDiff(flattened, allLabels);
    if (diff.length) {
      throw new Error(`全部项目节点与各项目节点总和不一致（同 URL 也必须保留项目隔离）：${diff.slice(0, 8).join("；")}`);
    }

    const projectOccurrences = new Map();
    for (const project of perProject) {
      for (const label of new Set(project.labels)) {
        const entry = projectOccurrences.get(label) || [];
        entry.push(project.name);
        projectOccurrences.set(label, entry);
      }
    }
    const shared = [...projectOccurrences.entries()].filter(([, owners]) => owners.length > 1);
    await chooseAllProjects(page);
    return shared.length
      ? `校验 ${flattened.length} 个节点；发现 ${shared.length} 个跨项目同 URL，均保留为独立节点`
      : `校验 ${flattened.length} 个节点；当前夹具没有跨项目同 URL，已完成逐项目总和校验`;
  }, { page, shotOnPass: true });

  if (ctx.topologyNoProjects || !(ctx.topologyProjectOptions || []).length) {
    H.skip("J-04", "IPv6 资产在拓扑节点中保留完整主机字面量", "当前项目夹具没有 IPv6 资产");
  } else {
    let ipv6Labels = [];
    try {
      await chooseAllProjects(page);
      const labels = await visibleCardLabels(page);
      ipv6Labels = labels.filter(
        (label) => /\[[0-9a-f:]+\]/i.test(label) || /(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]+/i.test(label),
      );
    } catch (error) {
      await H.run("J-04", "IPv6 资产在拓扑节点中保留完整主机字面量", async () => {
        throw error;
      }, { page });
    }
    if (!ipv6Labels.length) {
      H.skip("J-04", "IPv6 资产在拓扑节点中保留完整主机字面量", "当前项目夹具没有 IPv6 资产");
    } else {
      await H.run("J-04", "IPv6 资产在拓扑节点中保留完整主机字面量", async () => {
        for (const label of ipv6Labels) {
          const candidate = /^https?:\/\//i.test(label) ? label : `http://${label}`;
          let parsed;
          try { parsed = new URL(candidate); } catch (error) {
            throw new Error(`IPv6 节点 URL 无法解析：${label}（${error.message}）`);
          }
          const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
          if ((hostname.match(/:/g) || []).length < 2) {
            throw new Error(`IPv6 节点疑似被冒号截断：${label}`);
          }
        }
        return `已验证 ${ipv6Labels.length} 个 IPv6 节点：${ipv6Labels.join("、")}`;
      }, { page });
    }
  }

  await dismissStrayModal(page);
  await settle(page, 300);
  return true;
}

module.exports = { run };
