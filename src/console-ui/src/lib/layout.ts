import type { Layout, LayoutItem, ResponsiveLayouts as Layouts } from "react-grid-layout";

export const DASHBOARD_LAYOUT_KEY = "sgw.dashboard.layout.v1";

export type PanelId =
  | "readiness"
  | "approvals"
  | "credentials"
  | "usageFlow"
  | "policy"
  | "agents"
  | "activity";

export const panelIds: PanelId[] = [
  "readiness",
  "approvals",
  "credentials",
  "usageFlow",
  "policy",
  "agents",
  "activity"
];

export const defaultLayouts: Layouts = {
  lg: [
    { i: "readiness", x: 0, y: 0, w: 3, h: 3, minW: 3, minH: 3 },
    { i: "approvals", x: 3, y: 0, w: 3, h: 3, minW: 3, minH: 3 },
    { i: "credentials", x: 6, y: 0, w: 3, h: 3, minW: 3, minH: 3 },
    { i: "policy", x: 9, y: 0, w: 3, h: 3, minW: 3, minH: 3 },
    { i: "usageFlow", x: 0, y: 3, w: 6, h: 7, minW: 4, minH: 6 },
    { i: "activity", x: 6, y: 3, w: 6, h: 7, minW: 4, minH: 4 },
    { i: "agents", x: 0, y: 10, w: 12, h: 4, minW: 4, minH: 3 }
  ],
  md: [
    { i: "readiness", x: 0, y: 0, w: 4, h: 3, minW: 3, minH: 3 },
    { i: "approvals", x: 4, y: 0, w: 4, h: 3, minW: 3, minH: 3 },
    { i: "credentials", x: 0, y: 3, w: 4, h: 3, minW: 3, minH: 3 },
    { i: "policy", x: 4, y: 3, w: 4, h: 3, minW: 3, minH: 3 },
    { i: "usageFlow", x: 0, y: 6, w: 8, h: 7, minW: 4, minH: 6 },
    { i: "activity", x: 0, y: 13, w: 8, h: 6, minW: 4, minH: 4 },
    { i: "agents", x: 0, y: 19, w: 8, h: 4, minW: 4, minH: 3 }
  ],
  sm: panelIds.map((id, index) => ({ i: id, x: 0, y: index * 4, w: 1, h: id === "usageFlow" ? 7 : 4, minW: 1, minH: id === "usageFlow" ? 6 : 3 }))
};

export function readSavedLayouts(): Layouts {
  try {
    const raw = localStorage.getItem(DASHBOARD_LAYOUT_KEY);
    if (!raw) return defaultLayouts;
    return normalizeLayouts(JSON.parse(raw) as Layouts);
  } catch {
    return defaultLayouts;
  }
}

export function saveLayouts(layouts: Layouts): void {
  localStorage.setItem(DASHBOARD_LAYOUT_KEY, JSON.stringify(normalizeLayouts(layouts)));
}

export function resetLayouts(): Layouts {
  localStorage.removeItem(DASHBOARD_LAYOUT_KEY);
  return defaultLayouts;
}

export function normalizeLayouts(input: Layouts): Layouts {
  const out: Layouts = {};
  for (const breakpoint of ["lg", "md", "sm"]) {
    const base = defaultLayouts[breakpoint] || defaultLayouts.lg;
    const current = Array.isArray(input?.[breakpoint]) ? input[breakpoint] : [];
    out[breakpoint] = normalizeOne(current, base || []);
  }
  return out;
}

function normalizeOne(current: Layout, base: Layout): LayoutItem[] {
  const byId = new Map(current.filter((item) => panelIds.includes(item.i as PanelId)).map((item) => [item.i, item]));
  const result: LayoutItem[] = [];
  for (const fallback of base) {
    const saved = byId.get(fallback.i);
    if (!saved) {
      result.push({ ...fallback });
      continue;
    }
    result.push({
      ...fallback,
      ...saved,
      minW: fallback.minW,
      minH: fallback.minH,
      i: fallback.i
    });
  }
  return result;
}
