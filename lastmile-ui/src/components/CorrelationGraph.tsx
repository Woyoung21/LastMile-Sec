"use client";

import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from "react";

// @ts-expect-error -- d3-force ships without types in some installs; runtime module is present
import * as d3 from "d3-force";

import type { GraphData, GraphGroup, GraphLink, GraphNode } from "@/types/graph";
import type { ForceGraphMethods, NodeObject } from "react-force-graph-2d";

/** Optional flag for edges added only to stabilize layout (not real correlations). */
type SimLink = GraphLink & { __layoutOnly?: boolean };

const CYAN = "#00E5FF";
/** Vendor / framework hubs — indigo-violet (distinct from control gray + MITRE cyan, matches accent energy). */
const FRAMEWORK_FILL = "#818cf8";
const CONTROL_FILL = "#9ca3af";
const LINK_DIM = "rgba(255,255,255,0.15)";
const LINK_HI = "rgba(0, 229, 255, 0.82)";
const LINK_LAYOUT_ONLY = "rgba(255,255,255,0.06)";

type ForceGraph2DComponent = typeof import("react-force-graph-2d").default;

const GRAPH_NODE_REL_SIZE = 1;
const RADIUS_FW = 8;
const RADIUS_MITRE = 6;
const RADIUS_CTL = 4;

/**
 * Dense Neo4j-scale graphs: weak repulsion, tight vendor→control spokes only, longer
 * control→MITRE edges (using one short distance for *all* non-layout links pulled MITRE
 * toward every hub and stretched the layout — looked like unchanged “islands”).
 */
/** Weak many-body so loose / disconnected nodes are not shot away from the main mass. */
const DENSE_CHARGE_FRAMEWORK = -5;
const DENSE_CHARGE_CONTROL = -4;
const DENSE_CHARGE_MITRE = -5;
/** Framework (vendor) ↔ Control only */
const DENSE_LINK_VENDOR_CONTROL = 12;
/** Control ↔ MITRE (many edges — keep longer so techniques form a shared cloud, not tight rings) */
const DENSE_LINK_CONTROL_MITRE = 56;
/** Rare Framework ↔ MITRE (e.g. synthetic anchors) */
const DENSE_LINK_FRAMEWORK_MITRE = 48;
const DENSE_LINK_LAYOUT = 50;
const DENSE_CENTER_STRENGTH = 0.22;
const DENSE_BOUNDING_STRENGTH = 0.015;

function endpointGroup(
  end: unknown,
  idToGroup: Map<string, GraphGroup>,
): GraphGroup | undefined {
  if (end == null) return undefined;
  if (typeof end === "object" && "group" in (end as object)) {
    return (end as NodeObject & { group?: GraphGroup }).group;
  }
  return idToGroup.get(String(end));
}

/** Controls + MITRE linked to this vendor only (PROVIDES + MITIGATES), for drag-as-a-group. */
function buildVendorDragCluster(
  vendorId: string,
  idToGroup: Map<string, GraphGroup>,
  links: SimLink[],
): Set<string> {
  const controls = new Set<string>();
  for (const l of links) {
    if (l.__layoutOnly) continue;
    const s = String(l.source);
    const t = String(l.target);
    if (s === vendorId && idToGroup.get(t) === "Control") controls.add(t);
    if (t === vendorId && idToGroup.get(s) === "Control") controls.add(s);
  }
  const out = new Set<string>([vendorId, ...controls]);
  for (const l of links) {
    if (l.__layoutOnly) continue;
    const s = String(l.source);
    const t = String(l.target);
    if (controls.has(s) && idToGroup.get(t) === "MITRE") out.add(t);
    if (controls.has(t) && idToGroup.get(s) === "MITRE") out.add(s);
  }
  return out;
}

function nodeValForRadius(g: GraphGroup | undefined): number {
  if (g === "Framework") return RADIUS_FW * RADIUS_FW;
  if (g === "MITRE") return RADIUS_MITRE * RADIUS_MITRE;
  return RADIUS_CTL * RADIUS_CTL;
}

function forceBoundingBox(boxHalf: number, strength: number) {
  let nodes: NodeObject[] = [];
  const force = (alpha: number) => {
    const k = strength * alpha;
    for (const d of nodes) {
      const x = d.x ?? 0;
      const y = d.y ?? 0;
      const nd = d as NodeObject & { vx?: number; vy?: number };
      let dvx = 0;
      let dvy = 0;
      if (x < -boxHalf) dvx += (-boxHalf - x) * k;
      if (x > boxHalf) dvx += (boxHalf - x) * k;
      if (y < -boxHalf) dvy += (-boxHalf - y) * k;
      if (y > boxHalf) dvy += (boxHalf - y) * k;
      nd.vx = (nd.vx ?? 0) + dvx;
      nd.vy = (nd.vy ?? 0) + dvy;
    }
  };
  (force as unknown as { initialize: (ns: NodeObject[]) => void }).initialize = (
    ns: NodeObject[],
  ) => {
    nodes = ns;
  };
  return force;
}

function canonicalUndirectedEdgeKey(a: string, b: string): string {
  const s = String(a);
  const t = String(b);
  return s <= t ? `${s}\0${t}` : `${t}\0${s}`;
}

/**
 * MITRE nodes with no incident edge in the source data get soft anchors to frameworks and controls
 * so the link force pulls them into the main component instead of jittering as a disconnected clump.
 */
function buildSyntheticMitreAnchors(
  nodes: GraphNode[],
  originalLinks: GraphLink[],
): SimLink[] {
  const incident = new Set<string>();
  for (const l of originalLinks) {
    incident.add(String(l.source));
    incident.add(String(l.target));
  }

  const frameworkIds = nodes
    .filter((n) => n.group === "Framework")
    .map((n) => n.id)
    .sort();
  const controlIds = nodes
    .filter((n) => n.group === "Control")
    .map((n) => n.id)
    .sort();

  if (frameworkIds.length === 0) return [];

  const mitreOrphans = nodes
    .filter((n) => n.group === "MITRE" && !incident.has(n.id))
    .map((n) => n.id)
    .sort();

  const added: SimLink[] = [];
  for (let i = 0; i < mitreOrphans.length; i++) {
    const mitreId = mitreOrphans[i]!;
    const fw = frameworkIds[i % frameworkIds.length]!;
    added.push({
      source: mitreId,
      target: fw,
      __layoutOnly: true,
    });
    if (controlIds.length > 0) {
      const ctl = controlIds[(i * 7) % controlIds.length]!;
      added.push({
        source: mitreId,
        target: ctl,
        __layoutOnly: true,
      });
    }
  }
  return added;
}

function linkEndpointId(
  end: string | number | NodeObject | undefined,
): string | null {
  if (end == null) return null;
  if (typeof end === "object") return String((end as NodeObject).id ?? "");
  return String(end);
}

function linkKeyFromLinkObject(link: object): string | null {
  const l = link as { source?: unknown; target?: unknown };
  const s = linkEndpointId(l.source as NodeObject);
  const t = linkEndpointId(l.target as NodeObject);
  if (s == null || t == null) return null;
  return canonicalUndirectedEdgeKey(s, t);
}

function toGraphNode(n: NodeObject): GraphNode {
  return {
    id: String(n.id),
    group: n.group as GraphGroup,
    label: String(n.label ?? n.id),
    description: String(n.description ?? ""),
  };
}

export type CorrelationGraphHandle = {
  resetZoom: () => void;
};

export type CorrelationGraphProps = {
  data: GraphData;
  onNodeSelect: (node: GraphNode | null) => void;
  selectedId: string | null;
};

export const CorrelationGraph = forwardRef<
  CorrelationGraphHandle,
  CorrelationGraphProps
>(function CorrelationGraph({ data, onNodeSelect, selectedId }, ref) {
  const fgRef = useRef<ForceGraphMethods | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dims, setDims] = useState({ width: 400, height: 300 });
  const [hoverNode, setHoverNode] = useState<NodeObject | null>(null);
  const [Fg, setFg] = useState<ForceGraph2DComponent | null>(null);
  const flyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** When dragging a Framework (vendor) node, move its controls + MITRE together. */
  const vendorDragClusterRef = useRef<Set<string> | null>(null);
  /** Positions of every cluster node at drag start — rigid offset = vendor_delta from these. */
  const vendorDragStartRef = useRef<Map<string, { x: number; y: number }> | null>(
    null,
  );

  /** Neo4j-scale exports (thousands of nodes): faster settle, lighter links, milder charge. */
  const isDenseGraph = data.nodes.length >= 2000;

  useEffect(() => {
    let cancelled = false;
    import("react-force-graph-2d").then((m) => {
      if (!cancelled) setFg(() => m.default);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const clearFlyTimeout = useCallback(() => {
    if (flyTimeoutRef.current != null) {
      clearTimeout(flyTimeoutRef.current);
      flyTimeoutRef.current = null;
    }
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const ro = new ResizeObserver((entries) => {
      const cr = entries[0]?.contentRect;
      if (!cr) return;
      const w = Math.max(1, Math.floor(cr.width));
      const h = Math.max(1, Math.floor(cr.height));
      setDims((d) => (d.width === w && d.height === h ? d : { width: w, height: h }));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => () => clearFlyTimeout(), [clearFlyTimeout]);

  const { graphData, syntheticEdgeKeys } = useMemo(() => {
    const nodes = data.nodes.map((n) => ({ ...n }));
    const baseLinks = data.links.map((l) => ({ ...l }));
    const synthetic = buildSyntheticMitreAnchors(data.nodes, data.links);
    const keys = new Set<string>();
    for (const l of synthetic) {
      keys.add(canonicalUndirectedEdgeKey(l.source, l.target));
    }
    return {
      graphData: {
        nodes,
        links: [...baseLinks, ...synthetic.map((l) => ({ ...l }))],
      },
      syntheticEdgeKeys: keys,
    };
  }, [data]);

  const idToGroup = useMemo(() => {
    const m = new Map<string, GraphGroup>();
    for (const n of graphData.nodes) {
      m.set(String(n.id), n.group as GraphGroup);
    }
    return m;
  }, [graphData]);

  const idToNode = useMemo(() => {
    const m = new Map<string, NodeObject>();
    for (const n of graphData.nodes) {
      m.set(String(n.id), n as NodeObject);
    }
    return m;
  }, [graphData]);

  const onNodeDrag = useCallback(
    (node: NodeObject) => {
      const g = node.group as GraphGroup | undefined;
      if (g !== "Framework") return;

      if (!vendorDragClusterRef.current) {
        const cluster = buildVendorDragCluster(
          String(node.id),
          idToGroup,
          graphData.links as SimLink[],
        );
        vendorDragClusterRef.current = cluster;
        const starts = new Map<string, { x: number; y: number }>();
        for (const nid of cluster) {
          const n = idToNode.get(nid);
          if (n) starts.set(nid, { x: n.x ?? 0, y: n.y ?? 0 });
        }
        vendorDragStartRef.current = starts;
        for (const nid of cluster) {
          const n = idToNode.get(nid);
          if (!n) continue;
          const nd = n as NodeObject & { fx?: number; fy?: number };
          nd.fx = undefined;
          nd.fy = undefined;
        }
      }

      const cluster = vendorDragClusterRef.current;
      const starts = vendorDragStartRef.current;
      if (!cluster || !starts) return;

      const dragId = String(node.id);
      const v0 = starts.get(dragId);
      if (!v0) return;

      const totalDx = (node.x ?? 0) - v0.x;
      const totalDy = (node.y ?? 0) - v0.y;

      // Rigid move: same offset for vendor + controls + MITRE. Lock non-dragged nodes with
      // fx/fy so link/charge forces cannot pull them back; leave the vendor unfixed so the
      // graph's drag handler still drives it.
      for (const nid of cluster) {
        const s = starts.get(nid);
        const n = idToNode.get(nid);
        if (!s || !n) continue;
        const nx = s.x + totalDx;
        const ny = s.y + totalDy;
        n.x = nx;
        n.y = ny;
        const nd = n as NodeObject & {
          fx?: number;
          fy?: number;
          vx?: number;
          vy?: number;
        };
        nd.vx = 0;
        nd.vy = 0;
        if (nid === dragId) {
          nd.fx = undefined;
          nd.fy = undefined;
        } else {
          nd.fx = nx;
          nd.fy = ny;
        }
      }
    },
    [graphData, idToGroup, idToNode],
  );

  const onNodeDragEnd = useCallback(
    (node: NodeObject) => {
      const g = node.group as GraphGroup | undefined;
      const cluster = vendorDragClusterRef.current;
      vendorDragClusterRef.current = null;
      vendorDragStartRef.current = null;
      fgRef.current?.resumeAnimation();

      // Pin vendor + subtree at drop positions so link/center/charge cannot snap them back.
      if (g === "Framework" && cluster && cluster.size > 0) {
        for (const nid of cluster) {
          const n = idToNode.get(nid);
          if (!n) continue;
          const nd = n as NodeObject & { fx?: number; fy?: number; vx?: number; vy?: number };
          nd.fx = n.x;
          nd.fy = n.y;
          nd.vx = 0;
          nd.vy = 0;
        }
        // Stop cold — do not reheat, or physics immediately fights the new layout.
        return;
      }

      fgRef.current?.d3ReheatSimulation();
    },
    [idToNode],
  );

  // Apply D3 forces when the graph component is mounted and when data or viewport changes.
  // react-force-graph initializes its own simulation after mount; for dense graphs we re-apply
  // after short delays so our link/charge/center settings are not overwritten.
  useEffect(() => {
    if (!Fg) return;
    let cancelled = false;
    const deferredTimeouts: ReturnType<typeof setTimeout>[] = [];

    const applySimulationForces = () => {
      if (cancelled) return;
      const fg = fgRef.current;
      if (!fg) return;

      const centerForce = d3.forceCenter(0, 0);
      if (isDenseGraph) {
        centerForce.strength(DENSE_CENTER_STRENGTH);
      }
      fg.d3Force("center", centerForce as never);

      const boxHalf = isDenseGraph
        ? Math.max(560, Math.min(dims.width, dims.height) * 0.62)
        : Math.max(300, Math.min(dims.width, dims.height) * 0.42);
      const boundingStrength = isDenseGraph ? DENSE_BOUNDING_STRENGTH : 0.14;
      fg.d3Force("bounding", forceBoundingBox(boxHalf, boundingStrength) as never);

      const chargeForce = d3.forceManyBody().strength((node: NodeObject) => {
        const g = (node as NodeObject & { group?: GraphGroup }).group;
        if (isDenseGraph) {
          if (g === "Framework") return DENSE_CHARGE_FRAMEWORK;
          if (g === "MITRE") return DENSE_CHARGE_MITRE;
          return DENSE_CHARGE_CONTROL;
        }
        return g === "Framework" ? -1800 : -40;
      });
      fg.d3Force("charge", chargeForce as never);

      const linkForce = d3
        .forceLink([...(graphData.links as SimLink[])])
        .id((d: NodeObject) => String(d.id ?? ""))
        .distance((l: SimLink) => {
          if (l.__layoutOnly) {
            return isDenseGraph ? DENSE_LINK_LAYOUT : 72;
          }
          if (!isDenseGraph) {
            return 35;
          }
          const a = endpointGroup(l.source, idToGroup);
          const b = endpointGroup(l.target, idToGroup);
          const gs = new Set(
            [a, b].filter((x): x is GraphGroup => x != null),
          );
          if (gs.has("Framework") && gs.has("Control")) {
            return DENSE_LINK_VENDOR_CONTROL;
          }
          if (gs.has("Control") && gs.has("MITRE")) {
            return DENSE_LINK_CONTROL_MITRE;
          }
          if (gs.has("Framework") && gs.has("MITRE")) {
            return DENSE_LINK_FRAMEWORK_MITRE;
          }
          return DENSE_LINK_CONTROL_MITRE;
        });
      fg.d3Force("link", linkForce as never);

      // force-graph may register collide from node sizes — removes hard "bouncing" between clusters.
      fg.d3Force("collide", null);

      fg.d3ReheatSimulation?.();
    };

    const rafId = requestAnimationFrame(() => {
      applySimulationForces();
      if (isDenseGraph) {
        deferredTimeouts.push(
          setTimeout(() => applySimulationForces(), 0),
          setTimeout(() => applySimulationForces(), 200),
        );
      }
    });

    return () => {
      cancelled = true;
      cancelAnimationFrame(rafId);
      for (const t of deferredTimeouts) {
        clearTimeout(t);
      }
    };
  }, [Fg, graphData, dims.width, dims.height, isDenseGraph, idToGroup]);

  const focusId = hoverNode?.id ?? selectedId;

  const linkIsActive = useCallback(
    (link: object) => {
      const l = link as { source?: unknown; target?: unknown };
      const s = linkEndpointId(l.source as NodeObject);
      const t = linkEndpointId(l.target as NodeObject);
      if (focusId == null) return false;
      return s === focusId || t === focusId;
    },
    [focusId],
  );

  const linkColorCb = useCallback(
    (l: object) => {
      if (linkIsActive(l)) return LINK_HI;
      const k = linkKeyFromLinkObject(l);
      if (k && syntheticEdgeKeys.has(k)) return LINK_LAYOUT_ONLY;
      return LINK_DIM;
    },
    [linkIsActive, syntheticEdgeKeys],
  );

  const linkWidthCb = useCallback(
    (l: object) => {
      if (linkIsActive(l)) return 1.15;
      const k = linkKeyFromLinkObject(l);
      if (k && syntheticEdgeKeys.has(k)) return 0.32;
      return isDenseGraph ? 0.35 : 0.55;
    },
    [linkIsActive, syntheticEdgeKeys, isDenseGraph],
  );

  const resetZoom = useCallback(() => {
    clearFlyTimeout();
    fgRef.current?.zoomToFit(900, 120);
  }, [clearFlyTimeout]);

  useImperativeHandle(ref, () => ({ resetZoom }), [resetZoom]);

  const nodeColor = useCallback((n: NodeObject) => {
    const g = n.group as GraphGroup | undefined;
    if (g === "Control") return CONTROL_FILL;
    if (g === "Framework") return FRAMEWORK_FILL;
    return CYAN;
  }, []);

  const nodeVal = useCallback((n: NodeObject) => {
    return nodeValForRadius(n.group as GraphGroup | undefined);
  }, []);

  const paintNodeObject = useCallback(
    (node: NodeObject, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const g = node.group as GraphGroup | undefined;
      const id = String(node.id);
      const isHover = hoverNode && String(hoverNode.id) === id;
      const showLabel =
        g === "Framework" ||
        (g === "Control" && isHover) ||
        (g === "MITRE" && (isHover || selectedId === id));

      if (!showLabel) return;

      const label = String(node.label ?? node.id);
      const fontPx = Math.max(10 / globalScale, 3);
      ctx.font = `500 ${fontPx}px var(--font-geist-sans), system-ui, sans-serif`;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";

      const v =
        typeof (node as { val?: number }).val === "number"
          ? (node as { val: number }).val
          : nodeValForRadius(g);
      const r = Math.sqrt(v) * GRAPH_NODE_REL_SIZE;
      const y = (node.y ?? 0) + r + fontPx * 0.35;

      ctx.strokeStyle = "rgba(0,0,0,0.55)";
      ctx.lineWidth = 3 / globalScale;
      ctx.strokeText(label, node.x ?? 0, y);
      ctx.fillStyle =
        g === "Framework"
          ? FRAMEWORK_FILL
          : g === "Control"
            ? "#e5e7eb"
            : CYAN;
      ctx.fillText(label, node.x ?? 0, y);
    },
    [hoverNode, selectedId],
  );

  return (
    <div
      ref={containerRef}
      className="absolute inset-0 bg-[#0a0a0a]"
    >
      {!Fg ? (
        <div className="absolute inset-0 bg-[#0a0a0a]" aria-hidden />
      ) : (
        <Fg
          ref={fgRef}
          width={dims.width}
          height={dims.height}
          graphData={graphData}
          backgroundColor="#0a0a0a"
          nodeId="id"
          linkSource="source"
          linkTarget="target"
          nodeLabel={() => ""}
          nodeColor={nodeColor}
          nodeVal={nodeVal}
          nodeRelSize={GRAPH_NODE_REL_SIZE}
          linkColor={linkColorCb}
          linkWidth={linkWidthCb}
          nodeCanvasObjectMode={() => "after"}
          nodeCanvasObject={paintNodeObject}
          enableNodeDrag
          onNodeDrag={onNodeDrag}
          onNodeDragEnd={onNodeDragEnd}
          minZoom={0.35}
          maxZoom={24}
          d3AlphaDecay={isDenseGraph ? 0.028 : 1e-10}
          d3VelocityDecay={isDenseGraph ? 0.33 : 0.1}
          onNodeHover={(n) => setHoverNode(n)}
          onNodeClick={(n) => {
            onNodeSelect(toGraphNode(n));
            const fg = fgRef.current;
            if (!fg || n.x == null || n.y == null) return;
            clearFlyTimeout();
            fg.centerAt(n.x, n.y, 920);
            flyTimeoutRef.current = setTimeout(() => {
              fg.zoom(4.5, 1500);
              flyTimeoutRef.current = null;
            }, 220);
          }}
          onBackgroundClick={() => {
            setHoverNode(null);
            onNodeSelect(null);
          }}
        />
      )}
    </div>
  );
});
