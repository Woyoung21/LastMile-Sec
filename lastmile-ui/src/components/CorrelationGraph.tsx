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
const FRAMEWORK_FILL = "#FFFFFF";
const CONTROL_FILL = "#9ca3af";
const LINK_DIM = "rgba(255,255,255,0.15)";
const LINK_HI = "rgba(0, 229, 255, 0.82)";
const LINK_LAYOUT_ONLY = "rgba(255,255,255,0.06)";

type ForceGraph2DComponent = typeof import("react-force-graph-2d").default;

const GRAPH_NODE_REL_SIZE = 1;
const RADIUS_FW = 8;
const RADIUS_MITRE = 6;
const RADIUS_CTL = 4;

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

  useEffect(() => {
    if (!Fg) return;
    let cancelled = false;
    const raf = requestAnimationFrame(() => {
      if (cancelled) return;
      const fg = fgRef.current;
      if (!fg) return;

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      fg.d3Force("center", d3.forceCenter(0, 0) as any);

      const boxHalf = Math.max(300, Math.min(dims.width, dims.height) * 0.42);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      fg.d3Force("bounding", forceBoundingBox(boxHalf, 0.14) as any);

      fg.d3Force(
        "charge",
        d3
          .forceManyBody()
          .strength(
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ((node: any) => (node.group === "Framework" ? -1800 : -40)) as any
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
          ) as any,
      );

      const linkForce = d3
        .forceLink([...(graphData.links as SimLink[])])
        .id((d: NodeObject) => String(d.id ?? ""))
        .distance((l: SimLink) => (l.__layoutOnly ? 72 : 35));
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      fg.d3Force("link", linkForce as any);

      fg.d3ReheatSimulation?.();
    });

    return () => {
      cancelled = true;
      cancelAnimationFrame(raf);
    };
  }, [Fg, graphData, dims.width, dims.height]);

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
      return 0.55;
    },
    [linkIsActive, syntheticEdgeKeys],
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
          enableNodeDrag={false}
          minZoom={0.35}
          maxZoom={24}
          d3AlphaDecay={1e-10}
          d3VelocityDecay={0.1}
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
