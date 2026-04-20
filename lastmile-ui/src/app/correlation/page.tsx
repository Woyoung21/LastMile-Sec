"use client";

import { useRef, useState } from "react";

import {
  CorrelationGraph,
  type CorrelationGraphHandle,
} from "@/components/CorrelationGraph";
import mockGraphData from "@/data/mockGraphData.json";
import { formatControlDescription } from "@/lib/formatControlDescription";
import type { GraphData, GraphNode } from "@/types/graph";

const data = mockGraphData as GraphData;

export default function CorrelationPage() {
  const graphRef = useRef<CorrelationGraphHandle>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const clearSelection = () => {
    setSelectedNode(null);
    graphRef.current?.resetZoom();
  };

  return (
    <div className="relative flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="relative min-h-0 h-full w-full flex-1">
        <div
          className="absolute left-6 top-6 z-10 max-w-[min(100%-3rem,22rem)] rounded-xl border border-surface-border bg-black/50 p-4 text-xs shadow-xl backdrop-blur-md sm:text-sm"
          role="region"
          aria-label="Graph legend"
        >
          <p className="mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted">
            Legend
          </p>
          <ul className="space-y-3 text-foreground/95">
            <li className="flex items-center gap-3">
              <span
                className="h-3 w-3 shrink-0 rounded-full border border-indigo-400/40 bg-indigo-400"
                aria-hidden
              />
              <span>Framework / Source</span>
            </li>
            <li className="flex items-center gap-3">
              <span
                className="h-3 w-3 shrink-0 rounded-full bg-[#9ca3af]"
                aria-hidden
              />
              <span>Security Control (Remediation)</span>
            </li>
            <li className="flex items-center gap-3">
              <span
                className="h-3 w-3 shrink-0 rounded-full bg-[#00E5FF]"
                aria-hidden
              />
              <span>MITRE ATT&amp;CK Technique</span>
            </li>
          </ul>
        </div>

        <CorrelationGraph
          ref={graphRef}
          data={data}
          selectedId={selectedNode?.id ?? null}
          onNodeSelect={setSelectedNode}
        />

        <aside
          className={`absolute inset-y-0 right-0 z-20 flex w-96 max-w-full flex-col border-l border-surface-border bg-surface/80 backdrop-blur-md transition-transform duration-300 ease-out ${
            selectedNode ? "translate-x-0" : "translate-x-full"
          } ${selectedNode ? "" : "pointer-events-none"}`}
          aria-hidden={!selectedNode}
        >
          {selectedNode && (
            <>
              <div className="flex shrink-0 items-start justify-between gap-3 border-b border-surface-border p-4">
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-bold uppercase tracking-wider text-muted">
                    {selectedNode.group}
                  </p>
                  <h2 className="mt-1 break-words text-lg font-semibold leading-snug text-foreground">
                    {selectedNode.label}
                  </h2>
                </div>
                <button
                  type="button"
                  onClick={clearSelection}
                  className="shrink-0 rounded-md border border-surface-border px-2.5 py-1.5 text-sm text-muted transition-colors hover:border-accent/50 hover:text-accent"
                  aria-label="Clear selection"
                >
                  ✕
                </button>
              </div>
              <div className="custom-scroll min-h-0 flex-1 overflow-y-auto p-4">
                <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground/90">
                  {formatControlDescription(selectedNode.description)}
                </p>
              </div>
              <div className="shrink-0 border-t border-surface-border p-4">
                <button
                  type="button"
                  onClick={clearSelection}
                  className="w-full rounded-md border border-surface-border bg-black/30 py-2.5 text-sm font-medium text-muted transition-colors hover:border-accent/45 hover:text-accent"
                >
                  Clear selection
                </button>
              </div>
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
