export type GraphGroup = "Framework" | "Control" | "MITRE";

export type GraphNode = {
  id: string;
  group: GraphGroup;
  label: string;
  description: string;
};

export type GraphLink = {
  source: string;
  target: string;
};

export type GraphData = {
  nodes: GraphNode[];
  links: GraphLink[];
};
