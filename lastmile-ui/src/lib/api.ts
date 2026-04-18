import type { InventoryResponse, LatestApiResponse } from "@/types/lastmile";

function apiBase(): string {
  const b = process.env.NEXT_PUBLIC_API_BASE_URL ?? "";
  return b.replace(/\/$/, "");
}

export async function fetchInventory(
  folder: string,
): Promise<InventoryResponse> {
  const res = await fetch(`${apiBase()}/api/inventory/${folder}`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`inventory ${res.status}`);
  return res.json() as Promise<InventoryResponse>;
}

export async function fetchLatestPacket(
  folder: "remediated" | "mapped" | "processed" | "correlate",
): Promise<LatestApiResponse> {
  const res = await fetch(
    `${apiBase()}/api/latest?folder=${encodeURIComponent(folder)}`,
    { cache: "no-store" },
  );
  if (!res.ok) throw new Error(`latest ${folder}: ${res.status}`);
  return res.json() as Promise<LatestApiResponse>;
}
