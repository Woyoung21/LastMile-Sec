/**
 * Cleans control text for display: OSCAL placeholders, PDF TOC dot leaders, whitespace.
 */
export function formatControlDescription(raw: string): string {
  let s = raw.trim();
  if (!s) return s;

  s = s.replace(/\[[Aa]ssignment:\s*[^\]]*\]/g, " ");
  s = s.replace(/\.{4,}/g, " ");
  s = s.replace(/^[\s.]{3,}\d*[\s.]*$/gm, " ");
  s = s.replace(/\s+/g, " ").trim();
  return s;
}
