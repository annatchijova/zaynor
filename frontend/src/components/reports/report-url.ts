function isRelativeUrl(value: string): boolean {
  return value.startsWith("/") && !value.startsWith("//");
}

export function isSafeReportUrl(value: string): boolean {
  if (isRelativeUrl(value)) {
    return true;
  }

  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}
