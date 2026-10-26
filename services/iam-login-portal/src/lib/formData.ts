export function str(value: FormDataEntryValue | null): string {
  return typeof value === "string" ? value : "";
}
