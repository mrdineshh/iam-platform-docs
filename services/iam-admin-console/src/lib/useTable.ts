import { useEffect, useMemo, useState } from "react";

export type SortDir = "asc" | "desc";

export interface TableOptions<T> {
  /** Text that the search box matches against (lower-cased by the hook). */
  searchText: (row: T) => string;
  /** One comparator per sortable column key. */
  sorters: Record<string, (a: T, b: T) => number>;
  initialSort?: { key: string; dir: SortDir };
  pageSize?: number;
}

/**
 * Client-side search + sort + pagination. Every list in this console is
 * already fully loaded (tens of rows per tenant), so doing it in the browser
 * is simpler and instant; if a list ever needs server-side paging this hook's
 * return shape is the seam to swap.
 */
export function useTable<T>(rows: T[], options: TableOptions<T>) {
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState(options.initialSort ?? null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(options.pageSize ?? 10);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? rows.filter((r) => options.searchText(r).toLowerCase().includes(q)) : rows;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, query]);

  const sorted = useMemo(() => {
    if (!sort) return filtered;
    const cmp = options.sorters[sort.key];
    if (!cmp) return filtered;
    const out = [...filtered].sort(cmp);
    return sort.dir === "desc" ? out.reverse() : out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered, sort]);

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));

  // A new search, a page-size change, or a deleted row can leave the current
  // page past the end -- pull it back instead of showing an empty page.
  useEffect(() => {
    if (page > pageCount) setPage(pageCount);
  }, [page, pageCount]);

  useEffect(() => {
    setPage(1);
  }, [query, pageSize]);

  const pageRows = useMemo(
    () => sorted.slice((page - 1) * pageSize, page * pageSize),
    [sorted, page, pageSize],
  );

  function toggleSort(key: string) {
    setSort((prev) => {
      if (!prev || prev.key !== key) return { key, dir: "asc" };
      return { key, dir: prev.dir === "asc" ? "desc" : "asc" };
    });
  }

  return {
    pageRows,
    total: rows.length,
    filteredCount: sorted.length,
    query,
    setQuery,
    sort,
    toggleSort,
    page,
    setPage,
    pageCount,
    pageSize,
    setPageSize,
  };
}

export type TableState = ReturnType<typeof useTable<unknown>>;
