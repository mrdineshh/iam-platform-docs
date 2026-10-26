import { redirect } from "next/navigation";

interface SearchParams {
  tenant?: string;
}

// The bare domain has nothing of its own to show -- send visitors straight
// to the direct sign-in entry point (see portal/page.tsx).
export default async function RootPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  redirect(params.tenant ? `/portal?tenant=${encodeURIComponent(params.tenant)}` : "/portal");
}
