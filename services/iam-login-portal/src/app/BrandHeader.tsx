/** Top-of-page brand: the tenant's logo when it has one, otherwise a letter mark and the tenant name. */
export function BrandHeader({ tenantName, logoUrl }: { tenantName: string; logoUrl?: string | null }) {
  return (
    <div className="login-page__brand">
      {logoUrl ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img src={logoUrl} alt={tenantName} className="login-page__brand-logo" />
      ) : (
        <>
          <span className="login-page__brand-mark">{tenantName.charAt(0).toUpperCase()}</span>
          <span className="login-page__brand-name">{tenantName}</span>
        </>
      )}
    </div>
  );
}
