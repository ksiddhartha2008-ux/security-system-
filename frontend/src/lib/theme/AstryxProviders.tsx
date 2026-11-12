import { forwardRef, type AnchorHTMLAttributes, type ReactNode } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { Theme } from '@astryxdesign/core/theme';
import { LinkProvider } from '@astryxdesign/core/Link';
import { secureflowTheme } from './secureflow.js';

type AdapterProps = AnchorHTMLAttributes<HTMLAnchorElement> & { to?: string; href?: string };

/**
 * React Router adapter for Astryx links. Astryx passes `href`; the router wants
 * `to`. Both are accepted so components can use either API without a reload.
 */
const RouterLinkAdapter = forwardRef<HTMLAnchorElement, AdapterProps>(function RouterLinkAdapter(
  { href, to, children, ...rest },
  ref,
) {
  const destination = to ?? href ?? '/';
  return (
    <RouterLink ref={ref} to={destination} {...rest}>
      {children}
    </RouterLink>
  );
});

/**
 * Design system boundary. Everything inside uses the SecureFlow Astryx theme;
 * the legacy application CSS keeps its own tokens in styles.css.
 */
export function AstryxProviders({ children }: { children: ReactNode }) {
  return (
    <Theme theme={secureflowTheme} mode="dark">
      <LinkProvider component={RouterLinkAdapter}>{children}</LinkProvider>
    </Theme>
  );
}
