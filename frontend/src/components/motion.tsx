import { createElement, useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { formatMetric, useInView, useReducedMotion, type RevealDirection } from '../lib/motion';

type Tag = 'div' | 'section' | 'article' | 'li';

export function ScrollReveal({
  children,
  as = 'div',
  direction = 'up',
  delay = 0,
  duration = 460,
  once = true,
  hover = false,
  className,
  style,
  id,
  ariaLabel,
}: {
  children: ReactNode;
  as?: Tag;
  direction?: RevealDirection;
  delay?: number;
  duration?: number;
  once?: boolean;
  hover?: boolean;
  className?: string;
  style?: CSSProperties;
  id?: string;
  ariaLabel?: string;
}) {
  const reduced = useReducedMotion();
  const { ref, inView } = useInView<HTMLElement>({ once });
  const visible = reduced || inView;
  const revealedStyle = {
    ...style,
    '--reveal-delay': `${delay}ms`,
    '--reveal-duration': `${duration}ms`,
  } as CSSProperties;

  return createElement(
    as,
    {
      ref: ref as never,
      id,
      'aria-label': ariaLabel,
      className: `reveal${hover ? ' reveal-hover' : ''}${visible ? ' is-visible' : ''}${className ? ` ${className}` : ''}`,
      'data-reveal': direction,
      style: revealedStyle,
    },
    children,
  );
}

/**
 * Counts from the previous value to the new one. The visible number is hidden
 * from assistive technology and a static, final value is exposed instead, so a
 * screen reader never hears every intermediate frame.
 */
export function AnimatedMetric({
  value,
  decimals = 0,
  prefix = '',
  suffix = '',
  duration = 700,
  locale,
  className,
  animateOnView = true,
}: {
  value: number;
  decimals?: number;
  prefix?: string;
  suffix?: string;
  duration?: number;
  locale?: string;
  className?: string;
  animateOnView?: boolean;
}) {
  const reduced = useReducedMotion();
  const target = Number.isFinite(value) ? value : 0;
  const { ref, inView } = useInView<HTMLSpanElement>({ threshold: 0.3, once: false });
  const [display, setDisplay] = useState(() => (reduced || !animateOnView ? target : 0));
  const shown = useRef(display);
  const frame = useRef<number | null>(null);
  const revealed = useRef(!animateOnView);
  const lastTarget = useRef(target);

  const run = (to: number, from: number, ms: number) => {
    if (frame.current) cancelAnimationFrame(frame.current);
    if (reduced || typeof requestAnimationFrame === 'undefined') {
      shown.current = to;
      setDisplay(to);
      return;
    }
    const start = performance.now();
    const delta = to - from;
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / Math.max(ms, 1));
      const eased = 1 - (1 - progress) ** 3;
      const next = from + delta * eased;
      shown.current = next;
      setDisplay(next);
      if (progress < 1) frame.current = requestAnimationFrame(tick);
      else { frame.current = null; shown.current = to; setDisplay(to); }
    };
    frame.current = requestAnimationFrame(tick);
  };

  useEffect(() => {
    if (!animateOnView || revealed.current || !inView) return;
    revealed.current = true;
    run(target, 0, duration);
    // `run` reads the current reduced-motion value; it is intentionally not a dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inView, animateOnView, target, duration]);

  useEffect(() => {
    if (!revealed.current) return;
    if (lastTarget.current === target) return;
    lastTarget.current = target;
    run(target, shown.current, Math.min(duration, 450));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, duration]);

  useEffect(() => {
    if (!reduced) return;
    if (frame.current) cancelAnimationFrame(frame.current);
    frame.current = null;
    shown.current = target;
    setDisplay(target);
  }, [reduced, target]);

  useEffect(() => () => {
    if (frame.current) cancelAnimationFrame(frame.current);
  }, []);

  return (
    <span ref={ref} className={`animated-metric${className ? ` ${className}` : ''}`}>
      <span aria-hidden="true">{prefix}{formatMetric(display, { decimals, locale })}{suffix}</span>
      <span className="sr-only">{prefix}{formatMetric(target, { decimals, locale })}{suffix}</span>
    </span>
  );
}

/** Replays a short entrance when the route path changes. */
export function PageTransition({ routeKey, children }: { routeKey: string; children: ReactNode }) {
  const reduced = useReducedMotion();
  return (
    <div key={routeKey} className={reduced ? 'page-transition is-reduced' : 'page-transition'}>
      {children}
    </div>
  );
}
