import { useEffect, useRef, useState } from 'react';

export type RevealDirection = 'up' | 'down' | 'left' | 'right' | 'none';

export const MOTION = {
  duration: { fast: 160, base: 260, slow: 420 },
  easing: 'cubic-bezier(0.22, 1, 0.36, 1)',
  stagger: 45,
  distance: 16,
} as const;

/** Live `prefers-reduced-motion` value. Updates when the OS setting changes. */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => (
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
      : false
  ));

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = () => setReduced(media.matches);
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);

  return reduced;
}

type InViewCallback = (visible: boolean) => void;
type InViewRecord = { callback: InViewCallback; once: boolean; observer: IntersectionObserver };

/**
 * One IntersectionObserver per threshold and root margin pair, shared by every
 * component. A dashboard with 40 revealed cards therefore creates one observer,
 * not forty.
 */
const observers = new Map<string, IntersectionObserver>();
const records = new WeakMap<Element, InViewRecord>();

/**
 * A fast scroll can move an element from below the viewport to above it in one
 * frame. IntersectionObserver only reports a change when intersection changes,
 * so that element would never be revealed. A passive scroll fallback checks the
 * few pending elements and reveals anything at or above the viewport.
 */
const pending = new Set<InViewRecord & { element: Element }>();
let scrollBound = false;
let checkScheduled = false;

function unbindScroll() {
  if (!scrollBound) return;
  scrollBound = false;
  window.removeEventListener('scroll', scheduleCheck, true);
  window.removeEventListener('resize', scheduleCheck);
}

function checkPending() {
  checkScheduled = false;
  const viewport = window.innerHeight || document.documentElement.clientHeight;
  for (const record of [...pending]) {
    const rect = record.element.getBoundingClientRect();
    if (rect.top >= viewport * 0.95) continue;
    record.callback(true);
    pending.delete(record);
    if (record.once) {
      record.observer.unobserve(record.element);
      records.delete(record.element);
    }
  }
  if (!pending.size) unbindScroll();
}

function scheduleCheck() {
  if (checkScheduled) return;
  checkScheduled = true;
  requestAnimationFrame(checkPending);
}

function bindScroll() {
  if (scrollBound) return;
  scrollBound = true;
  window.addEventListener('scroll', scheduleCheck, { capture: true, passive: true });
  window.addEventListener('resize', scheduleCheck, { passive: true });
}

function observerFor(threshold: number, rootMargin: string) {
  const key = `${threshold}|${rootMargin}`;
  const existing = observers.get(key);
  if (existing) return existing;
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      const record = records.get(entry.target);
      if (!record) continue;
      // An element above the viewport has already been passed. Treat it as
      // revealed so a fast scroll or a restored scroll position cannot leave a
      // card permanently invisible.
      const passed = entry.boundingClientRect.top < 0;
      if (entry.isIntersecting || passed) {
        record.callback(true);
        if (record.once) {
          observer.unobserve(entry.target);
          records.delete(entry.target);
        }
      } else if (!record.once) {
        record.callback(false);
      }
    }
  }, { threshold, rootMargin });
  observers.set(key, observer);
  return observer;
}

function observe(element: Element, options: { once: boolean; threshold: number; rootMargin: string }, callback: InViewCallback) {
  if (typeof IntersectionObserver === 'undefined') {
    callback(true);
    return () => {};
  }
  const observer = observerFor(options.threshold, options.rootMargin);
  const record = { callback, once: options.once, observer, element };
  records.set(element, record);
  pending.add(record);
  bindScroll();
  observer.observe(element);
  scheduleCheck();
  return () => {
    observer.unobserve(element);
    records.delete(element);
    pending.delete(record);
    if (!pending.size) unbindScroll();
  };
}

export function useInView<T extends HTMLElement = HTMLDivElement>({
  once = true,
  threshold = 0.15,
  rootMargin = '0px 0px -6% 0px',
}: { once?: boolean; threshold?: number; rootMargin?: string } = {}) {
  const ref = useRef<T | null>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const element = ref.current;
    if (!element) return undefined;
    let active = true;
    const stop = observe(element, { once, threshold, rootMargin }, (visible) => {
      if (active) setInView(visible);
    });
    return () => { active = false; stop(); };
  }, [once, threshold, rootMargin]);

  return { ref, inView };
}

/** Locale aware number text, without changing the value the caller passed. */
export function formatMetric(value: number, { decimals = 0, locale }: { decimals?: number; locale?: string } = {}) {
  const safe = Number.isFinite(value) ? value : 0;
  return new Intl.NumberFormat(locale, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  }).format(safe);
}
