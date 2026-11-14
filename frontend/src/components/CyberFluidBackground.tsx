import { useEffect, useRef } from 'react';
import { useThemeMode } from '../lib/theme/ThemeMode';

type Particle = {
  x: number;
  y: number;
  vx: number;
  vy: number;
  alpha: number;
  size: number;
  color: string;
  life: number;
};

const PALETTE = {
  dark: [
    'rgba(97, 179, 255, 0.55)',
    'rgba(63, 206, 142, 0.5)',
    'rgba(124, 58, 237, 0.4)',
    'rgba(242, 199, 68, 0.32)',
  ],
  light: [
    'rgba(18, 87, 184, 0.3)',
    'rgba(8, 122, 77, 0.28)',
    'rgba(91, 46, 168, 0.2)',
    'rgba(138, 90, 0, 0.18)',
  ],
};

const FINE_POINTER = '(pointer: fine)';
const REDUCED_MOTION = '(prefers-reduced-motion: reduce)';

/**
 * Ambient particle flow field behind the page content.
 *
 * This is the CyberFluidBackground idea from the reference design, adapted to
 * this application:
 * - it reads the resolved theme and swaps its palette, so light mode is not a
 *   dark canvas with washed out particles
 * - it renders inside the content region, not over the navigation
 * - it stops drawing when the tab is hidden and draws one static frame when the
 *   user asks for reduced motion
 * - it never receives pointer events and is hidden from assistive technology
 * - device pixel ratio is capped so a 4K screen does not quadruple the work
 */
export function CyberFluidBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const { resolved } = useThemeMode();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const context = canvas.getContext('2d', { alpha: true });
    if (!context) return undefined;

    const reduced = window.matchMedia(REDUCED_MOTION);
    const finePointer = window.matchMedia(FINE_POINTER);
    const colors = PALETTE[resolved];
    const pointer = { x: -1, y: -1, px: -1, py: -1, active: false };

    let frame = 0;
    let width = 0;
    let height = 0;
    let dpr = 1;
    let particles: Particle[] = [];
    let visible = !document.hidden;

    const create = (x: number, y: number): Particle => ({
      x,
      y,
      vx: (Math.random() - 0.5) * 0.7,
      vy: (Math.random() - 0.5) * 0.7,
      alpha: Math.random() * 0.45 + 0.12,
      size: Math.random() * 2.2 + 0.6,
      color: colors[Math.floor(Math.random() * colors.length)],
      life: Math.random() * 320 + 120,
    });

    const targetCount = () => {
      if (width < 640) return 36;
      if (width < 1100) return 58;
      return 86;
    };

    const seed = () => {
      particles = Array.from({ length: targetCount() }, () => create(Math.random() * width, Math.random() * height));
    };

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      width = Math.max(1, Math.round(rect.width));
      height = Math.max(1, Math.round(rect.height));
      dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      seed();
      if (reduced.matches) drawStatic();
    };

    const paint = (particle: Particle) => {
      context.beginPath();
      context.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
      context.fillStyle = particle.color;
      context.globalAlpha = particle.alpha;
      context.fill();
      // A soft halo instead of shadowBlur, which is expensive per particle.
      context.beginPath();
      context.arc(particle.x, particle.y, particle.size * 2.6, 0, Math.PI * 2);
      context.globalAlpha = particle.alpha * 0.14;
      context.fill();
      context.globalAlpha = 1;
    };

    const drawStatic = () => {
      context.clearRect(0, 0, width, height);
      for (const particle of particles) paint(particle);
    };

    const step = (time: number) => {
      // Erase a little of the previous frame to leave a short fluid trail while
      // keeping the canvas transparent over the themed surface.
      context.globalCompositeOperation = 'destination-out';
      context.fillStyle = 'rgba(0, 0, 0, 0.09)';
      context.fillRect(0, 0, width, height);
      context.globalCompositeOperation = 'source-over';

      const centreX = pointer.x;
      const centreY = pointer.y;

      for (const particle of particles) {
        particle.vx += Math.sin(particle.y * 0.0032 + time * 0.00042) * 0.14;
        particle.vy += Math.cos(particle.x * 0.0032 + time * 0.00042) * 0.14;

        if (pointer.active) {
          const dx = particle.x - centreX;
          const dy = particle.y - centreY;
          const distance = Math.hypot(dx, dy);
          if (distance > 0.5 && distance < 170) {
            const force = (170 - distance) / 170;
            particle.vx += (dy / distance) * force * 1.35;
            particle.vy -= (dx / distance) * force * 1.35;
          }
        }

        particle.x += particle.vx;
        particle.y += particle.vy;
        particle.vx *= 0.986;
        particle.vy *= 0.986;
        particle.life -= 1;

        if (particle.life <= 0 || particle.x < -20 || particle.x > width + 20 || particle.y < -20 || particle.y > height + 20) {
          Object.assign(particle, create(Math.random() * width, Math.random() * height));
          continue;
        }
        paint(particle);
      }
    };

    const loop = (time: number) => {
      if (!visible) return;
      step(time);
      frame = requestAnimationFrame(loop);
    };

    const start = () => {
      cancelAnimationFrame(frame);
      if (!reduced.matches) frame = requestAnimationFrame(loop);
    };

    const onPointerMove = (event: PointerEvent) => {
      if (!finePointer.matches) return;
      const rect = canvas.getBoundingClientRect();
      const inside = event.clientX >= rect.left && event.clientX <= rect.right && event.clientY >= rect.top && event.clientY <= rect.bottom;
      if (!inside) { pointer.active = false; return; }
      pointer.px = pointer.x;
      pointer.py = pointer.y;
      pointer.x = event.clientX - rect.left;
      pointer.y = event.clientY - rect.top;
      pointer.active = true;
      if (particles.length < 150 && Math.hypot(pointer.x - pointer.px, pointer.y - pointer.py) > 6 && Math.random() < 0.25) {
        particles.push(create(pointer.x, pointer.y));
      }
    };

    const onPointerLeave = () => { pointer.active = false; };

    const onVisibility = () => {
      visible = !document.hidden;
      if (visible) start();
      else cancelAnimationFrame(frame);
    };

    const onMotionPreference = () => {
      cancelAnimationFrame(frame);
      if (reduced.matches) drawStatic();
      else start();
    };

    const observer = new ResizeObserver(() => {
      cancelAnimationFrame(frame);
      resize();
      if (!reduced.matches) start();
    });
    observer.observe(canvas);

    resize();
    if (reduced.matches) drawStatic();
    else start();

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('pointerleave', onPointerLeave, { passive: true });
    document.addEventListener('visibilitychange', onVisibility);
    reduced.addEventListener('change', onMotionPreference);

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerleave', onPointerLeave);
      document.removeEventListener('visibilitychange', onVisibility);
      reduced.removeEventListener('change', onMotionPreference);
      context.clearRect(0, 0, width, height);
    };
  }, [resolved]);

  return (
    <div className="fluid-layer" aria-hidden="true">
      <div className="fluid-glow" />
      <canvas ref={canvasRef} className="fluid-canvas" />
    </div>
  );
}
