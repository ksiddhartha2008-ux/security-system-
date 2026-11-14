import { useEffect, useRef, useState } from 'react';
import { useThemeMode } from '../lib/theme/ThemeMode';

const VERTEX = 'attribute vec2 p; void main(){ gl_Position = vec4(p, 0.0, 1.0); }';

const FRAGMENT = `precision mediump float;
uniform vec2 u_res;
uniform vec2 u_mouse;
uniform float u_time;
uniform float u_vign;
uniform vec3 u_c1;
uniform vec3 u_c2;
uniform vec3 u_c3;
uniform vec3 u_c4;

float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
float noise(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  f = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), f.x),
             mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), f.x), f.y);
}

void main() {
  vec2 uv = gl_FragCoord.xy / u_res;
  vec2 p = (uv - 0.5) * vec2(u_res.x / u_res.y, 1.0);
  float tm = u_time * 0.12;

  float wave = sin(p.x * 3.2 + tm + sin(p.y * 4.0 - tm)) * 0.12
             + cos(p.y * 5.0 - tm * 0.8) * 0.08;
  vec2 q = p + vec2(wave, sin(p.x * 2.0 + tm) * 0.08);

  float a = exp(-length(q - vec2(-0.35, 0.12 + sin(tm) * 0.08)) * 2.8);
  float b = exp(-length(q - vec2(0.42, -0.18 + cos(tm * 0.8) * 0.1)) * 3.0);
  vec2 mp = (u_mouse - 0.5) * vec2(u_res.x / u_res.y, 1.0);
  float c = exp(-length(p - mp) * 4.5);

  float n = noise(gl_FragCoord.xy * 0.18 + floor(u_time * 8.0));
  vec3 col = u_c1 + a * u_c2 + b * u_c3 + c * u_c4;
  col += wave * u_c4 * 0.28;

  float dither = (n - 0.5) * 0.035;
  col += dither;
  col *= 1.0 - u_vign * length(p);
  gl_FragColor = vec4(clamp(col, 0.0, 1.0), 1.0);
}`;

const PALETTE = {
  dark: {
    c1: [0.018, 0.035, 0.09],
    c2: [0.02, 0.35, 0.55],
    c3: [0.27, 0.08, 0.48],
    c4: [0.04, 0.28, 0.38],
    vignette: 0.5,
  },
  light: {
    c1: [0.96, 0.975, 1.0],
    c2: [0.52, 0.76, 0.98],
    c3: [0.76, 0.66, 0.98],
    c4: [0.62, 0.88, 1.0],
    vignette: 0.14,
  },
};

function compile(gl: WebGLRenderingContext, type: number, source: string) {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

/**
 * WebGL fluid shader for the public hero.
 *
 * Failure is silent and visual: if the browser has no WebGL, the shader fails to
 * compile, or the context is lost, the CSS gradient fallback underneath remains.
 * Reduced motion draws one static frame. The loop stops when the tab is hidden.
 */
export function PublicShader() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const { resolved } = useThemeMode();
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;

    let gl: WebGLRenderingContext | null = null;
    try {
      gl = canvas.getContext('webgl', { alpha: false, antialias: false, powerPreference: 'low-power' });
    } catch {
      gl = null;
    }
    if (!gl) {
      setFailed(true);
      return undefined;
    }
    const context = gl;

    const vertex = compile(context, context.VERTEX_SHADER, VERTEX);
    const fragment = compile(context, context.FRAGMENT_SHADER, FRAGMENT);
    if (!vertex || !fragment) {
      setFailed(true);
      return undefined;
    }
    const program = context.createProgram();
    if (!program) {
      setFailed(true);
      return undefined;
    }
    context.attachShader(program, vertex);
    context.attachShader(program, fragment);
    context.linkProgram(program);
    if (!context.getProgramParameter(program, context.LINK_STATUS)) {
      setFailed(true);
      return undefined;
    }
    context.useProgram(program);

    const buffer = context.createBuffer();
    context.bindBuffer(context.ARRAY_BUFFER, buffer);
    context.bufferData(context.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), context.STATIC_DRAW);
    const position = context.getAttribLocation(program, 'p');
    context.enableVertexAttribArray(position);
    context.vertexAttribPointer(position, 2, context.FLOAT, false, 0, 0);

    const uRes = context.getUniformLocation(program, 'u_res');
    const uMouse = context.getUniformLocation(program, 'u_mouse');
    const uTime = context.getUniformLocation(program, 'u_time');
    const uVign = context.getUniformLocation(program, 'u_vign');
    const uC1 = context.getUniformLocation(program, 'u_c1');
    const uC2 = context.getUniformLocation(program, 'u_c2');
    const uC3 = context.getUniformLocation(program, 'u_c3');
    const uC4 = context.getUniformLocation(program, 'u_c4');
    const palette = PALETTE[resolved];

    const reducedQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const pointer = { x: 0.5, y: 0.35, tx: 0.5, ty: 0.35 };
    let frame = 0;
    let time = 0;
    let last = 0;
    let visible = !document.hidden;
    let width = 2;
    let height = 2;

    const render = () => {
      context.uniform2f(uRes, width, height);
      context.uniform2f(uMouse, pointer.x, pointer.y);
      context.uniform1f(uTime, time);
      context.uniform1f(uVign, palette.vignette);
      context.uniform3fv(uC1, palette.c1);
      context.uniform3fv(uC2, palette.c2);
      context.uniform3fv(uC3, palette.c3);
      context.uniform3fv(uC4, palette.c4);
      context.drawArrays(context.TRIANGLE_STRIP, 0, 4);
    };

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 1.35);
      width = Math.max(2, Math.round(rect.width * dpr));
      height = Math.max(2, Math.round(rect.height * dpr));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
        context.viewport(0, 0, width, height);
      }
      render();
    };

    const loop = (now: number) => {
      if (!visible) return;
      const delta = last ? Math.min(0.05, (now - last) / 1000) : 0;
      last = now;
      time += delta;
      pointer.x += (pointer.tx - pointer.x) * 0.06;
      pointer.y += (pointer.ty - pointer.y) * 0.06;
      render();
      frame = requestAnimationFrame(loop);
    };

    const start = () => {
      cancelAnimationFrame(frame);
      last = 0;
      if (!reducedQuery.matches && !document.hidden) frame = requestAnimationFrame(loop);
    };

    const onPointerMove = (event: PointerEvent) => {
      if (event.pointerType !== 'mouse' && event.pointerType !== 'pen') return;
      const rect = canvas.getBoundingClientRect();
      if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) return;
      pointer.tx = (event.clientX - rect.left) / rect.width;
      pointer.ty = 1 - (event.clientY - rect.top) / rect.height;
    };

    const onVisibility = () => {
      visible = !document.hidden;
      if (visible) start();
      else cancelAnimationFrame(frame);
    };

    const onMotionPreference = () => {
      cancelAnimationFrame(frame);
      if (reducedQuery.matches) {
        time = 0;
        render();
      } else start();
    };

    const onContextLost = (event: Event) => {
      event.preventDefault();
      cancelAnimationFrame(frame);
      setFailed(true);
    };

    const observer = new ResizeObserver(() => {
      cancelAnimationFrame(frame);
      resize();
      start();
    });
    observer.observe(canvas);

    setFailed(false);
    resize();
    if (reducedQuery.matches) render();
    else start();

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    document.addEventListener('visibilitychange', onVisibility);
    reducedQuery.addEventListener('change', onMotionPreference);
    canvas.addEventListener('webglcontextlost', onContextLost);

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener('pointermove', onPointerMove);
      document.removeEventListener('visibilitychange', onVisibility);
      reducedQuery.removeEventListener('change', onMotionPreference);
      canvas.removeEventListener('webglcontextlost', onContextLost);
      context.deleteProgram(program);
      context.deleteShader(vertex);
      context.deleteShader(fragment);
      context.deleteBuffer(buffer);
    };
  }, [resolved]);

  return (
    <div className="lp-shader" aria-hidden="true">
      <div className="lp-shader-fallback" />
      <canvas ref={canvasRef} className={failed ? 'lp-shader-canvas is-hidden' : 'lp-shader-canvas'} />
    </div>
  );
}
