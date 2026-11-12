/**
 * SecureFlow AI theme for Astryx.
 *
 * Extends the neutral theme with a dark-first SOC palette and semantic severity
 * colours. Light values are present so the theme is complete, but the current
 * application CSS is dark-first; light mode is not exposed in the UI yet.
 */
import { defineTheme } from '@astryxdesign/core/theme';
import { neutralTheme } from '@astryxdesign/theme-neutral/built';

export const secureflowTheme = defineTheme({
  name: 'secureflow',
  extends: neutralTheme,
  typography: {
    scale: { base: 14, ratio: 1.2 },
    body: { family: 'Segoe UI', fallbacks: 'system-ui, -apple-system, Roboto, Helvetica, Arial, sans-serif' },
    heading: { family: 'Segoe UI', fallbacks: 'system-ui, -apple-system, Roboto, Helvetica, Arial, sans-serif' },
    code: { family: 'JetBrains Mono', fallbacks: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace' },
  },
  radius: { base: 5, multiplier: 1 },
  tokens: {
    '--color-accent': ['#1B63D8', '#4D9DFF'],
    '--color-on-accent': ['#FFFFFF', '#06101F'],

    '--color-background-body': ['#EDEFF4', '#0A0E15'],
    '--color-background-surface': ['#F6F8FB', '#0E141F'],
    '--color-background-card': ['#FFFFFF', '#131B2A'],
    '--color-background-muted': ['#EFF2F7', '#0B111B'],
    '--color-background-popover': ['#FFFFFF', '#1A2334'],
    '--color-background-inverted': ['#16202E', '#F6F8FB'],

    '--color-text-primary': ['#152238', '#E9EFF9'],
    '--color-text-secondary': ['#54637F', '#9DACCA'],
    '--color-text-disabled': ['#9AA7BC', '#5A6A87'],

    '--color-border': ['#D9DFEA', '#253149'],
    '--color-border-emphasized': ['#B9C3D6', '#384664'],

    '--color-error': ['#D3262C', '#FF6B6E'],
    '--color-error-muted': ['#FBE3E4', '#3A1620'],
    '--color-on-error': ['#FFFFFF', '#2A0508'],
    '--color-on-error-muted': ['#8C1218', '#FFB3B5'],

    '--color-warning': ['#B35B04', '#FFA35C'],
    '--color-warning-muted': ['#FDEBD8', '#37230F'],
    '--color-on-warning': ['#FFFFFF', '#2B1606'],
    '--color-on-warning-muted': ['#8F4404', '#FFC08A'],

    '--color-success': ['#188554', '#3FCE8E'],
    '--color-success-muted': ['#DDF3E7', '#0E2E21'],
    '--color-on-success': ['#FFFFFF', '#04170E'],
    '--color-on-success-muted': ['#10693F', '#7BE3B2'],

    '--color-info': ['#147BC7', '#61B3FF'],
    '--color-info-muted': ['#DFEDFB', '#0F2740'],
    '--color-on-info': ['#FFFFFF', '#06101F'],
    '--color-on-info-muted': ['#0F5E9C', '#A8D4FF'],

    '--color-text-red': ['#B31B20', '#FF8589'],
    '--color-background-red': ['#FBE3E4', '#3A1620'],
    '--color-border-red': ['#F0B6B8', '#5F2731'],

    '--color-text-orange': ['#9E4B02', '#FFAB66'],
    '--color-background-orange': ['#FDEBD8', '#37230F'],
    '--color-border-orange': ['#EFC396', '#66401C'],

    '--color-text-yellow': ['#7A5B00', '#F2C744'],
    '--color-background-yellow': ['#FBF2D4', '#332A0C'],
    '--color-border-yellow': ['#E8D489', '#5C4C16'],

    '--color-text-green': ['#0E6B42', '#55D795'],
    '--color-background-green': ['#DDF3E7', '#0E2E21'],
    '--color-border-green': ['#A8DEC4', '#1D5138'],

    '--color-text-blue': ['#155CA8', '#7CB8FF'],
    '--color-background-blue': ['#DFEDFB', '#12253C'],
    '--color-border-blue': ['#B1D2F1', '#2C4A72'],

    '--color-text-teal': ['#0B6E63', '#4FC8B8'],
    '--color-background-teal': ['#D9F2EF', '#0B2723'],
    '--color-border-teal': ['#9BD9D0', '#1E5049'],

    '--color-text-purple': ['#6A3DB8', '#BC9CFF'],
    '--color-background-purple': ['#EEE5FB', '#241A3D'],
    '--color-border-purple': ['#CDB4EF', '#46336E'],

    '--color-text-cyan': ['#0A6C8C', '#5BC3E8'],
    '--color-background-cyan': ['#DBF0F8', '#0C2733'],
    '--color-border-cyan': ['#A5D9EC', '#1F4F63'],

    '--color-text-pink': ['#A61A64', '#F585BB'],
    '--color-background-pink': ['#FBE3EF', '#33101F'],
    '--color-border-pink': ['#EFB4D3', '#5D2440'],

    '--color-text-gray': ['#4E5D75', '#A9B6CE'],
    '--color-background-gray': ['#EDF0F5', '#1A2231'],
    '--color-border-gray': ['#D3DAE6', '#313D55'],

    '--color-overlay': ['rgba(15, 23, 36, 0.45)', 'rgba(2, 6, 12, 0.62)'],
    '--color-track': ['#DDE3ED', '#1C2639'],
    '--color-skeleton': ['#E2E7F0', '#18202F'],

    '--focus-outline-color': ['#1B63D8', '#4D9DFF'],
    '--focus-outline-width': '2px',
    '--focus-outline-offset': '3px',
  },
  components: {
    card: {
      base: { boxShadow: 'none', borderColor: 'var(--color-border)' },
      'variant:default': { backgroundColor: 'var(--color-background-card)' },
    },
    table: { base: { fontSize: '13px' } },
    banner: { base: { fontSize: '13px' } },
  },
});

export default secureflowTheme;
