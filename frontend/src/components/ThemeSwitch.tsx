import { Monitor, Moon, Sun } from 'lucide-react';
import { useThemeMode, type ThemeMode } from '../lib/theme/ThemeMode';

const OPTIONS: { key: ThemeMode; label: string; Icon: typeof Sun }[] = [
  { key: 'light', label: 'Light', Icon: Sun },
  { key: 'dark', label: 'Dark', Icon: Moon },
  { key: 'system', label: 'System', Icon: Monitor },
];

/** Three way appearance control used by the account menu and the public site. */
export function ThemeSwitch({ labelId, className = '' }: { labelId?: string; className?: string }) {
  const { mode, setMode } = useThemeMode();
  return (
    <div
      className={`theme-switch ${className}`.trim()}
      role="group"
      aria-labelledby={labelId}
      aria-label={labelId ? undefined : 'Appearance'}
    >
      {OPTIONS.map(({ key, label, Icon }) => {
        const active = mode === key;
        return (
          <button
            key={key}
            type="button"
            aria-pressed={active}
            aria-label={label}
            title={label}
            onClick={() => setMode(key)}
          >
            <Icon size={13} aria-hidden="true" />
            <span>{label}</span>
          </button>
        );
      })}
    </div>
  );
}
