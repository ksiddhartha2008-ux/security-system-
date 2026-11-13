/* Applied before the first paint so a stored preference never flashes.
 * The runtime provider (src/lib/theme/ThemeMode.tsx) owns later changes. */
(function () {
  try {
    var stored = window.localStorage.getItem('sf-theme');
    var mode = stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'system';
    var dark = mode === 'dark' || (mode === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    var theme = dark ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.style.colorScheme = theme;
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', dark ? '#0a0e15' : '#f4f6fa');
  } catch (error) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();
