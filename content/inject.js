// Выполняется в контексте страницы (не в изолированном мире расширения).
// Штатные виджеты MaxPatrol открывают переходы через window.open в новую вкладку.
// При включенной опции (data-vr-same-tab="1" на <html>) переход на тот же origin
// выполняется в текущей вкладке; с зажатым Ctrl/Cmd поведение штатное.
(function () {
  if (window.__vrOpenPatched) return;
  window.__vrOpenPatched = true;
  const orig = window.open;
  let modifier = false;
  document.addEventListener('keydown', e => { if (e.ctrlKey || e.metaKey) modifier = true; }, true);
  document.addEventListener('keyup', () => { modifier = false; }, true);
  document.addEventListener('mousedown', e => { modifier = e.ctrlKey || e.metaKey || e.button === 1; }, true);
  window.open = function (url, target, features) {
    try {
      const enabled = document.documentElement.dataset.vrSameTab === '1';
      if (enabled && !modifier && url) {
        const u = new URL(String(url), location.href);
        if (u.origin === location.origin) { location.assign(u.href); return null; }
      }
    } catch (_) {}
    return orig.call(window, url, target, features);
  };
})();
