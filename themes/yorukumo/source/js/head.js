// 主题切换功能：手动选择优先（存 localStorage），否则跟随系统
(function () {
  var STORAGE_KEY = 'theme';

  // 将 MediaQueryList 的引用挂载到 window 全局对象，防止被 V8 引擎垃圾回收 (GC) 导致监听器失效
  window.themeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

  function systemTheme() {
    return window.themeMediaQuery.matches ? 'dark' : 'light';
  }

  function savedTheme() {
    try {
      var v = localStorage.getItem(STORAGE_KEY);
      return (v === 'dark' || v === 'light') ? v : null;
    } catch (e) {
      return null;
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  // 初始化：有保存的选择就用保存的，否则跟随系统
  function updateTheme() {
    applyTheme(savedTheme() || systemTheme());
  }

  updateTheme();

  // 系统主题变化时，仅在用户没有手动选择过时才跟随
  function onSystemChange() {
    if (!savedTheme()) updateTheme();
  }

  // 监听系统主题变化（包含旧版浏览器兼容）
  if (window.themeMediaQuery.addEventListener) {
    window.themeMediaQuery.addEventListener('change', onSystemChange);
  } else if (window.themeMediaQuery.addListener) {
    window.themeMediaQuery.addListener(onSystemChange);
  }

  // 标题栏深色模式切换按钮
  function bindToggle() {
    var btn = document.querySelector('.theme-toggle');
    if (!btn) return;
    btn.addEventListener('click', function () {
      var current = document.documentElement.getAttribute('data-theme') || systemTheme();
      var next = current === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      try {
        localStorage.setItem(STORAGE_KEY, next);
      } catch (e) {}
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindToggle);
  } else {
    bindToggle();
  }
})();
