// Tiny i18n runtime - bundled, dependency-free, CSP-safe (no eval, no fetch).
// Shared with thingino-web-builder so terminology stays consistent across tools.
//
// Load order (in index.html, before the app module): i18n.js -> the per-language
// dict files (i18n-dfu-<lang>.js, each calls I18N.add(lang, {...})) -> /src/main.js.
//
// Usage:
//   I18N.t('key' [, {name: value}])   -> translated string (falls back lang -> en -> key)
//   <tag data-i18n="key">             -> textContent set by I18N.apply()
//   <tag data-i18n-ph="key">          -> placeholder (inputs)
//   <tag data-i18n-title="key">       -> title attribute
//   <tag data-i18n-html="key">        -> innerHTML (for strings with <strong>/<br>; dict is trusted)
//   I18N.selector('id')               -> builds the language <select> into that element
//   window 'i18nchange' event         -> fires on language switch; re-render dynamic UI in the handler
(function () {
  var SUPPORTED = ["en", "es", "fr", "de", "it", "nl", "pl", "pt", "tr", "uk", "ru", "ar", "zh-CN", "ja", "ko"];
  var RTL = ["ar", "he", "fa", "ur"];   // right-to-left languages -> dir="rtl" in apply()
  var NAMES = {
    "en": "English", "es": "Español", "fr": "Français", "de": "Deutsch",
    "it": "Italiano", "nl": "Nederlands", "pl": "Polski", "pt": "Português",
    "tr": "Türkçe", "uk": "Українська", "ru": "Русский", "ar": "العربية",
    "zh-CN": "中文", "ja": "日本語", "ko": "한국어",
  };
  var DICT = {};
  function add(lang, obj) { DICT[lang] = Object.assign(DICT[lang] || {}, obj); }

  // Pick the language: saved override -> first supported browser language -> English.
  function detect() {
    try {
      var saved = localStorage.getItem("lang");
      if (saved && SUPPORTED.indexOf(saved) >= 0) return saved;
    } catch (e) { /* private mode */ }
    var cands = navigator.languages || [navigator.language || "en"];
    for (var i = 0; i < cands.length; i++) {
      var c = cands[i]; if (!c) continue;
      if (SUPPORTED.indexOf(c) >= 0) return c;       // exact, e.g. zh-CN
      var base = c.split("-")[0];
      if (base === "zh") return "zh-CN";             // any Chinese -> Simplified
      if (SUPPORTED.indexOf(base) >= 0) return base; // es-MX -> es, pt-BR -> pt
    }
    return "en";
  }
  var lang = detect();

  function t(key, params) {
    var s = (DICT[lang] && DICT[lang][key]) || (DICT["en"] && DICT["en"][key]) || key;
    if (params) for (var k in params) s = s.split("{" + k + "}").join(params[k]);
    return s;
  }

  function apply(root) {
    root = root || document;
    root.querySelectorAll("[data-i18n]").forEach(function (el) { el.textContent = t(el.getAttribute("data-i18n")); });
    root.querySelectorAll("[data-i18n-ph]").forEach(function (el) { el.setAttribute("placeholder", t(el.getAttribute("data-i18n-ph"))); });
    root.querySelectorAll("[data-i18n-title]").forEach(function (el) { el.setAttribute("title", t(el.getAttribute("data-i18n-title"))); });
    root.querySelectorAll("[data-i18n-html]").forEach(function (el) { el.innerHTML = t(el.getAttribute("data-i18n-html")); });
    document.documentElement.lang = lang;
    document.documentElement.dir = RTL.indexOf(lang) >= 0 ? "rtl" : "ltr";
  }

  function set(l) {
    if (SUPPORTED.indexOf(l) < 0) return;
    lang = l;
    try { localStorage.setItem("lang", l); } catch (e) { /* private mode */ }
    apply();
    window.dispatchEvent(new Event("i18nchange"));
  }

  // Build the language <select> into the element with the given id.
  function selector(containerId) {
    var c = document.getElementById(containerId);
    if (!c) return;
    var sel = document.createElement("select");
    sel.className = "form-select form-select-sm";
    sel.style.width = "auto";
    sel.setAttribute("aria-label", "Language");
    SUPPORTED.forEach(function (l) {
      var o = document.createElement("option");
      o.value = l; o.textContent = NAMES[l];
      if (l === lang) o.selected = true;
      sel.appendChild(o);
    });
    sel.addEventListener("change", function () { set(sel.value); });
    c.appendChild(sel);
  }

  window.I18N = {
    add: add, t: t, apply: apply, set: set, selector: selector,
    SUPPORTED: SUPPORTED, NAMES: NAMES,
    get lang() { return lang; },
  };
})();
