// Runs before every module (a classic script, index.html): moves what this browser saved under the project's old
// name (localStorage "vantage.*": decks, layouts, ranges, the SQL draft, old notes) to "nd.*", the prefix every other
// key uses, so nothing saved is lost. A value already saved under the new name wins. Safe to run on every load.
(function () {
  try {
    var old = [];
    for (var i = 0; i < localStorage.length; i++) {
      var k = localStorage.key(i);
      if (k && k.indexOf('vantage.') === 0) old.push(k);
    }
    old.forEach(function (k) {
      var nk = 'nd.' + k.slice('vantage.'.length);
      if (localStorage.getItem(nk) === null) localStorage.setItem(nk, localStorage.getItem(k));
      localStorage.removeItem(k);
    });
  } catch (e) { /* storage blocked: nothing to move */ }
})();
